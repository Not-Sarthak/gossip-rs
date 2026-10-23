// pull: "tell me what i'm missing"
//
//   node_a hashes every value it holds (plus ones it recently dropped) into bloom filters
//   node_a → PullRequest { filter, a's contact info } → node_b
//   node_b sends back every value whose hash is NOT in the filter
//
// filters hold value hashes, not labels, so a newer version of a value a peer already has
// is still "missing" and gets pulled. when the table is too big for one packet's filter,
// the hash space is split by its top mask_bits bits into 2^mask_bits filters, one per packet
use crate::bloom::Bloom;
use crate::crds::{Crds, CrdsValue, Hash};
use crate::network;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

// target false positive rate per filter (agave's CrdsFilter false rate); a false positive only
// delays a value by a round, since every request uses fresh seeds
pub const FALSE_RATE: f64 = 0.1;

// a requester never splits into more than 2^this filters, i.e. 256 packets per pull round
pub const MAX_REQUEST_MASK_BITS: u32 = 8;

// a filter from the wire can't claim to partition more finely than a u64 prefix allows
const MAX_MASK_BITS: u32 = 64;

// most bytes of values one pull request can make us send back (53 full packets);
// requesters are ping-verified, so this bounds work per request, not reflection
pub const PULL_RESPONSE_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CrdsFilterWire")]
pub struct CrdsFilter {
    pub filter: Bloom,
    pub mask: u64,
    pub mask_bits: u32,
}

#[derive(Deserialize)]
struct CrdsFilterWire {
    filter: Bloom,
    mask: u64,
    mask_bits: u32,
}

impl TryFrom<CrdsFilterWire> for CrdsFilter {
    type Error = String;

    fn try_from(wire: CrdsFilterWire) -> Result<Self, Self::Error> {
        if wire.mask_bits > MAX_MASK_BITS {
            return Err(format!("mask_bits {}", wire.mask_bits));
        }
        Ok(CrdsFilter {
            filter: wire.filter,
            mask: wire.mask,
            mask_bits: wire.mask_bits,
        })
    }
}

// the mask is the filter's index in the top mask_bits bits with every lower bit set
fn compute_mask(index: u64, mask_bits: u32) -> u64 {
    if mask_bits == 0 {
        return !0;
    }
    (index << (64 - mask_bits)) | (!0u64 >> mask_bits)
}

// which filter of a 2^mask_bits set a hash belongs to: its top mask_bits bits
fn filter_index(hash: &Hash, mask_bits: u32) -> usize {
    hash.as_u64().checked_shr(64 - mask_bits).unwrap_or(0) as usize
}

impl CrdsFilter {
    // does this hash fall in the slice of hash space this filter covers?
    pub fn test_mask(&self, hash: &Hash) -> bool {
        let ones = (!0u64).checked_shr(self.mask_bits).unwrap_or(0);
        (hash.as_u64() | ones) == self.mask
    }

    // true when the requester already has the value, or it belongs to another filter's slice
    pub fn filter_contains(&self, hash: &Hash) -> bool {
        !self.test_mask(hash) || self.filter.contains(&hash.0)
    }
}

pub struct CrdsFilterSet {
    filters: Vec<CrdsFilter>,
    mask_bits: u32,
}

impl CrdsFilterSet {
    // splits num_items over as few filters as fit max_bits each at FALSE_RATE,
    // then sizes each filter from the items it will actually hold
    pub fn new(num_items: usize, max_bits: u64) -> Self {
        let max_items = Bloom::max_items(max_bits, FALSE_RATE);
        let mut mask_bits = 0;
        while mask_bits < MAX_REQUEST_MASK_BITS && num_items.div_ceil(1 << mask_bits) > max_items {
            mask_bits += 1;
        }
        let num_filters = 1usize << mask_bits;
        let per_filter = num_items.div_ceil(num_filters);
        let filters = (0..num_filters as u64)
            .map(|index| CrdsFilter {
                filter: Bloom::new(per_filter, FALSE_RATE, max_bits),
                mask: compute_mask(index, mask_bits),
                mask_bits,
            })
            .collect();
        CrdsFilterSet { filters, mask_bits }
    }

    pub fn add(&mut self, hash: &Hash) {
        let index = filter_index(hash, self.mask_bits);
        self.filters[index].filter.add(&hash.0);
    }

    pub fn into_filters(self) -> Vec<CrdsFilter> {
        self.filters
    }
}

// what a node sends to ask for missing values: one PullRequest per filter, each fitting a packet.
// the bloom gets the largest bit count that still fits next to the caller's contact info
pub fn build_requests(
    crds: &Crds,
    caller: &CrdsValue,
) -> Result<Vec<crate::node::Protocol>, bincode::Error> {
    let hashes: Vec<Hash> = crds
        .values()
        .map(|v| v.value_hash)
        .chain(crds.purged_hashes().copied())
        .collect();
    let mut max_bits = crate::bloom::MAX_BLOOM_BITS;
    loop {
        let mut set = CrdsFilterSet::new(hashes.len(), max_bits);
        for hash in &hashes {
            set.add(hash);
        }
        let requests: Vec<_> = set
            .into_filters()
            .into_iter()
            .map(|filter| crate::node::Protocol::PullRequest(filter, caller.clone()))
            .collect();
        let mut largest = 0;
        for request in &requests {
            largest = largest.max(network::serialized_size(request)?);
        }
        if largest <= network::PACKET_DATA_SIZE {
            return Ok(requests);
        }
        // shrink by the overflow, rounded up to whole u64 blocks, and rebuild
        let excess_bits = ((largest - network::PACKET_DATA_SIZE) as u64 * u8::BITS as u64)
            .next_multiple_of(u64::BITS as u64);
        if excess_bits >= max_bits {
            return Err(Box::new(bincode::ErrorKind::SizeLimit));
        }
        max_bits -= excess_bits;
    }
}

// the responder's side: values the filter says the requester is missing, in random order
// so a capped response doesn't keep sending the same subset, up to max_bytes of values
pub fn filter_values(crds: &Crds, filter: &CrdsFilter, max_bytes: usize) -> Vec<CrdsValue> {
    let mut missing: Vec<&CrdsValue> = crds
        .values()
        .filter(|v| !filter.filter_contains(&v.value_hash))
        .map(|v| &v.value)
        .collect();
    missing.shuffle(&mut rand::rng());
    let mut used = 0;
    let mut out = Vec::new();
    for value in missing {
        let Ok(size) = network::serialized_size(value) else {
            continue;
        };
        if used + size > max_bytes {
            break;
        }
        used += size;
        out.push(value.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{CRDS_TIMEOUT_MS, CrdsData, Keypair, Route, Vote, hashv};

    // hashes used to exercise partitioning
    const NUM_HASHES: u64 = 10_000;
    // a false positive rate low enough that single-value tests are deterministic in practice
    const EXACT_RATE: f64 = 1e-9;

    #[test]
    fn test_every_hash_lands_in_exactly_one_filter() {
        for mask_bits in [0u32, 1, 3] {
            let filters: Vec<CrdsFilter> = (0..(1u64 << mask_bits))
                .map(|i| CrdsFilter {
                    filter: Bloom::new(1, FALSE_RATE, 64),
                    mask: compute_mask(i, mask_bits),
                    mask_bits,
                })
                .collect();
            for i in 0..NUM_HASHES {
                let hash = hashv(&[&i.to_le_bytes()]);
                let owners: Vec<usize> = (0..filters.len())
                    .filter(|&f| filters[f].test_mask(&hash))
                    .collect();
                assert_eq!(owners, vec![filter_index(&hash, mask_bits)]);
            }
        }
    }

    #[test]
    fn test_filter_set_splits_when_table_outgrows_one_filter() {
        let max_bits = 8000;
        let max_items = Bloom::max_items(max_bits, FALSE_RATE);
        assert_eq!(
            CrdsFilterSet::new(max_items, max_bits).into_filters().len(),
            1
        );
        assert_eq!(
            CrdsFilterSet::new(max_items + 1, max_bits)
                .into_filters()
                .len(),
            2
        );
        assert_eq!(
            CrdsFilterSet::new(max_items * 4 + 1, max_bits)
                .into_filters()
                .len(),
            8
        );

        let mut set = CrdsFilterSet::new(max_items * 3, max_bits);
        let hashes: Vec<Hash> = (0..max_items as u64 * 3)
            .map(|i| hashv(&[&i.to_le_bytes()]))
            .collect();
        for hash in &hashes {
            set.add(hash);
        }
        let filters = set.into_filters();
        assert!(
            hashes
                .iter()
                .all(|h| filters.iter().all(|f| f.filter_contains(h)))
        );
    }

    #[test]
    fn test_newer_version_is_missing_older_is_not() {
        let kp = Keypair::new();
        let now = crate::crds::timestamp();
        let old = CrdsValue::new_signed(
            CrdsData::Vote(Vote {
                from: kp.pubkey(),
                slot: 1,
                wallclock: now,
            }),
            &kp,
        )
        .unwrap();
        let new = CrdsValue::new_signed(
            CrdsData::Vote(Vote {
                from: kp.pubkey(),
                slot: 2,
                wallclock: now + 1,
            }),
            &kp,
        )
        .unwrap();

        // the requester only has the old version; a near-zero false positive rate keeps the
        // new hash from being "contained" by chance (FALSE_RATE would fail one run in ten)
        let mut filter = CrdsFilter {
            filter: Bloom::new(1, EXACT_RATE, 1024),
            mask: !0,
            mask_bits: 0,
        };
        filter.filter.add(&old.hash().unwrap().0);

        let mut responder = Crds::new(Keypair::new().pubkey(), 100, CRDS_TIMEOUT_MS);
        responder
            .insert(new.clone(), now, Route::LocalMessage)
            .unwrap();
        assert_eq!(
            filter_values(&responder, &filter, PULL_RESPONSE_MAX_BYTES),
            vec![new]
        );
    }

    #[test]
    fn test_requests_fit_a_packet_and_responses_respect_the_cap() {
        let me = Keypair::new();
        let now = crate::crds::timestamp();
        let mut crds = Crds::new(me.pubkey(), 10_000, CRDS_TIMEOUT_MS);
        for _ in 0..5_000 {
            let kp = Keypair::new();
            let v = CrdsValue::new_signed(
                CrdsData::Vote(Vote {
                    from: kp.pubkey(),
                    slot: 1,
                    wallclock: now,
                }),
                &kp,
            )
            .unwrap();
            crds.insert(v, now, Route::PushMessage).unwrap();
        }
        let caller = CrdsValue::new_signed(
            CrdsData::ContactInfo(crate::crds::ContactInfo {
                pubkey: me.pubkey(),
                gossip: "127.0.0.1:1".parse().unwrap(),
                wallclock: now,
            }),
            &me,
        )
        .unwrap();
        let requests = build_requests(&crds, &caller).unwrap();
        assert!(requests.len() > 1);
        for request in &requests {
            assert!(network::serialize(request).is_ok());
        }

        let empty = CrdsFilter {
            filter: Bloom::new(0, FALSE_RATE, 64),
            mask: !0,
            mask_bits: 0,
        };
        let values = filter_values(&crds, &empty, PULL_RESPONSE_MAX_BYTES);
        let bytes: usize = values
            .iter()
            .map(|v| network::serialized_size(v).unwrap())
            .sum();
        assert!(bytes <= PULL_RESPONSE_MAX_BYTES && bytes + 200 > PULL_RESPONSE_MAX_BYTES);
    }

    #[test]
    fn test_rejects_out_of_range_mask_bits() {
        let filter = CrdsFilter {
            filter: Bloom::new(1, FALSE_RATE, 64),
            mask: 0,
            mask_bits: 65,
        };
        let bytes = bincode::serialize(&filter).unwrap();
        assert!(bincode::deserialize::<CrdsFilter>(&bytes).is_err());
    }
}
