use crate::bitvec::BitVec;
use fnv::FnvHasher;
use serde::{Deserialize, Serialize};
use std::hash::Hasher;

// a bloom filter never needs more hash functions than this; the optimal k for
// any false-positive rate we use is under 10, so anything larger off the wire is hostile
pub const MAX_BLOOM_KEYS: usize = 32;

// a filter has to fit in one udp packet, so it can never carry more bits than the packet has
pub const MAX_BLOOM_BITS: u64 = crate::network::PACKET_DATA_SIZE as u64 * 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BloomWire")]
pub struct Bloom {
    seeds: Vec<u64>,
    bits: BitVec,
}

#[derive(Deserialize)]
struct BloomWire {
    seeds: Vec<u64>,
    bits: BitVec,
}

// everything a remote peer controls is checked here, before the filter is ever used:
// zero bits would divide by zero, zero seeds would match everything, and huge
// counts would turn one packet into a lot of hashing work
impl TryFrom<BloomWire> for Bloom {
    type Error = String;

    fn try_from(wire: BloomWire) -> Result<Self, Self::Error> {
        if wire.seeds.is_empty() || wire.seeds.len() > MAX_BLOOM_KEYS {
            return Err(format!("bloom has {} seeds", wire.seeds.len()));
        }
        if wire.bits.is_empty() || wire.bits.len() > MAX_BLOOM_BITS {
            return Err(format!("bloom has {} bits", wire.bits.len()));
        }
        Ok(Bloom {
            seeds: wire.seeds,
            bits: wire.bits,
        })
    }
}

impl Bloom {
    // num_items: determines the size of bloom filter. more items -> more bits needed -> bigger filter
    // false_positive_rate: lower rate = more bits = more memory. higher rate = fewer bits = less memory but more wrong answers.
    // max_bits: never allocate more than this, even if the math says you should.
    pub fn new(num_items: usize, false_positive_rate: f64, max_bits: u64) -> Self {
        // Derivation:
        //
        // given: m bits, k hash functions, n items to insert
        //
        // step 1: probability a specific bit is still 0 after all insertions
        //   one hash has a 1/m chance of hitting a specific bit
        //   so (1 - 1/m) chance of NOT hitting it
        //   with k hash functions per item and n items, total kn hashes
        //   probability bit is still 0: p0 = (1 - 1/m)^(kn)
        //   for large m, using the limit (1 - 1/m)^m ≈ e^(-1):
        //     p0 = ((1 - 1/m)^m)^(kn/m) ≈ (e^(-1))^(kn/m) = e^(-kn/m)
        //
        // step 2: false positive probability
        //   a false positive occurs when all k bits are set for an element NOT in the set
        //   each bit has probability (1 - p0) of being set
        //   all k bits set: p_fp = (1 - p0)^k = (1 - e^(-kn/m))^k
        //
        // step 3: find optimal k that minimizes p_fp
        //   take ln of both sides: ln(p_fp) = k * ln(1 - e^(-kn/m))
        //   substitute g = e^(-kn/m), so k = -(m/n) * ln(g)
        //   then ln(p_fp) = -(m/n) * ln(g) * ln(1 - g)
        //   minimize by differentiating w.r.t. g, set to 0:
        //     d/dg [ln(g) * ln(1-g)] = ln(1-g)/g - ln(g)/(1-g) = 0
        //   this gives g = 1/2, meaning e^(-kn/m) = 1/2
        //   solving: k = (m/n) * ln(2) ≈ 0.693 * (m/n)
        //
        // step 4: false positive rate at optimal k
        //   substituting g = 1/2 into p_fp = (1 - g)^k = (1/2)^k
        //   with k = (m/n) * ln(2):
        //     p_fp = (1/2)^((m/n) * ln(2)) = (2^(-ln(2)))^(m/n) ≈ (0.6185)^(m/n)
        //
        // step 5: solve for m given desired false positive rate p
        //   p = (0.6185)^(m/n)
        //   ln(p) = (m/n) * ln(0.6185)
        //   ln(0.6185) = -ln(2)^2 = -(ln2)^2
        //   therefore: m/n = -ln(p) / (ln2)^2
        //   so: m = -n * ln(p) / (ln2)^2
        //
        // step 6: solve for k given m
        //   k = (m/n) * ln(2)
        let ln2 = std::f64::consts::LN_2;
        let num_bits = (-(num_items as f64) * false_positive_rate.ln() / (ln2 * ln2)).ceil() as u64;
        let num_bits = num_bits.clamp(1, max_bits.clamp(1, MAX_BLOOM_BITS));

        let num_seeds = if num_items == 0 {
            1
        } else {
            ((num_bits as f64 / num_items as f64) * ln2).round() as usize
        };
        let num_seeds = num_seeds.clamp(1, MAX_BLOOM_KEYS);

        // fresh random seeds every time, so a false positive in one round is not repeated in the next
        let seeds: Vec<u64> = (0..num_seeds).map(|_| rand::random()).collect();

        Bloom {
            seeds,
            bits: BitVec::new(num_bits),
        }
    }

    // the inverse of step 5 above: how many items fit in max_bits at rate p with optimal k
    //   n = -m * (ln2)^2 / ln(p)
    pub fn max_items(max_bits: u64, false_positive_rate: f64) -> usize {
        let ln2 = std::f64::consts::LN_2;
        ((max_bits as f64 * ln2 * ln2) / -false_positive_rate.ln())
            .floor()
            .max(1.0) as usize
    }

    fn position(&self, seed: u64, item: &[u8]) -> u64 {
        // fnv (Fowler-Noll-Vo) is a fast, non-cryptographic hash function; each seed is its own offset basis
        let mut hasher = FnvHasher::with_key(seed);
        hasher.write(item);
        hasher.finish() % self.bits.len()
    }

    pub fn add(&mut self, item: &[u8]) {
        for i in 0..self.seeds.len() {
            let pos = self.position(self.seeds[i], item);
            self.bits.set(pos);
        }
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        self.seeds
            .iter()
            .all(|&seed| self.bits.get(self.position(seed, item)))
    }

    pub fn num_bits(&self) -> u64 {
        self.bits.len()
    }

    pub fn num_seeds(&self) -> usize {
        self.seeds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // trials used when measuring the false positive rate
    const FP_TRIALS: usize = 100_000;

    #[test]
    fn test_bloom_membership() {
        let mut bloom = Bloom::new(1000, 0.01, 10_000);
        bloom.add(b"hello");
        bloom.add(b"world");
        assert!(bloom.contains(b"hello"));
        assert!(bloom.contains(b"world"));
    }

    #[test]
    fn test_sizing_matches_formula() {
        // m = -n ln p / (ln2)^2 = 100 * 4.605 / 0.4805 = 958.5 -> 959, k = 9.59 * 0.693 = 6.6 -> 7
        let bloom = Bloom::new(100, 0.01, 10_000);
        assert_eq!(bloom.num_bits(), 959);
        assert_eq!(bloom.num_seeds(), 7);
        // capped by max_bits
        assert_eq!(Bloom::new(100_000, 0.01, 4096).num_bits(), 4096);
        // max_items inverts the sizing
        assert!(Bloom::max_items(959, 0.01) >= 99 && Bloom::max_items(959, 0.01) <= 100);
    }

    // measured false positive rate stays within 1.5x of the target for the rates gossip uses
    #[test]
    fn test_false_positive_rate_measured() {
        // the largest table one packet-sized filter holds at 0.1 is about 2000 items
        for &(n, p) in &[(1000usize, 0.1f64), (1000, 0.01), (2000, 0.1)] {
            let mut bloom = Bloom::new(n, p, MAX_BLOOM_BITS);
            for i in 0..n {
                bloom.add(format!("in-{i}").as_bytes());
            }
            for i in 0..n {
                assert!(bloom.contains(format!("in-{i}").as_bytes()));
            }
            let fps = (0..FP_TRIALS)
                .filter(|i| bloom.contains(format!("out-{i}").as_bytes()))
                .count();
            let rate = fps as f64 / FP_TRIALS as f64;
            assert!(rate < p * 1.5, "n={n} p={p} measured {rate}");
        }
    }

    #[test]
    fn test_rejects_hostile_filters() {
        let ok = Bloom::new(10, 0.1, 1000);
        assert!(bincode::deserialize::<Bloom>(&bincode::serialize(&ok).unwrap()).is_ok());

        // zero bits: would be a division by zero in position()
        let zero_bits = (vec![1u64], BitVec::new(0));
        assert!(bincode::deserialize::<Bloom>(&bincode::serialize(&zero_bits).unwrap()).is_err());
        // zero seeds: would claim to contain everything
        let zero_seeds = (Vec::<u64>::new(), BitVec::new(64));
        assert!(bincode::deserialize::<Bloom>(&bincode::serialize(&zero_seeds).unwrap()).is_err());
        // too many seeds: hashing work amplification
        let many_seeds = (vec![1u64; MAX_BLOOM_KEYS + 1], BitVec::new(64));
        assert!(bincode::deserialize::<Bloom>(&bincode::serialize(&many_seeds).unwrap()).is_err());
        // more bits than a packet can hold
        let too_big = (vec![1u64], BitVec::new(MAX_BLOOM_BITS + 64));
        assert!(bincode::deserialize::<Bloom>(&bincode::serialize(&too_big).unwrap()).is_err());
    }
}
