// push: "here's something new"
//
//   node_a → PushMessage { new values } → up to fanout peers from a's active set
//   each peer inserts them and pushes them on to its own active set
//
// so every value arrives at a node along several paths. the node counts, per origin,
// which senders deliver first; once it has seen enough, it keeps the best few and sends
//   node_b → PruneMessage { origins } → slow sender
// telling that sender to stop pushing those origins' values to b
use crate::crds::{CRDS_CAPACITY, Keypair, Pubkey, verify};
use ed25519_dalek::Signature;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

// peers each new value is pushed to
pub const PUSH_FANOUT: usize = 6;

// peers kept in the active set; a few more than the fanout so prunes don't starve an origin
pub const ACTIVE_SET_SIZE: usize = PUSH_FANOUT + 3;

// one active-set peer is swapped for a random candidate this often, so pruned paths are retried
pub const ACTIVE_SET_ROTATE_MS: u64 = 7_500;

// push only values younger than this (agave's CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS); older ones travel by pull
pub const PUSH_MSG_TIMEOUT_MS: u64 = 30_000;

// distinct values from an origin seen before its senders are ranked (agave: 20)
pub const PRUNE_MIN_UPSERTS: usize = 20;

// senders per origin that are never pruned (agave's CRDS_GOSSIP_PRUNE_MIN_INGRESS_NODES)
pub const PRUNE_MIN_INGRESS_NODES: usize = 2;

// a delivery scores for its sender only if it is the first copy or the first duplicate
pub const PRUNE_NUM_DUPS_THRESHOLD: u8 = 2;

// prunes older than this are ignored, so a captured prune can't be replayed later (agave: 500 ms)
pub const PRUNE_MSG_TIMEOUT_MS: u64 = 500;

// domain separator for prune signatures
pub const PRUNE_DATA_PREFIX: &[u8] = b"\xffSOLANA_PRUNE_DATA";

// origins tracked by the received cache; matches the table so it can't outgrow it
pub const RECEIVED_CACHE_CAPACITY: usize = CRDS_CAPACITY;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneData {
    // the node asking to be pruned, and who signs this
    pub pubkey: Pubkey,
    // origins whose values should no longer be pushed to pubkey
    pub prunes: Vec<Pubkey>,
    pub signature: Signature,
    // the node that should stop pushing
    pub destination: Pubkey,
    pub wallclock: u64,
}

fn prune_message(
    pubkey: &Pubkey,
    prunes: &[Pubkey],
    destination: &Pubkey,
    wallclock: u64,
) -> Result<Vec<u8>, bincode::Error> {
    let mut message = PRUNE_DATA_PREFIX.to_vec();
    message.extend(bincode::serialize(&(
        pubkey,
        prunes,
        destination,
        wallclock,
    ))?);
    Ok(message)
}

impl PruneData {
    pub fn new(
        keypair: &Keypair,
        prunes: Vec<Pubkey>,
        destination: Pubkey,
        wallclock: u64,
    ) -> Result<Self, bincode::Error> {
        let pubkey = keypair.pubkey();
        let signature = keypair.sign(&prune_message(&pubkey, &prunes, &destination, wallclock)?);
        Ok(PruneData {
            pubkey,
            prunes,
            signature,
            destination,
            wallclock,
        })
    }

    pub fn verify(&self) -> bool {
        prune_message(
            &self.pubkey,
            &self.prunes,
            &self.destination,
            self.wallclock,
        )
        .map(|message| verify(&self.pubkey, &message, &self.signature))
        .unwrap_or(false)
    }
}

struct ActivePeer {
    pubkey: Pubkey,
    addr: SocketAddr,
    // origins this peer asked us not to push to it
    pruned: HashSet<Pubkey>,
}

#[derive(Default)]
pub struct ActiveSet {
    peers: Vec<ActivePeer>,
    last_rotate: u64,
}

impl ActiveSet {
    // keeps only candidates still known and verified, fills up to size, and on schedule
    // swaps one member for an outsider so a pruned path gets another chance
    pub fn rotate(
        &mut self,
        now: u64,
        candidates: &[(Pubkey, SocketAddr)],
        size: usize,
        rotate_ms: u64,
    ) {
        self.peers.retain(|p| {
            candidates
                .iter()
                .any(|(pk, addr)| *pk == p.pubkey && *addr == p.addr)
        });
        let mut outsiders: Vec<(Pubkey, SocketAddr)> = candidates
            .iter()
            .filter(|(pk, _)| !self.peers.iter().any(|p| p.pubkey == *pk))
            .copied()
            .collect();
        outsiders.shuffle(&mut rand::rng());
        let due = now.saturating_sub(self.last_rotate) >= rotate_ms;
        if due && self.peers.len() >= size && !outsiders.is_empty() && !self.peers.is_empty() {
            let index = rand::random_range(0..self.peers.len());
            self.peers.swap_remove(index);
        }
        if due {
            self.last_rotate = now;
        }
        while self.peers.len() < size {
            let Some((pubkey, addr)) = outsiders.pop() else {
                break;
            };
            self.peers.push(ActivePeer {
                pubkey,
                addr,
                pruned: HashSet::new(),
            });
        }
    }

    // a node's own values are never pruned, so they always leave by every path
    pub fn prune(&mut self, self_pubkey: &Pubkey, peer: &Pubkey, origins: &[Pubkey]) -> usize {
        let Some(active) = self.peers.iter_mut().find(|p| p.pubkey == *peer) else {
            return 0;
        };
        let mut added = 0;
        for origin in origins {
            if origin != self_pubkey
                && active.pruned.len() < CRDS_CAPACITY
                && active.pruned.insert(*origin)
            {
                added += 1;
            }
        }
        added
    }

    // up to fanout peers that haven't pruned this origin and aren't the origin itself
    pub fn targets(&self, origin: &Pubkey, fanout: usize) -> Vec<(Pubkey, SocketAddr)> {
        self.peers
            .iter()
            .filter(|p| p.pubkey != *origin && !p.pruned.contains(origin))
            .take(fanout)
            .map(|p| (p.pubkey, p.addr))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[derive(Default)]
struct ReceivedCacheEntry {
    // sender -> deliveries that were the first copy or the first duplicate
    scores: HashMap<Pubkey, usize>,
    // distinct new values seen from this origin
    num_upserts: usize,
}

#[derive(Default)]
pub struct ReceivedCache {
    entries: HashMap<Pubkey, ReceivedCacheEntry>,
}

impl ReceivedCache {
    // num_dups: 0 for a new value, n for the nth extra copy of a value we already had
    pub fn record(&mut self, origin: Pubkey, sender: Pubkey, num_dups: u8) {
        if !self.entries.contains_key(&origin) && self.entries.len() >= RECEIVED_CACHE_CAPACITY {
            // drop the origin we know least about
            if let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.num_upserts)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&victim);
            }
        }
        let entry = self.entries.entry(origin).or_default();
        if num_dups == 0 {
            entry.num_upserts += 1;
        }
        let score = entry.scores.entry(sender).or_default();
        if num_dups < PRUNE_NUM_DUPS_THRESHOLD {
            *score += 1;
        }
    }

    // once an origin has PRUNE_MIN_UPSERTS values, keeps its PRUNE_MIN_INGRESS_NODES best senders
    // (and the origin itself) and returns the rest to prune; then starts counting afresh
    pub fn prune(&mut self, self_pubkey: &Pubkey, origin: &Pubkey) -> Vec<Pubkey> {
        if self
            .entries
            .get(origin)
            .is_none_or(|e| e.num_upserts < PRUNE_MIN_UPSERTS)
        {
            return Vec::new();
        }
        let Some(entry) = self.entries.remove(origin) else {
            return Vec::new();
        };
        let mut ranked: Vec<(Pubkey, usize)> = entry.scores.into_iter().collect();
        // best first; pubkey breaks ties so the choice is deterministic
        ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        ranked
            .into_iter()
            .skip(PRUNE_MIN_INGRESS_NODES)
            .map(|(sender, _)| sender)
            .filter(|sender| sender != origin && sender != self_pubkey)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn test_prune_data_signature() {
        let kp = Keypair::new();
        let data = PruneData::new(&kp, vec![Pubkey([1; 32])], Pubkey([2; 32]), 7).unwrap();
        assert!(data.verify());
        let mut tampered = data.clone();
        tampered.prunes.push(Pubkey([3; 32]));
        assert!(!tampered.verify());
        let mut redirected = data;
        redirected.destination = Pubkey([4; 32]);
        assert!(!redirected.verify());
    }

    #[test]
    fn test_received_cache_prunes_slow_senders() {
        let me = Pubkey([0; 32]);
        let origin = Pubkey([9; 32]);
        let (fast, second, slow) = (Pubkey([1; 32]), Pubkey([2; 32]), Pubkey([3; 32]));
        let mut cache = ReceivedCache::default();
        for _ in 0..PRUNE_MIN_UPSERTS - 1 {
            cache.record(origin, fast, 0);
            cache.record(origin, second, 1);
            cache.record(origin, slow, 2);
        }
        assert!(cache.prune(&me, &origin).is_empty());
        cache.record(origin, fast, 0);
        cache.record(origin, slow, 2);
        assert_eq!(cache.prune(&me, &origin), vec![slow]);
        // counting restarts after a prune
        assert!(cache.prune(&me, &origin).is_empty());
    }

    #[test]
    fn test_origin_is_never_pruned() {
        let me = Pubkey([0; 32]);
        let origin = Pubkey([9; 32]);
        let mut cache = ReceivedCache::default();
        for _ in 0..PRUNE_MIN_UPSERTS {
            cache.record(origin, Pubkey([1; 32]), 0);
            cache.record(origin, Pubkey([2; 32]), 1);
            cache.record(origin, origin, 5);
        }
        assert!(!cache.prune(&me, &origin).contains(&origin));
    }

    #[test]
    fn test_active_set_targets_and_prunes() {
        let me = Pubkey([0; 32]);
        let peers: Vec<(Pubkey, SocketAddr)> =
            (1..=4).map(|i| (Pubkey([i; 32]), addr(i as u16))).collect();
        let mut set = ActiveSet::default();
        set.rotate(0, &peers, ACTIVE_SET_SIZE, ACTIVE_SET_ROTATE_MS);
        assert_eq!(set.len(), 4);

        let origin = peers[0].0;
        // never push an origin's value back to it
        assert_eq!(set.targets(&origin, PUSH_FANOUT).len(), 3);
        assert_eq!(set.prune(&me, &peers[1].0, &[origin]), 1);
        let targets = set.targets(&origin, PUSH_FANOUT);
        assert_eq!(targets.len(), 2);
        assert!(!targets.iter().any(|(pk, _)| *pk == peers[1].0));
        // our own values ignore prunes
        assert_eq!(set.prune(&me, &peers[1].0, &[me]), 0);
        assert_eq!(set.targets(&me, PUSH_FANOUT).len(), 4);
        // fanout caps the targets
        assert_eq!(set.targets(&me, 2).len(), 2);
    }

    #[test]
    fn test_active_set_drops_vanished_peers_and_rotates() {
        let peers: Vec<(Pubkey, SocketAddr)> = (1..=12)
            .map(|i| (Pubkey([i; 32]), addr(i as u16)))
            .collect();
        let mut set = ActiveSet::default();
        set.rotate(0, &peers, 4, 100);
        assert_eq!(set.len(), 4);
        let before: HashSet<Pubkey> = set.peers.iter().map(|p| p.pubkey).collect();
        set.rotate(100, &peers, 4, 100);
        let after: HashSet<Pubkey> = set.peers.iter().map(|p| p.pubkey).collect();
        assert_eq!(set.len(), 4);
        assert_eq!(before.intersection(&after).count(), 3);
        set.rotate(150, &peers[..2], 4, 100);
        assert!(set.len() <= 2);
    }
}
