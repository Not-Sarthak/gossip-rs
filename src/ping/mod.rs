// ping/pong: "are you really at that address?"
//
//   node_a → Ping { token, signed by a } → addr
//   addr   → Pong { hash(prefix ‖ token), signed by b } → node_a
//   node_a now knows b answers at addr, and will send it pull responses and pushes
//
// hashing the token with a prefix means a pong can never be replayed as a ping or anything else
use crate::crds::{Hash, Keypair, Pubkey, hashv, verify};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

// domain separator for pong hashes (agave's PING_PONG_HASH_PREFIX)
pub const PING_PONG_HASH_PREFIX: &[u8] = b"SOLANA_PING_PONG";

// how long a verified pong is trusted (agave's GOSSIP_PING_CACHE_TTL, 1280 s)
pub const PING_CACHE_TTL_MS: u64 = 1_280_000;

// at most one ping per remote in this window, so we can't be used to flood an address (agave: ttl / 64)
pub const PING_RATE_LIMIT_MS: u64 = PING_CACHE_TTL_MS / 64;

// a verified remote is pinged again once its pong is this fraction of the ttl old (1/2),
// so it is re-verified before it expires
const REPING_TTL_DIVISOR: u64 = 2;

// most remotes tracked at once (agave's GOSSIP_PING_CACHE_CAPACITY)
pub const PING_CACHE_CAPACITY: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    pub from: Pubkey,
    pub token: Hash,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    pub from: Pubkey,
    pub hash: Hash,
    pub signature: Signature,
}

pub fn pong_hash(token: &Hash) -> Hash {
    hashv(&[PING_PONG_HASH_PREFIX, &token.0])
}

impl Ping {
    pub fn new(keypair: &Keypair) -> Self {
        let token = Hash(rand::random());
        Ping {
            from: keypair.pubkey(),
            token,
            signature: keypair.sign(&token.0),
        }
    }

    pub fn verify(&self) -> bool {
        verify(&self.from, &self.token.0, &self.signature)
    }
}

impl Pong {
    pub fn new(ping: &Ping, keypair: &Keypair) -> Self {
        let hash = pong_hash(&ping.token);
        Pong {
            from: keypair.pubkey(),
            hash,
            signature: keypair.sign(&hash.0),
        }
    }

    pub fn verify(&self) -> bool {
        verify(&self.from, &self.hash.0, &self.signature)
    }
}

type Remote = (Pubkey, SocketAddr);

pub struct PingCache {
    ttl_ms: u64,
    rate_limit_ms: u64,
    capacity: usize,
    // remote -> when we last pinged it
    pings: HashMap<Remote, u64>,
    // remote -> when it last answered with a valid pong
    pongs: HashMap<Remote, u64>,
    // expected pong hash -> (remote, when the ping went out)
    pending: HashMap<Hash, (Remote, u64)>,
}

impl PingCache {
    pub fn new(ttl_ms: u64, rate_limit_ms: u64, capacity: usize) -> Self {
        PingCache {
            ttl_ms,
            rate_limit_ms,
            capacity: capacity.max(1),
            pings: HashMap::new(),
            pongs: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    // records a pong; true if it answers a ping we sent to exactly that pubkey and address
    pub fn add(&mut self, pong: &Pong, from: SocketAddr, now: u64) -> bool {
        let remote = (pong.from, from);
        match self.pending.get(&pong.hash) {
            Some((expected, sent))
                if *expected == remote && now.saturating_sub(*sent) <= self.ttl_ms =>
            {
                self.pending.remove(&pong.hash);
                self.pongs.insert(remote, now);
                self.trim(now);
                true
            }
            _ => false,
        }
    }

    // is the remote verified, and should we ping it now? a fresh ping goes out when the remote
    // is unverified or its pong is past half its ttl, but never more than once per rate limit
    pub fn check(
        &mut self,
        now: u64,
        remote: (Pubkey, SocketAddr),
        keypair: &Keypair,
    ) -> (bool, Option<Ping>) {
        let age = self.pongs.get(&remote).map(|at| now.saturating_sub(*at));
        let verified = age.is_some_and(|age| age < self.ttl_ms);
        let needs_ping = age.is_none_or(|age| age >= self.ttl_ms / REPING_TTL_DIVISOR);
        let rate_limited = self
            .pings
            .get(&remote)
            .is_some_and(|at| now.saturating_sub(*at) < self.rate_limit_ms);
        if !needs_ping || rate_limited {
            return (verified, None);
        }
        let ping = Ping::new(keypair);
        self.pings.insert(remote, now);
        self.pending.insert(pong_hash(&ping.token), (remote, now));
        self.trim(now);
        (verified, Some(ping))
    }

    // drops expired entries, then the oldest ones, until every map fits the capacity
    fn trim(&mut self, now: u64) {
        let ttl = self.ttl_ms;
        let capacity = self.capacity;
        if self.pings.len() > capacity {
            self.pings.retain(|_, at| now.saturating_sub(*at) < ttl);
            evict_oldest(&mut self.pings, capacity, |at| *at);
        }
        if self.pongs.len() > capacity {
            self.pongs.retain(|_, at| now.saturating_sub(*at) < ttl);
            evict_oldest(&mut self.pongs, capacity, |at| *at);
        }
        if self.pending.len() > capacity {
            self.pending
                .retain(|_, (_, at)| now.saturating_sub(*at) < ttl);
            evict_oldest(&mut self.pending, capacity, |(_, at)| *at);
        }
    }
}

fn evict_oldest<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    capacity: usize,
    at: impl Fn(&V) -> u64,
) {
    if map.len() <= capacity {
        return;
    }
    let mut ages: Vec<(u64, K)> = map.iter().map(|(k, v)| (at(v), k.clone())).collect();
    ages.sort_unstable_by_key(|(at, _)| *at);
    for (_, key) in ages.into_iter().take(map.len() - capacity) {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // values used across the cache tests
    const TTL: u64 = 1000;
    const RATE_LIMIT: u64 = 100;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn test_pong_is_hash_of_prefixed_token_and_signed() {
        let a = Keypair::new();
        let b = Keypair::new();
        let ping = Ping::new(&a);
        assert!(ping.verify());
        let pong = Pong::new(&ping, &b);
        assert!(pong.verify());
        assert_eq!(pong.hash, hashv(&[PING_PONG_HASH_PREFIX, &ping.token.0]));
        assert_ne!(pong.hash, ping.token);
        // a pong signed by someone else for b's pubkey fails
        let forged = Pong {
            from: b.pubkey(),
            ..Pong::new(&ping, &a)
        };
        assert!(!forged.verify());
    }

    #[test]
    fn test_verification_flow_and_ttl() {
        let me = Keypair::new();
        let peer = Keypair::new();
        let mut cache = PingCache::new(TTL, RATE_LIMIT, PING_CACHE_CAPACITY);
        let remote = (peer.pubkey(), addr(1));

        let (verified, ping) = cache.check(0, remote, &me);
        assert!(!verified);
        let ping = ping.unwrap();
        // rate limited: no second ping inside the window
        assert!(cache.check(10, remote, &me).1.is_none());

        // a pong from the wrong address or the wrong key does not verify
        assert!(!cache.add(&Pong::new(&ping, &peer), addr(2), 20));
        assert!(!cache.add(&Pong::new(&ping, &Keypair::new()), addr(1), 20));
        assert!(cache.add(&Pong::new(&ping, &peer), addr(1), 20));
        // the same pong cannot be replayed
        assert!(!cache.add(&Pong::new(&ping, &peer), addr(1), 21));

        assert_eq!(cache.check(30, remote, &me), (true, None));
        // past half the ttl it re-pings while still verified
        let (verified, ping) = cache.check(20 + TTL / 2, remote, &me);
        assert!(verified && ping.is_some());
        // past the ttl it is unverified again
        assert!(!cache.check(20 + TTL, remote, &me).0);
    }

    #[test]
    fn test_capacity_bounded() {
        let me = Keypair::new();
        let mut cache = PingCache::new(TTL, RATE_LIMIT, 4);
        for port in 0..20 {
            cache.check(port as u64, (Pubkey::default(), addr(port)), &me);
        }
        assert!(cache.pings.len() <= 4 && cache.pending.len() <= 4);
    }
}
