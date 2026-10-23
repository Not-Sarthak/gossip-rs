// crds -> cluster replicated data store
//
// every value is signed by the node it describes, versioned by that node's wallclock,
// and stored under a label (pubkey + kind) so a node owns exactly one value per kind
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// a value may run ahead of our clock by at most this much (agave's CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS);
// anything further ahead would otherwise win every future conflict for its label
pub const MAX_WALLCLOCK_SKEW_MS: u64 = 30_000;

// values not refreshed by their owner within this window are purged (agave's CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS)
pub const CRDS_TIMEOUT_MS: u64 = 15_000;

// most values one table holds before evicting the oldest (agave's CRDS_UNIQUE_PUBKEY_CAPACITY)
pub const CRDS_CAPACITY: usize = 8192;

// size of an ed25519 secret key plus public key, the solana keypair file layout
const KEYPAIR_FILE_BYTES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Pubkey(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Hash(pub [u8; 32]);

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl Hash {
    // the first 8 bytes as a little-endian integer, used for pull filter partitioning
    pub fn as_u64(&self) -> u64 {
        let mut word = [0u8; size_of::<u64>()];
        word.copy_from_slice(&self.0[..size_of::<u64>()]);
        u64::from_le_bytes(word)
    }
}

// sha256 over the concatenation of the parts
pub fn hashv(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Hash(hasher.finalize().into())
}

// milliseconds since the unix epoch; a clock set before 1970 reads as 0
pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct Keypair(SigningKey);

impl Keypair {
    pub fn new() -> Self {
        Keypair(SigningKey::from_bytes(&rand::random::<[u8; 32]>()))
    }

    pub fn pubkey(&self) -> Pubkey {
        Pubkey(self.0.verifying_key().to_bytes())
    }

    // secret key then public key, as in a solana keypair file
    pub fn to_bytes(&self) -> [u8; KEYPAIR_FILE_BYTES] {
        self.0.to_keypair_bytes()
    }

    // fails when the public half doesn't match the secret half
    pub fn from_bytes(bytes: &[u8; KEYPAIR_FILE_BYTES]) -> Result<Self, String> {
        SigningKey::from_keypair_bytes(bytes)
            .map(Keypair)
            .map_err(|e| e.to_string())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }

    // solana keypair file: a json array of 64 bytes, secret key then public key
    pub fn read_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let bytes: Vec<u8> =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let bytes: [u8; KEYPAIR_FILE_BYTES] = bytes
            .try_into()
            .map_err(|_| format!("{}: expected {KEYPAIR_FILE_BYTES} bytes", path.display()))?;
        Self::from_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn write_file(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string(&self.to_bytes().to_vec()).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
    }
}

impl Default for Keypair {
    fn default() -> Self {
        Self::new()
    }
}

pub fn verify(pubkey: &Pubkey, message: &[u8], signature: &Signature) -> bool {
    VerifyingKey::from_bytes(&pubkey.0)
        .map(|key| key.verify_strict(message, signature).is_ok())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactInfo {
    pub pubkey: Pubkey,
    pub gossip: SocketAddr,
    pub wallclock: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub from: Pubkey,
    pub slot: u64,
    pub wallclock: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrdsData {
    ContactInfo(ContactInfo),
    Vote(Vote),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrdsValueLabel {
    ContactInfo(Pubkey),
    Vote(Pubkey),
}

impl CrdsValueLabel {
    pub fn pubkey(&self) -> Pubkey {
        match self {
            CrdsValueLabel::ContactInfo(p) | CrdsValueLabel::Vote(p) => *p,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdsValue {
    pub signature: Signature,
    pub data: CrdsData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrdsError {
    // signature missing, malformed, or not made by the pubkey inside the value
    InvalidSignature,
    // wallclock further ahead of ours than MAX_WALLCLOCK_SKEW_MS
    FutureWallclock,
    // wallclock older than the table timeout
    Expired,
    // the exact same value is already stored; carries how many times push delivered it again
    Duplicate(u8),
    // an equal-or-newer version of this label is already stored
    Stale,
    Encoding,
}

// where a value came from; only push duplicates feed the prune logic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    LocalMessage,
    PullRequest,
    PullResponse,
    PushMessage,
}

impl CrdsData {
    pub fn pubkey(&self) -> Pubkey {
        match self {
            CrdsData::ContactInfo(ci) => ci.pubkey,
            CrdsData::Vote(vote) => vote.from,
        }
    }

    pub fn wallclock(&self) -> u64 {
        match self {
            CrdsData::ContactInfo(ci) => ci.wallclock,
            CrdsData::Vote(vote) => vote.wallclock,
        }
    }

    pub fn label(&self) -> CrdsValueLabel {
        match self {
            CrdsData::ContactInfo(ci) => CrdsValueLabel::ContactInfo(ci.pubkey),
            CrdsData::Vote(vote) => CrdsValueLabel::Vote(vote.from),
        }
    }
}

impl CrdsValue {
    pub fn new_signed(data: CrdsData, keypair: &Keypair) -> Result<Self, CrdsError> {
        let message = bincode::serialize(&data).map_err(|_| CrdsError::Encoding)?;
        Ok(CrdsValue {
            signature: keypair.sign(&message),
            data,
        })
    }

    // the signer must be the pubkey the value describes, so nobody can write another node's data
    pub fn verify(&self) -> bool {
        match bincode::serialize(&self.data) {
            Ok(message) => verify(&self.data.pubkey(), &message, &self.signature),
            Err(_) => false,
        }
    }

    // hash of the whole signed value; two versions of one label always differ here
    pub fn hash(&self) -> Result<Hash, CrdsError> {
        bincode::serialize(self)
            .map(|bytes| hashv(&[&bytes]))
            .map_err(|_| CrdsError::Encoding)
    }

    pub fn pubkey(&self) -> Pubkey {
        self.data.pubkey()
    }

    pub fn wallclock(&self) -> u64 {
        self.data.wallclock()
    }

    pub fn label(&self) -> CrdsValueLabel {
        self.data.label()
    }

    pub fn contact_info(&self) -> Option<&ContactInfo> {
        match &self.data {
            CrdsData::ContactInfo(ci) => Some(ci),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VersionedCrdsValue {
    pub value: CrdsValue,
    pub value_hash: Hash,
    // insertion order, so push can send only what is new since its cursor
    pub ordinal: u64,
    // how many extra copies push delivered after the first
    pub num_push_dups: u8,
}

// agave's override rule: the newer wallclock wins; on a tie the larger value hash wins,
// so every node picks the same winner no matter which copy it saw first
fn overrides(value: &CrdsValue, value_hash: &Hash, other: &VersionedCrdsValue) -> bool {
    match value.wallclock().cmp(&other.value.wallclock()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => *value_hash > other.value_hash,
    }
}

pub struct Crds {
    table: HashMap<CrdsValueLabel, VersionedCrdsValue>,
    // ordinal -> label, for the push cursor
    ordinals: BTreeMap<u64, CrdsValueLabel>,
    // (wallclock, label), for purging and eviction oldest-first
    by_wallclock: BTreeSet<(u64, CrdsValueLabel)>,
    next_ordinal: u64,
    // hashes of values we dropped or overwrote, with the time we did; they go in our
    // pull filters so peers don't keep sending back versions we already rejected
    purged: VecDeque<(Hash, u64)>,
    self_pubkey: Pubkey,
    capacity: usize,
    timeout_ms: u64,
}

impl Crds {
    pub fn new(self_pubkey: Pubkey, capacity: usize, timeout_ms: u64) -> Self {
        Crds {
            table: HashMap::new(),
            ordinals: BTreeMap::new(),
            by_wallclock: BTreeSet::new(),
            next_ordinal: 0,
            purged: VecDeque::new(),
            self_pubkey,
            capacity: capacity.max(1),
            timeout_ms,
        }
    }

    pub fn insert(&mut self, value: CrdsValue, now: u64, route: Route) -> Result<(), CrdsError> {
        if !value.verify() {
            return Err(CrdsError::InvalidSignature);
        }
        let wallclock = value.wallclock();
        if wallclock > now.saturating_add(MAX_WALLCLOCK_SKEW_MS) {
            return Err(CrdsError::FutureWallclock);
        }
        if now.saturating_sub(wallclock) > self.timeout_ms {
            return Err(CrdsError::Expired);
        }
        let value_hash = value.hash()?;
        let label = value.label();

        if let Some(existing) = self.table.get_mut(&label) {
            if existing.value_hash == value_hash {
                if route == Route::PushMessage {
                    existing.num_push_dups = existing.num_push_dups.saturating_add(1);
                }
                return Err(CrdsError::Duplicate(existing.num_push_dups));
            }
            if !overrides(&value, &value_hash, existing) {
                self.record_purged(value_hash, now);
                return Err(CrdsError::Stale);
            }
        }

        if let Some(old) = self.remove(&label) {
            self.record_purged(old.value_hash, now);
        }
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        self.ordinals.insert(ordinal, label);
        self.by_wallclock.insert((wallclock, label));
        self.table.insert(
            label,
            VersionedCrdsValue {
                value,
                value_hash,
                ordinal,
                num_push_dups: 0,
            },
        );
        self.evict_over_capacity(now);
        Ok(())
    }

    fn remove(&mut self, label: &CrdsValueLabel) -> Option<VersionedCrdsValue> {
        let old = self.table.remove(label)?;
        self.ordinals.remove(&old.ordinal);
        self.by_wallclock.remove(&(old.value.wallclock(), *label));
        Some(old)
    }

    fn record_purged(&mut self, hash: Hash, now: u64) {
        self.purged.push_back((hash, now));
        // the purged list is only a hint for pull filters, so it shares the table's bound
        while self.purged.len() > self.capacity {
            self.purged.pop_front();
        }
    }

    // evicts the oldest values owned by other nodes until the table fits its capacity
    fn evict_over_capacity(&mut self, now: u64) {
        while self.table.len() > self.capacity {
            let victim = self
                .by_wallclock
                .iter()
                .find(|(_, label)| label.pubkey() != self.self_pubkey)
                .map(|(_, label)| *label);
            match victim.and_then(|label| self.remove(&label)) {
                Some(old) => self.record_purged(old.value_hash, now),
                None => break,
            }
        }
    }

    // drops every value from other nodes whose wallclock is older than the timeout,
    // and forgets purged hashes old enough that the values would be rejected as expired anyway
    pub fn purge(&mut self, now: u64) -> usize {
        let cutoff = now.saturating_sub(self.timeout_ms);
        let expired: Vec<CrdsValueLabel> = self
            .by_wallclock
            .iter()
            .take_while(|(wallclock, _)| *wallclock < cutoff)
            .filter(|(_, label)| label.pubkey() != self.self_pubkey)
            .map(|(_, label)| *label)
            .collect();
        for label in &expired {
            if let Some(old) = self.remove(label) {
                self.record_purged(old.value_hash, now);
            }
        }
        while self.purged.front().is_some_and(|(_, at)| *at < cutoff) {
            self.purged.pop_front();
        }
        expired.len()
    }

    pub fn get(&self, label: &CrdsValueLabel) -> Option<&VersionedCrdsValue> {
        self.table.get(label)
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &VersionedCrdsValue> {
        self.table.values()
    }

    pub fn contact_infos(&self) -> impl Iterator<Item = &ContactInfo> {
        self.table.values().filter_map(|v| v.value.contact_info())
    }

    pub fn contact_info(&self, pubkey: &Pubkey) -> Option<&ContactInfo> {
        self.table
            .get(&CrdsValueLabel::ContactInfo(*pubkey))
            .and_then(|v| v.value.contact_info())
    }

    pub fn purged_hashes(&self) -> impl Iterator<Item = &Hash> {
        self.purged.iter().map(|(hash, _)| hash)
    }

    // values inserted at or after the cursor, oldest first; advances the cursor past them
    pub fn entries_since(&self, cursor: &mut u64) -> Vec<&VersionedCrdsValue> {
        let entries: Vec<&VersionedCrdsValue> = self
            .ordinals
            .range(*cursor..)
            .filter_map(|(_, label)| self.table.get(label))
            .collect();
        *cursor = self.next_ordinal;
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // a wallclock comfortably inside every window used below
    const NOW: u64 = 1_000_000;

    fn vote(keypair: &Keypair, slot: u64, wallclock: u64) -> CrdsValue {
        CrdsValue::new_signed(
            CrdsData::Vote(Vote {
                from: keypair.pubkey(),
                slot,
                wallclock,
            }),
            keypair,
        )
        .unwrap()
    }

    fn table() -> Crds {
        Crds::new(Pubkey::default(), CRDS_CAPACITY, CRDS_TIMEOUT_MS)
    }

    #[test]
    fn test_insert_and_get() {
        let kp = Keypair::new();
        let mut crds = table();
        crds.insert(vote(&kp, 100, NOW), NOW, Route::LocalMessage)
            .unwrap();
        assert!(crds.get(&CrdsValueLabel::Vote(kp.pubkey())).is_some());
        assert!(
            crds.get(&CrdsValueLabel::ContactInfo(kp.pubkey()))
                .is_none()
        );
    }

    #[test]
    fn test_newer_wallclock_wins_older_is_stale() {
        let kp = Keypair::new();
        let mut crds = table();
        crds.insert(vote(&kp, 1, NOW), NOW, Route::LocalMessage)
            .unwrap();
        crds.insert(vote(&kp, 2, NOW + 1), NOW, Route::LocalMessage)
            .unwrap();
        assert_eq!(
            crds.insert(vote(&kp, 3, NOW - 1), NOW, Route::LocalMessage),
            Err(CrdsError::Stale)
        );
        let label = CrdsValueLabel::Vote(kp.pubkey());
        assert_eq!(crds.get(&label).unwrap().value, vote(&kp, 2, NOW + 1));
        // the overwritten and the rejected versions both land in the purged list
        assert_eq!(crds.purged_hashes().count(), 2);
    }

    #[test]
    fn test_tie_breaks_on_hash_in_any_order() {
        let kp = Keypair::new();
        let (a, b) = (vote(&kp, 1, NOW), vote(&kp, 2, NOW));
        let winner = if a.hash().unwrap() > b.hash().unwrap() {
            a.clone()
        } else {
            b.clone()
        };
        let label = CrdsValueLabel::Vote(kp.pubkey());

        let mut first = table();
        let _ = first.insert(a.clone(), NOW, Route::PushMessage);
        let _ = first.insert(b.clone(), NOW, Route::PushMessage);
        let mut second = table();
        let _ = second.insert(b, NOW, Route::PushMessage);
        let _ = second.insert(a, NOW, Route::PushMessage);
        assert_eq!(first.get(&label).unwrap().value, winner);
        assert_eq!(second.get(&label).unwrap().value, winner);
    }

    #[test]
    fn test_rejects_forged_and_unsigned() {
        let owner = Keypair::new();
        let attacker = Keypair::new();
        let mut crds = table();
        // signed by the attacker but claiming to be the owner's vote
        let data = CrdsData::Vote(Vote {
            from: owner.pubkey(),
            slot: 666,
            wallclock: NOW,
        });
        let forged = CrdsValue::new_signed(data.clone(), &attacker).unwrap();
        assert_eq!(
            crds.insert(forged, NOW, Route::PushMessage),
            Err(CrdsError::InvalidSignature)
        );
        let unsigned = CrdsValue {
            signature: Signature::from_bytes(&[0; 64]),
            data,
        };
        assert_eq!(
            crds.insert(unsigned, NOW, Route::PushMessage),
            Err(CrdsError::InvalidSignature)
        );
        assert!(crds.is_empty());
    }

    #[test]
    fn test_rejects_future_and_expired_wallclock() {
        let kp = Keypair::new();
        let mut crds = table();
        let ahead = vote(&kp, 1, NOW + MAX_WALLCLOCK_SKEW_MS + 1);
        assert_eq!(
            crds.insert(ahead, NOW, Route::PushMessage),
            Err(CrdsError::FutureWallclock)
        );
        let behind = vote(&kp, 1, NOW - CRDS_TIMEOUT_MS - 1);
        assert_eq!(
            crds.insert(behind, NOW, Route::PushMessage),
            Err(CrdsError::Expired)
        );
        // u64::MAX wallclock cannot overflow anything
        assert_eq!(
            crds.insert(vote(&kp, 1, u64::MAX), NOW, Route::PushMessage),
            Err(CrdsError::FutureWallclock)
        );
    }

    #[test]
    fn test_push_duplicates_counted() {
        let kp = Keypair::new();
        let mut crds = table();
        let v = vote(&kp, 1, NOW);
        crds.insert(v.clone(), NOW, Route::PushMessage).unwrap();
        assert_eq!(
            crds.insert(v.clone(), NOW, Route::PushMessage),
            Err(CrdsError::Duplicate(1))
        );
        assert_eq!(
            crds.insert(v.clone(), NOW, Route::PullResponse),
            Err(CrdsError::Duplicate(1))
        );
        assert_eq!(
            crds.insert(v, NOW, Route::PushMessage),
            Err(CrdsError::Duplicate(2))
        );
    }

    #[test]
    fn test_purge_keeps_own_values_and_future_timestamps_are_safe() {
        let me = Keypair::new();
        let other = Keypair::new();
        let mut crds = Crds::new(me.pubkey(), CRDS_CAPACITY, CRDS_TIMEOUT_MS);
        crds.insert(vote(&me, 1, NOW), NOW, Route::LocalMessage)
            .unwrap();
        crds.insert(vote(&other, 1, NOW), NOW, Route::PushMessage)
            .unwrap();
        // a clock that went backwards must not underflow
        assert_eq!(crds.purge(0), 0);
        assert_eq!(crds.purge(NOW + CRDS_TIMEOUT_MS + 1), 1);
        assert!(crds.get(&CrdsValueLabel::Vote(me.pubkey())).is_some());
        assert!(crds.get(&CrdsValueLabel::Vote(other.pubkey())).is_none());
    }

    #[test]
    fn test_capacity_evicts_oldest_foreign_value() {
        let me = Keypair::new();
        let mut crds = Crds::new(me.pubkey(), 3, CRDS_TIMEOUT_MS);
        crds.insert(vote(&me, 1, NOW - 10), NOW, Route::LocalMessage)
            .unwrap();
        let others: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
        for (i, kp) in others.iter().enumerate() {
            crds.insert(vote(kp, 1, NOW + i as u64), NOW, Route::PushMessage)
                .unwrap();
        }
        assert_eq!(crds.len(), 3);
        assert!(crds.get(&CrdsValueLabel::Vote(me.pubkey())).is_some());
        assert!(
            crds.get(&CrdsValueLabel::Vote(others[0].pubkey()))
                .is_none()
        );
        assert!(
            crds.get(&CrdsValueLabel::Vote(others[2].pubkey()))
                .is_some()
        );
    }

    #[test]
    fn test_cursor_returns_only_new_entries() {
        let kp = Keypair::new();
        let other = Keypair::new();
        let mut crds = table();
        let mut cursor = 0;
        crds.insert(vote(&kp, 1, NOW), NOW, Route::LocalMessage)
            .unwrap();
        assert_eq!(crds.entries_since(&mut cursor).len(), 1);
        assert_eq!(crds.entries_since(&mut cursor).len(), 0);
        crds.insert(vote(&kp, 2, NOW + 1), NOW, Route::LocalMessage)
            .unwrap();
        crds.insert(vote(&other, 2, NOW), NOW, Route::LocalMessage)
            .unwrap();
        assert_eq!(crds.entries_since(&mut cursor).len(), 2);
    }

    #[test]
    fn test_keypair_file_round_trip() {
        let kp = Keypair::new();
        let path = std::env::temp_dir().join(format!("gossip-rs-keypair-{}.json", kp.pubkey()));
        kp.write_file(&path).unwrap();
        let back = Keypair::read_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(back.pubkey(), kp.pubkey());
    }
}
