use crate::crds::{
    CRDS_CAPACITY, CRDS_TIMEOUT_MS, ContactInfo, Crds, CrdsData, CrdsError, CrdsValue,
    CrdsValueLabel, Hash, Keypair, MAX_WALLCLOCK_SKEW_MS, Pubkey, Route, Vote, timestamp,
};
use crate::network::{self, PACKET_DATA_SIZE};
use crate::ping::{
    PING_CACHE_CAPACITY, PING_CACHE_TTL_MS, PING_RATE_LIMIT_MS, Ping, PingCache, Pong,
};
use crate::pull::{self, CrdsFilter, PULL_RESPONSE_MAX_BYTES};
use crate::push::{
    ACTIVE_SET_ROTATE_MS, ACTIVE_SET_SIZE, ActiveSet, PRUNE_MSG_TIMEOUT_MS, PUSH_FANOUT,
    PUSH_MSG_TIMEOUT_MS, PruneData, ReceivedCache,
};
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// gossip protocol message types, in agave's wire order
//
// pull:      PullRequest { filter, caller } → PullResponse { values the caller is missing }
// push:      PushMessage { new values } → peers, PruneMessage back from peers seeing duplicates
// ping/pong: PingMessage { token } → PongMessage { hash(prefix ‖ token) }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    PullRequest(CrdsFilter, CrdsValue),
    PullResponse(Pubkey, Vec<CrdsValue>),
    PushMessage(Pubkey, Vec<CrdsValue>),
    PruneMessage(Pubkey, PruneData),
    PingMessage(Ping),
    PongMessage(Pong),
}

// how often the push loop runs (agave's GOSSIP_SLEEP_MILLIS)
pub const GOSSIP_INTERVAL_MS: u64 = 100;

// pull is the slow repair path; push carries fresh values, so pull runs every few push rounds
pub const PULL_INTERVAL_MULTIPLE: u32 = 5;

// own contact info is re-signed this many times per crds timeout so peers never purge a live node
const CONTACT_INFO_REFRESHES_PER_TIMEOUT: u64 = 4;

// packets queued between threads; past this the newest are dropped instead of using unbounded memory
// (8192 full packets is about 10 MB)
const QUEUE_CAPACITY: usize = 8192;

// leading pubkey characters in thread names, enough to tell nodes apart in a debugger
const THREAD_TAG_CHARS: usize = 8;

// how often idle threads wake up to check for shutdown
const EXIT_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub entrypoint: Option<SocketAddr>,
    pub gossip_interval: Duration,
    pub pull_interval: Duration,
    pub crds_timeout: Duration,
    pub crds_capacity: usize,
    pub push_fanout: usize,
    pub active_set_size: usize,
    pub active_set_rotate_interval: Duration,
    pub ping_cache_ttl: Duration,
    pub ping_rate_limit: Duration,
}

impl Config {
    pub fn new(
        bind: SocketAddr,
        entrypoint: Option<SocketAddr>,
        gossip_interval: Duration,
    ) -> Self {
        Config {
            bind,
            entrypoint,
            gossip_interval,
            pull_interval: gossip_interval.saturating_mul(PULL_INTERVAL_MULTIPLE),
            crds_timeout: Duration::from_millis(CRDS_TIMEOUT_MS),
            crds_capacity: CRDS_CAPACITY,
            push_fanout: PUSH_FANOUT,
            active_set_size: ACTIVE_SET_SIZE,
            active_set_rotate_interval: Duration::from_millis(ACTIVE_SET_ROTATE_MS),
            ping_cache_ttl: Duration::from_millis(PING_CACHE_TTL_MS),
            ping_rate_limit: Duration::from_millis(PING_RATE_LIMIT_MS),
        }
    }
}

macro_rules! metrics {
    ($($name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Metrics {
            $(pub $name: AtomicU64,)*
        }

        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct MetricsSnapshot {
            $(pub $name: u64,)*
        }

        impl Metrics {
            pub fn snapshot(&self) -> MetricsSnapshot {
                MetricsSnapshot { $($name: self.$name.load(Ordering::Relaxed),)* }
            }
        }
    };
}

metrics!(
    packets_sent,
    bytes_sent,
    max_packet_bytes,
    send_errors,
    outbox_dropped,
    oversized_messages,
    packets_received,
    malformed_packets,
    inbox_dropped,
    push_messages_sent,
    push_values_inserted,
    push_duplicates,
    push_stale,
    pull_requests_sent,
    pull_requests_answered,
    pull_requests_unverified,
    pull_response_packets_sent,
    pull_values_inserted,
    prunes_sent,
    prunes_received,
    prunes_rejected,
    pings_sent,
    pongs_sent,
    pongs_verified,
    values_rejected,
    values_purged,
);

impl Metrics {
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}

// a panic in one thread must not take the others down with a poisoned lock;
// every critical section leaves its state consistent, so the data is still good
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn read<T>(rwlock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    rwlock.read().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(rwlock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    rwlock.write().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct PushState {
    active_set: ActiveSet,
    received: ReceivedCache,
    // crds ordinal up to which values have been pushed
    cursor: u64,
}

// state shared by a node's threads. lock order is crds → push → ping_cache;
// no thread takes them the other way round, so they can't deadlock
struct Shared {
    keypair: Keypair,
    pubkey: Pubkey,
    gossip_addr: SocketAddr,
    config: Config,
    crds: RwLock<Crds>,
    push: Mutex<PushState>,
    ping_cache: Mutex<PingCache>,
    metrics: Arc<Metrics>,
    exit: Arc<AtomicBool>,
    outbox: SyncSender<(SocketAddr, Vec<u8>)>,
    // bytes left for values in a PushMessage / PullResponse, and for origins in a PruneMessage
    values_budget: usize,
    prunes_budget: usize,
}

pub struct Node {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Node {
    // binds the socket and starts the receive, dispatch, push, pull and send threads
    pub fn start(config: Config, keypair: Keypair) -> io::Result<Node> {
        if config.bind.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bind to a concrete ip; it is advertised to peers",
            ));
        }
        let socket = network::bind(config.bind)?;
        let gossip_addr = socket.local_addr()?;
        let pubkey = keypair.pubkey();
        let to_io = |e: bincode::Error| io::Error::other(e.to_string());
        let values_budget = PACKET_DATA_SIZE
            - network::serialized_size(&Protocol::PushMessage(pubkey, vec![])).map_err(to_io)?;
        let empty_prune = PruneData::new(&keypair, vec![], pubkey, 0).map_err(to_io)?;
        let prunes_budget = PACKET_DATA_SIZE
            - network::serialized_size(&Protocol::PruneMessage(pubkey, empty_prune))
                .map_err(to_io)?;

        let (outbox, outbox_rx) = sync_channel(QUEUE_CAPACITY);
        let (inbox, inbox_rx) = sync_channel(QUEUE_CAPACITY);
        let metrics = Arc::new(Metrics::default());
        let exit = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            pubkey,
            gossip_addr,
            crds: RwLock::new(Crds::new(
                pubkey,
                config.crds_capacity,
                config.crds_timeout.as_millis() as u64,
            )),
            push: Mutex::new(PushState::default()),
            ping_cache: Mutex::new(PingCache::new(
                config.ping_cache_ttl.as_millis() as u64,
                config.ping_rate_limit.as_millis() as u64,
                PING_CACHE_CAPACITY,
            )),
            metrics: metrics.clone(),
            exit: exit.clone(),
            outbox,
            values_budget,
            prunes_budget,
            keypair,
            config,
        });
        shared
            .refresh_contact_info(timestamp())
            .map_err(|e| io::Error::other(format!("{e:?}")))?;

        let tag = pubkey
            .to_string()
            .chars()
            .take(THREAD_TAG_CHARS)
            .collect::<String>();
        let mut threads = vec![
            network::spawn_receiver(
                format!("gossip-recv-{tag}"),
                socket.try_clone()?,
                exit.clone(),
                inbox,
                metrics.clone(),
            )?,
            network::spawn_sender(
                format!("gossip-send-{tag}"),
                socket,
                exit.clone(),
                outbox_rx,
                metrics,
            )?,
        ];
        let s = shared.clone();
        threads.push(
            thread::Builder::new()
                .name(format!("gossip-dispatch-{tag}"))
                .spawn(move || s.run_dispatch(inbox_rx))?,
        );
        let s = shared.clone();
        threads.push(
            thread::Builder::new()
                .name(format!("gossip-push-{tag}"))
                .spawn(move || s.run_push())?,
        );
        let s = shared.clone();
        threads.push(
            thread::Builder::new()
                .name(format!("gossip-pull-{tag}"))
                .spawn(move || s.run_pull())?,
        );
        tracing::info!("node {pubkey} gossiping on {gossip_addr}");
        Ok(Node { shared, threads })
    }

    pub fn pubkey(&self) -> Pubkey {
        self.shared.pubkey
    }

    pub fn gossip_addr(&self) -> SocketAddr {
        self.shared.gossip_addr
    }

    // signs and stores a value from this node; push carries it to the cluster
    pub fn publish(&self, data: CrdsData) -> Result<(), CrdsError> {
        let value = CrdsValue::new_signed(data, &self.shared.keypair)?;
        write(&self.shared.crds).insert(value, timestamp(), Route::LocalMessage)
    }

    pub fn publish_vote(&self, slot: u64) -> Result<(), CrdsError> {
        self.publish(CrdsData::Vote(Vote {
            from: self.shared.pubkey,
            slot,
            wallclock: timestamp(),
        }))
    }

    pub fn get(&self, label: &CrdsValueLabel) -> Option<CrdsValue> {
        read(&self.shared.crds).get(label).map(|v| v.value.clone())
    }

    // label -> value hash for every value held; two nodes agree exactly when these are equal
    pub fn table(&self) -> BTreeMap<CrdsValueLabel, Hash> {
        read(&self.shared.crds)
            .values()
            .map(|v| (v.value.label(), v.value_hash))
            .collect()
    }

    pub fn num_values(&self) -> usize {
        read(&self.shared.crds).len()
    }

    pub fn peers(&self) -> Vec<ContactInfo> {
        read(&self.shared.crds)
            .contact_infos()
            .filter(|ci| ci.pubkey != self.shared.pubkey)
            .cloned()
            .collect()
    }

    pub fn active_set_len(&self) -> usize {
        lock(&self.shared.push).active_set.len()
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        self.shared.metrics.snapshot()
    }

    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.shared.exit.store(true, Ordering::Relaxed);
        for handle in self.threads.drain(..) {
            if handle.join().is_err() {
                tracing::error!("a gossip thread of {} panicked", self.shared.pubkey);
            }
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Shared {
    fn exiting(&self) -> bool {
        self.exit.load(Ordering::Relaxed)
    }

    // sleeps for the duration, waking early on shutdown; an interval too large for
    // the clock just means sleeping until shutdown
    fn sleep(&self, duration: Duration) {
        let deadline = Instant::now().checked_add(duration);
        while !self.exiting() {
            let left = deadline.map_or(EXIT_POLL, |d| d.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                break;
            }
            thread::sleep(left.min(EXIT_POLL));
        }
    }

    // encodes within the packet limit and queues for the send thread
    fn send(&self, addr: SocketAddr, message: &Protocol) -> bool {
        let bytes = match network::serialize(message) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("not sending oversized or unencodable message: {e}");
                Metrics::inc(&self.metrics.oversized_messages);
                return false;
            }
        };
        match self.outbox.try_send((addr, bytes)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                Metrics::inc(&self.metrics.outbox_dropped);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    fn refresh_contact_info(&self, now: u64) -> Result<(), CrdsError> {
        let data = CrdsData::ContactInfo(ContactInfo {
            pubkey: self.pubkey,
            gossip: self.gossip_addr,
            wallclock: now,
        });
        let value = CrdsValue::new_signed(data, &self.keypair)?;
        match write(&self.crds).insert(value, now, Route::LocalMessage) {
            Ok(()) | Err(CrdsError::Duplicate(_)) | Err(CrdsError::Stale) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // the one place every inbound message is handled
    fn run_dispatch(&self, inbox: Receiver<(Protocol, SocketAddr)>) {
        while !self.exiting() {
            match inbox.recv_timeout(EXIT_POLL) {
                Ok((message, from)) => self.handle(message, from),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn handle(&self, message: Protocol, from: SocketAddr) {
        let now = timestamp();
        match message {
            Protocol::PullRequest(filter, caller) => {
                self.handle_pull_request(filter, caller, from, now)
            }
            Protocol::PullResponse(_, values) => self.handle_pull_response(values, now),
            Protocol::PushMessage(sender, values) => self.handle_push(sender, values, now),
            Protocol::PruneMessage(sender, data) => self.handle_prune(sender, data, now),
            Protocol::PingMessage(ping) => self.handle_ping(ping, from),
            Protocol::PongMessage(pong) => self.handle_pong(pong, from, now),
        }
    }

    fn handle_pull_request(
        &self,
        filter: CrdsFilter,
        caller: CrdsValue,
        from: SocketAddr,
        now: u64,
    ) {
        let Some(caller_pubkey) = caller.contact_info().map(|ci| ci.pubkey) else {
            Metrics::inc(&self.metrics.values_rejected);
            return;
        };
        if caller_pubkey == self.pubkey {
            return;
        }
        // the caller's contact info is how a node joining through an entrypoint becomes known
        match write(&self.crds).insert(caller, now, Route::PullRequest) {
            Err(CrdsError::InvalidSignature) | Err(CrdsError::Encoding) => {
                Metrics::inc(&self.metrics.values_rejected);
                return;
            }
            _ => {}
        }
        // only answer an address that has proven it is the caller, so a spoofed source gets nothing
        let (verified, ping) =
            lock(&self.ping_cache).check(now, (caller_pubkey, from), &self.keypair);
        if let Some(ping) = ping
            && self.send(from, &Protocol::PingMessage(ping))
        {
            Metrics::inc(&self.metrics.pings_sent);
        }
        if !verified {
            Metrics::inc(&self.metrics.pull_requests_unverified);
            return;
        }
        let values = pull::filter_values(&read(&self.crds), &filter, PULL_RESPONSE_MAX_BYTES);
        Metrics::inc(&self.metrics.pull_requests_answered);
        for chunk in network::split_by_size(values, self.values_budget) {
            if self.send(from, &Protocol::PullResponse(self.pubkey, chunk)) {
                Metrics::inc(&self.metrics.pull_response_packets_sent);
            }
        }
    }

    fn handle_pull_response(&self, values: Vec<CrdsValue>, now: u64) {
        let mut crds = write(&self.crds);
        for value in values {
            match crds.insert(value, now, Route::PullResponse) {
                Ok(()) => Metrics::inc(&self.metrics.pull_values_inserted),
                Err(CrdsError::Duplicate(_)) | Err(CrdsError::Stale) => {}
                Err(_) => Metrics::inc(&self.metrics.values_rejected),
            }
        }
    }

    fn handle_push(&self, sender: Pubkey, values: Vec<CrdsValue>, now: u64) {
        if sender == self.pubkey {
            return;
        }
        let mut prunes: Vec<(SocketAddr, Pubkey, Vec<Pubkey>)> = Vec::new();
        {
            let mut crds = write(&self.crds);
            let mut push = lock(&self.push);
            let mut origins = Vec::new();
            for value in values {
                let origin = value.pubkey();
                let wallclock = value.wallclock();
                if now.saturating_sub(wallclock) > PUSH_MSG_TIMEOUT_MS
                    || wallclock > now.saturating_add(MAX_WALLCLOCK_SKEW_MS)
                {
                    Metrics::inc(&self.metrics.values_rejected);
                    continue;
                }
                match crds.insert(value, now, Route::PushMessage) {
                    Ok(()) => {
                        Metrics::inc(&self.metrics.push_values_inserted);
                        push.received.record(origin, sender, 0);
                    }
                    Err(CrdsError::Duplicate(num_dups)) => {
                        Metrics::inc(&self.metrics.push_duplicates);
                        push.received.record(origin, sender, num_dups);
                    }
                    Err(CrdsError::Stale) => Metrics::inc(&self.metrics.push_stale),
                    Err(_) => {
                        Metrics::inc(&self.metrics.values_rejected);
                        continue;
                    }
                }
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
            let mut by_node: HashMap<Pubkey, Vec<Pubkey>> = HashMap::new();
            for origin in origins {
                for node in push.received.prune(&self.pubkey, &origin) {
                    by_node.entry(node).or_default().push(origin);
                }
            }
            for (node, origins) in by_node {
                if let Some(ci) = crds.contact_info(&node) {
                    prunes.push((ci.gossip, node, origins));
                }
            }
        }
        for (addr, node, origins) in prunes {
            for chunk in network::split_by_size(origins, self.prunes_budget) {
                let Ok(data) = PruneData::new(&self.keypair, chunk, node, now) else {
                    continue;
                };
                if self.send(addr, &Protocol::PruneMessage(self.pubkey, data)) {
                    Metrics::inc(&self.metrics.prunes_sent);
                }
            }
        }
    }

    fn handle_prune(&self, sender: Pubkey, data: PruneData, now: u64) {
        Metrics::inc(&self.metrics.prunes_received);
        let fresh = now.saturating_sub(data.wallclock) <= PRUNE_MSG_TIMEOUT_MS
            && data.wallclock <= now.saturating_add(MAX_WALLCLOCK_SKEW_MS);
        if data.pubkey != sender || data.destination != self.pubkey || !fresh || !data.verify() {
            Metrics::inc(&self.metrics.prunes_rejected);
            return;
        }
        lock(&self.push)
            .active_set
            .prune(&self.pubkey, &data.pubkey, &data.prunes);
    }

    fn handle_ping(&self, ping: Ping, from: SocketAddr) {
        if ping.from == self.pubkey || !ping.verify() {
            return;
        }
        if self.send(
            from,
            &Protocol::PongMessage(Pong::new(&ping, &self.keypair)),
        ) {
            Metrics::inc(&self.metrics.pongs_sent);
        }
    }

    fn handle_pong(&self, pong: Pong, from: SocketAddr, now: u64) {
        if pong.verify() && lock(&self.ping_cache).add(&pong, from, now) {
            Metrics::inc(&self.metrics.pongs_verified);
        }
    }

    // refresh own contact info, purge, ping peers, rotate the active set, push what's new
    fn run_push(&self) {
        let refresh_ms =
            self.config.crds_timeout.as_millis() as u64 / CONTACT_INFO_REFRESHES_PER_TIMEOUT;
        let mut last_refresh = timestamp();
        while !self.exiting() {
            let now = timestamp();
            if now.saturating_sub(last_refresh) >= refresh_ms {
                if let Err(e) = self.refresh_contact_info(now) {
                    tracing::warn!("refreshing contact info failed: {e:?}");
                }
                last_refresh = now;
            }
            self.push_round(now);
            self.sleep(self.config.gossip_interval);
        }
    }

    fn push_round(&self, now: u64) {
        let purged = write(&self.crds).purge(now);
        Metrics::add(&self.metrics.values_purged, purged as u64);

        let peers: Vec<(Pubkey, SocketAddr)> = read(&self.crds)
            .contact_infos()
            .filter(|ci| ci.pubkey != self.pubkey)
            .map(|ci| (ci.pubkey, ci.gossip))
            .collect();
        let mut verified = Vec::new();
        let mut pings = Vec::new();
        {
            let mut cache = lock(&self.ping_cache);
            for &peer in &peers {
                let (ok, ping) = cache.check(now, peer, &self.keypair);
                if ok {
                    verified.push(peer);
                }
                if let Some(ping) = ping {
                    pings.push((peer.1, ping));
                }
            }
        }
        for (addr, ping) in pings {
            if self.send(addr, &Protocol::PingMessage(ping)) {
                Metrics::inc(&self.metrics.pings_sent);
            }
        }

        let mut cursor = lock(&self.push).cursor;
        let fresh: Vec<CrdsValue> = read(&self.crds)
            .entries_since(&mut cursor)
            .into_iter()
            .filter(|v| now.saturating_sub(v.value.wallclock()) <= PUSH_MSG_TIMEOUT_MS)
            .map(|v| v.value.clone())
            .collect();
        let mut per_peer: HashMap<SocketAddr, Vec<CrdsValue>> = HashMap::new();
        {
            let mut push = lock(&self.push);
            push.cursor = cursor;
            push.active_set.rotate(
                now,
                &verified,
                self.config.active_set_size,
                self.config.active_set_rotate_interval.as_millis() as u64,
            );
            for value in fresh {
                for (_, addr) in push
                    .active_set
                    .targets(&value.pubkey(), self.config.push_fanout)
                {
                    per_peer.entry(addr).or_default().push(value.clone());
                }
            }
        }
        for (addr, values) in per_peer {
            for chunk in network::split_by_size(values, self.values_budget) {
                if self.send(addr, &Protocol::PushMessage(self.pubkey, chunk)) {
                    Metrics::inc(&self.metrics.push_messages_sent);
                }
            }
        }
    }

    // pull from random peers, or from the entrypoint until it shows up as a peer
    fn run_pull(&self) {
        while !self.exiting() {
            self.pull_round();
            self.sleep(self.config.pull_interval);
        }
    }

    fn pull_round(&self) {
        let requests = {
            let crds = read(&self.crds);
            let Some(caller) = crds
                .get(&CrdsValueLabel::ContactInfo(self.pubkey))
                .map(|v| v.value.clone())
            else {
                return;
            };
            match pull::build_requests(&crds, &caller) {
                Ok(requests) => requests,
                Err(e) => {
                    tracing::warn!("building pull requests failed: {e}");
                    return;
                }
            }
        };
        let mut targets: Vec<SocketAddr> = self.peer_addrs();
        if let Some(entrypoint) = self.config.entrypoint
            && entrypoint != self.gossip_addr
            && !targets.contains(&entrypoint)
        {
            targets.push(entrypoint);
        }
        let mut rng = rand::rng();
        for request in requests {
            let Some(&addr) = targets.choose(&mut rng) else {
                return;
            };
            if self.send(addr, &request) {
                Metrics::inc(&self.metrics.pull_requests_sent);
            }
        }
    }

    fn peer_addrs(&self) -> Vec<SocketAddr> {
        read(&self.crds)
            .contact_infos()
            .filter(|ci| ci.pubkey != self.pubkey)
            .map(|ci| ci.gossip)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bloom::Bloom;

    #[test]
    fn test_every_message_round_trips_within_a_packet() {
        let kp = Keypair::new();
        let now = timestamp();
        let ci = CrdsValue::new_signed(
            CrdsData::ContactInfo(ContactInfo {
                pubkey: kp.pubkey(),
                gossip: "127.0.0.1:8000".parse().unwrap(),
                wallclock: now,
            }),
            &kp,
        )
        .unwrap();
        let vote = CrdsValue::new_signed(
            CrdsData::Vote(Vote {
                from: kp.pubkey(),
                slot: 7,
                wallclock: now,
            }),
            &kp,
        )
        .unwrap();
        let filter = CrdsFilter {
            filter: Bloom::new(10, pull::FALSE_RATE, 1024),
            mask: !0,
            mask_bits: 0,
        };
        let ping = Ping::new(&kp);
        let messages = vec![
            Protocol::PullRequest(filter, ci.clone()),
            Protocol::PullResponse(kp.pubkey(), vec![ci.clone(), vote.clone()]),
            Protocol::PushMessage(kp.pubkey(), vec![vote]),
            Protocol::PruneMessage(
                kp.pubkey(),
                PruneData::new(&kp, vec![kp.pubkey()], kp.pubkey(), now).unwrap(),
            ),
            Protocol::PongMessage(Pong::new(&ping, &kp)),
            Protocol::PingMessage(ping),
        ];
        for message in messages {
            let bytes = network::serialize(&message).unwrap();
            assert!(bytes.len() <= PACKET_DATA_SIZE);
            assert_eq!(network::deserialize::<Protocol>(&bytes).unwrap(), message);
        }
    }

    #[test]
    fn test_wire_sizes() {
        let kp = Keypair::new();
        let ci = CrdsValue::new_signed(
            CrdsData::ContactInfo(ContactInfo {
                pubkey: kp.pubkey(),
                gossip: "127.0.0.1:8000".parse().unwrap(),
                wallclock: 0,
            }),
            &kp,
        )
        .unwrap();
        // 64 signature + 4 variant + 32 pubkey + 10 ipv4 socket addr + 8 wallclock
        assert_eq!(network::serialized_size(&ci).unwrap(), 118);
        // 4 variant + 32 from + 32 token + 64 signature
        assert_eq!(
            network::serialized_size(&Protocol::PingMessage(Ping::new(&kp))).unwrap(),
            132
        );
    }

    #[test]
    fn test_unspecified_bind_rejected() {
        let config = Config::new(
            "0.0.0.0:0".parse().unwrap(),
            None,
            Duration::from_millis(GOSSIP_INTERVAL_MS),
        );
        assert_eq!(
            Node::start(config, Keypair::new()).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
}
