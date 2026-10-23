// end-to-end tests: real nodes on real udp sockets bound to 127.0.0.1:0, plus a raw
// TestPeer socket that speaks the wire protocol directly to play attacker or observer
use gossip_rs::bloom::Bloom;
use gossip_rs::crds::{ContactInfo, CrdsData, CrdsValue, CrdsValueLabel, Keypair, Vote, timestamp};
use gossip_rs::network::{self, PACKET_DATA_SIZE};
use gossip_rs::node::{Config, Node, Protocol};
use gossip_rs::ping::{Ping, Pong};
use gossip_rs::pull::{CrdsFilter, FALSE_RATE, PULL_RESPONSE_MAX_BYTES};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

// fast intervals so a test cluster converges in well under a second per hop
const TEST_GOSSIP_INTERVAL: Duration = Duration::from_millis(20);
const TEST_PULL_INTERVAL: Duration = Duration::from_millis(100);
// a lost ping retried quickly instead of after the production 20 s
const TEST_PING_RATE_LIMIT: Duration = Duration::from_millis(500);
// every wait in these tests is a deadline on a condition, never a fixed sleep
const DEADLINE: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(5);
// a false positive rate low enough that single-value filter checks are deterministic in practice
const EXACT_RATE: f64 = 1e-9;

fn localhost() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn config(entrypoint: Option<SocketAddr>) -> Config {
    let mut config = Config::new(localhost(), entrypoint, TEST_GOSSIP_INTERVAL);
    config.pull_interval = TEST_PULL_INTERVAL;
    config.ping_rate_limit = TEST_PING_RATE_LIMIT;
    config
}

fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(POLL);
    }
    done()
}

fn converged(nodes: &[Node]) -> bool {
    let first = nodes[0].table();
    nodes.iter().all(|n| n.table() == first)
}

// node 0 is the entrypoint; everyone else only knows its address
fn cluster(size: usize, make: impl Fn(Option<SocketAddr>) -> Config) -> Vec<Node> {
    let first = Node::start(make(None), Keypair::new()).unwrap();
    let entrypoint = first.gossip_addr();
    let mut nodes = vec![first];
    for _ in 1..size {
        nodes.push(Node::start(make(Some(entrypoint)), Keypair::new()).unwrap());
    }
    nodes
}

fn vote_label(node: &Node) -> CrdsValueLabel {
    CrdsValueLabel::Vote(node.pubkey())
}

fn slot_of(value: &CrdsValue) -> Option<u64> {
    match &value.data {
        CrdsData::Vote(vote) => Some(vote.slot),
        _ => None,
    }
}

fn signed_vote(keypair: &Keypair, slot: u64, wallclock: u64) -> CrdsValue {
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

// a raw socket with its own identity, answering pings so nodes can verify it
struct TestPeer {
    keypair: Keypair,
    socket: UdpSocket,
}

impl TestPeer {
    fn new() -> Self {
        TestPeer {
            keypair: Keypair::new(),
            socket: UdpSocket::bind(localhost()).unwrap(),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    fn contact_info(&self) -> CrdsValue {
        let data = CrdsData::ContactInfo(ContactInfo {
            pubkey: self.keypair.pubkey(),
            gossip: self.addr(),
            wallclock: timestamp(),
        });
        CrdsValue::new_signed(data, &self.keypair).unwrap()
    }

    fn send(&self, to: SocketAddr, message: &Protocol) {
        self.socket
            .send_to(&network::serialize(message).unwrap(), to)
            .unwrap();
    }

    fn send_raw(&self, to: SocketAddr, bytes: &[u8]) {
        self.socket.send_to(bytes, to).unwrap();
    }

    // reads packets until on_message returns true or the timeout passes; answers every ping
    fn recv_until(
        &self,
        timeout: Duration,
        mut on_message: impl FnMut(&Protocol, usize) -> bool,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 65_536];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            self.socket.set_read_timeout(Some(left)).unwrap();
            let Ok((size, from)) = self.socket.recv_from(&mut buf) else {
                continue;
            };
            let message: Protocol =
                network::deserialize(&buf[..size]).expect("nodes only send well-formed packets");
            if let Protocol::PingMessage(ping) = &message {
                self.send(from, &Protocol::PongMessage(Pong::new(ping, &self.keypair)));
            }
            if on_message(&message, size) {
                return true;
            }
        }
    }

    // gets this peer ping-verified by the node: pull, answer its ping, until a response comes back
    fn handshake(&self, node: SocketAddr) {
        let answered = wait_until(DEADLINE, || {
            self.send(
                node,
                &Protocol::PullRequest(empty_filter(), self.contact_info()),
            );
            self.recv_until(Duration::from_millis(200), |m, _| {
                matches!(m, Protocol::PullResponse(..))
            })
        });
        assert!(answered, "node never answered a verified pull");
        // drain the rest of that response
        self.recv_until(Duration::from_millis(100), |_, _| false);
    }
}

// a filter that contains nothing, so the response is everything (up to the cap)
fn empty_filter() -> CrdsFilter {
    CrdsFilter {
        filter: Bloom::new(0, FALSE_RATE, 64),
        mask: !0,
        mask_bits: 0,
    }
}

#[test]
fn five_nodes_converge_on_values() {
    let started = Instant::now();
    let nodes = cluster(5, config);
    for (slot, node) in nodes.iter().enumerate() {
        node.publish_vote(slot as u64).unwrap();
    }
    assert!(wait_until(DEADLINE, || nodes[0].num_values() == 10
        && converged(&nodes)));
    eprintln!(
        "metric: 5 nodes converged in {} ms",
        started.elapsed().as_millis()
    );
    for (slot, node) in nodes.iter().enumerate() {
        for other in &nodes {
            assert_eq!(
                other.get(&vote_label(node)).and_then(|v| slot_of(&v)),
                Some(slot as u64)
            );
        }
    }
}

#[test]
fn update_propagates_via_push() {
    let nodes = cluster(3, config);
    nodes[0].publish_vote(1).unwrap();
    assert!(wait_until(DEADLINE, || nodes[0].num_values() == 4 && converged(&nodes)));

    // the observer joins node 0, so node 0 verifies it and adds it to its active set
    let observer = TestPeer::new();
    observer.handshake(nodes[0].gossip_addr());
    assert!(wait_until(DEADLINE, || nodes[0].active_set_len() == 3));
    let before: Vec<u64> = nodes[1..]
        .iter()
        .map(|n| n.metrics().push_values_inserted)
        .collect();

    nodes[0].publish_vote(2).unwrap();
    let pushed = observer.recv_until(DEADLINE, |m, _| match m {
        Protocol::PushMessage(_, values) => values
            .iter()
            .any(|v| v.pubkey() == nodes[0].pubkey() && slot_of(v) == Some(2)),
        _ => false,
    });
    assert!(pushed, "new vote never arrived in a PushMessage");
    assert!(wait_until(DEADLINE, || nodes.iter().all(|n| n
        .get(&vote_label(&nodes[0]))
        .and_then(|v| slot_of(&v))
        == Some(2))));
    for (node, before) in nodes[1..].iter().zip(before) {
        assert!(node.metrics().push_values_inserted > before);
    }
}

#[test]
fn update_propagates_via_pull() {
    let node = Node::start(config(None), Keypair::new()).unwrap();
    node.publish_vote(1).unwrap();
    let old = node.get(&vote_label(&node)).unwrap();
    let requester = TestPeer::new();
    requester.handshake(node.gossip_addr());
    // the requester already holds the old vote and the node's contact info
    let contact = node
        .get(&CrdsValueLabel::ContactInfo(node.pubkey()))
        .unwrap();

    node.publish_vote(2).unwrap();
    // a near-zero false positive rate, so the new hash can't be "contained" by chance
    let mut filter = CrdsFilter {
        filter: Bloom::new(2, EXACT_RATE, 1024),
        mask: !0,
        mask_bits: 0,
    };
    filter.filter.add(&old.hash().unwrap().0);
    filter.filter.add(&contact.hash().unwrap().0);
    let mut got_new = false;
    let mut got_old = false;
    requester.send(
        node.gossip_addr(),
        &Protocol::PullRequest(filter, requester.contact_info()),
    );
    requester.recv_until(Duration::from_secs(2), |m, _| {
        if let Protocol::PullResponse(_, values) = m {
            got_new |= values
                .iter()
                .any(|v| v.pubkey() == node.pubkey() && slot_of(v) == Some(2));
            got_old |= values.contains(&old);
        }
        got_new
    });
    assert!(
        got_new,
        "a newer version of a value the requester has must be pulled"
    );
    assert!(!got_old);
}

#[test]
fn restart_with_newer_value_converges() {
    let identity = Keypair::new().to_bytes();
    let mut nodes = cluster(2, config);
    let entrypoint = nodes[0].gossip_addr();
    nodes.push(
        Node::start(
            config(Some(entrypoint)),
            Keypair::from_bytes(&identity).unwrap(),
        )
        .unwrap(),
    );
    for (slot, node) in nodes.iter().enumerate() {
        node.publish_vote(slot as u64).unwrap();
    }
    assert!(wait_until(DEADLINE, || nodes[0].num_values() == 6 && converged(&nodes)));

    let crashed = nodes.pop().unwrap();
    let old_addr = crashed.gossip_addr();
    crashed.shutdown();

    // same identity, new port, empty table, newer vote
    let restarted = Node::start(
        config(Some(entrypoint)),
        Keypair::from_bytes(&identity).unwrap(),
    )
    .unwrap();
    restarted.publish_vote(99).unwrap();
    let pubkey = restarted.pubkey();
    nodes.push(restarted);
    assert!(wait_until(DEADLINE, || nodes[2].num_values() == 6 && converged(&nodes)));
    for node in &nodes {
        assert_eq!(
            node.get(&CrdsValueLabel::Vote(pubkey))
                .and_then(|v| slot_of(&v)),
            Some(99)
        );
        let ci = node.get(&CrdsValueLabel::ContactInfo(pubkey)).unwrap();
        assert_ne!(ci.contact_info().unwrap().gossip, old_addr);
    }
}

#[test]
fn tie_converges_deterministically() {
    let nodes = cluster(3, config);
    assert!(wait_until(DEADLINE, || nodes[0].num_values() == 3 && converged(&nodes)));

    // one key signs two different votes with the same wallclock and gives each to a different node
    let equivocator = Keypair::new();
    let now = timestamp();
    let a = signed_vote(&equivocator, 1, now);
    let b = signed_vote(&equivocator, 2, now);
    let winner = if a.hash().unwrap() > b.hash().unwrap() {
        a.clone()
    } else {
        b.clone()
    };
    let peer = TestPeer::new();
    peer.send(
        nodes[0].gossip_addr(),
        &Protocol::PushMessage(peer.keypair.pubkey(), vec![a]),
    );
    peer.send(
        nodes[2].gossip_addr(),
        &Protocol::PushMessage(peer.keypair.pubkey(), vec![b]),
    );

    let label = CrdsValueLabel::Vote(equivocator.pubkey());
    assert!(wait_until(DEADLINE, || nodes
        .iter()
        .all(|n| n.get(&label) == Some(winner.clone()))));
    assert!(converged(&nodes));
}

#[test]
fn forged_and_unsigned_values_are_rejected() {
    let nodes = cluster(3, config);
    for (slot, node) in nodes.iter().enumerate() {
        node.publish_vote(slot as u64).unwrap();
    }
    assert!(wait_until(DEADLINE, || nodes[0].num_values() == 6 && converged(&nodes)));
    let victim = nodes[0].pubkey();
    let honest = nodes[0].get(&CrdsValueLabel::Vote(victim)).unwrap();
    let honest_ci = nodes[0].get(&CrdsValueLabel::ContactInfo(victim)).unwrap();

    let attacker = TestPeer::new();
    let later = timestamp() + 10_000;
    let forged_vote = CrdsValue::new_signed(
        CrdsData::Vote(Vote {
            from: victim,
            slot: 666,
            wallclock: later,
        }),
        &attacker.keypair,
    )
    .unwrap();
    let forged_ci = CrdsValue::new_signed(
        CrdsData::ContactInfo(ContactInfo {
            pubkey: victim,
            gossip: attacker.addr(),
            wallclock: later,
        }),
        &attacker.keypair,
    )
    .unwrap();
    let unsigned = CrdsValue {
        signature: ed25519_dalek::Signature::from_bytes(&[0; 64]),
        ..forged_vote.clone()
    };
    // a genuine value from the attacker's own key, too far in the future to accept
    let future = signed_vote(&attacker.keypair, 1, timestamp() + 3_600_000);
    let hostile = vec![forged_vote, forged_ci, unsigned, future];

    for node in &nodes {
        attacker.send(
            node.gossip_addr(),
            &Protocol::PushMessage(attacker.keypair.pubkey(), hostile.clone()),
        );
        attacker.send(
            node.gossip_addr(),
            &Protocol::PullResponse(attacker.keypair.pubkey(), hostile.clone()),
        );
    }
    assert!(wait_until(DEADLINE, || nodes
        .iter()
        .all(|n| n.metrics().values_rejected >= 8)));
    for node in &nodes {
        assert_eq!(
            node.get(&CrdsValueLabel::Vote(victim)),
            Some(honest.clone())
        );
        assert_eq!(
            node.get(&CrdsValueLabel::ContactInfo(victim))
                .map(|v| v.wallclock() >= honest_ci.wallclock()),
            Some(true)
        );
        assert_ne!(
            node.get(&CrdsValueLabel::ContactInfo(victim))
                .unwrap()
                .contact_info()
                .unwrap()
                .gossip,
            attacker.addr()
        );
        assert!(
            node.get(&CrdsValueLabel::Vote(attacker.keypair.pubkey()))
                .is_none()
        );
    }
}

#[test]
fn malformed_packets_do_not_panic() {
    let node = Node::start(config(None), Keypair::new()).unwrap();
    node.publish_vote(1).unwrap();
    let peer = TestPeer::new();
    let to = node.gossip_addr();

    let valid: Vec<Vec<u8>> = vec![
        network::serialize(&Protocol::PullRequest(empty_filter(), peer.contact_info())).unwrap(),
        network::serialize(&Protocol::PushMessage(
            peer.keypair.pubkey(),
            vec![signed_vote(&peer.keypair, 1, timestamp())],
        ))
        .unwrap(),
        network::serialize(&Protocol::PingMessage(Ping::new(&peer.keypair))).unwrap(),
    ];
    let mut sent = 0u64;
    let mut send = |bytes: &[u8]| {
        peer.send_raw(to, bytes);
        sent += 1;
    };
    send(&[]);
    send(&[0xff; 7]);
    send(&[0xff; PACKET_DATA_SIZE]);
    // larger than a packet: dropped before decoding
    send(&vec![0u8; PACKET_DATA_SIZE + 200]);
    // the bloom filter that used to divide by zero: one seed, zero bits
    let caller = network::serialize(&peer.contact_info()).unwrap();
    let mut zero_bits =
        bincode::serialize(&(0u32, vec![1u64], Vec::<u64>::new(), 0u64, !0u64, 0u32)).unwrap();
    zero_bits.extend_from_slice(&caller);
    send(&zero_bits);
    // a filter claiming 10^9 bits backed by one block
    let mut lying_len =
        bincode::serialize(&(0u32, vec![1u64], vec![0u64], 1_000_000_000u64, !0u64, 0u32)).unwrap();
    lying_len.extend_from_slice(&caller);
    send(&lying_len);
    for packet in &valid {
        for cut in 0..packet.len() {
            send(&packet[..cut]);
        }
        for i in 0..packet.len() {
            for byte in [0x00u8, 0xff] {
                let mut mutated = packet.clone();
                mutated[i] = byte;
                send(&mutated);
            }
        }
    }
    assert!(wait_until(DEADLINE, || node.metrics().packets_received >= sent));
    assert!(node.metrics().malformed_packets > 0);

    // still alive: answers a ping with a valid pong
    let ping = Ping::new(&peer.keypair);
    peer.send(to, &Protocol::PingMessage(ping.clone()));
    let ponged = peer.recv_until(DEADLINE, |m, _| matches!(m, Protocol::PongMessage(p) if p.verify() && p.from == node.pubkey() && p.hash == gossip_rs::ping::pong_hash(&ping.token)));
    assert!(ponged);
    assert!(node.get(&vote_label(&node)).is_some());
}

#[test]
fn unverified_pull_gets_no_reply() {
    let node = Node::start(config(None), Keypair::new()).unwrap();
    node.publish_vote(1).unwrap();
    // the victim's genuine signed contact info, replayed from the attacker's socket (a spoofed source)
    let victim = TestPeer::new();
    let attacker = TestPeer::new();
    let stolen = victim.contact_info();
    let request = Protocol::PullRequest(empty_filter(), stolen);
    let request_bytes = network::serialize(&request).unwrap().len();
    attacker.send(node.gossip_addr(), &request);

    // the only replies are pings; the attacker answers them with its own key, which can't verify
    let mut largest_reply = 0usize;
    let mut only_pings = true;
    for _ in 0..2 {
        attacker.send(node.gossip_addr(), &request);
        attacker.recv_until(Duration::from_secs(1), |m, size| {
            largest_reply = largest_reply.max(size);
            only_pings &= matches!(m, Protocol::PingMessage(..));
            false
        });
    }
    assert!(
        only_pings,
        "an unverified pull drew something other than a ping"
    );
    assert!(
        largest_reply <= request_bytes,
        "reply {largest_reply} bytes to a {request_bytes} byte request"
    );
    assert_eq!(node.metrics().pull_requests_answered, 0);
    assert!(node.metrics().pull_requests_unverified >= 2);
    eprintln!(
        "metric: unverified pull of {request_bytes} bytes drew at most a {largest_reply} byte ping"
    );
}

#[test]
fn every_packet_fits_with_a_large_table() {
    // a table bigger than one filter holds, so pulls split into several filters
    const LARGE_TABLE: usize = 3000;
    let a = Node::start(config(None), Keypair::new()).unwrap();
    let feeder = TestPeer::new();
    let now = timestamp();
    let values: Vec<CrdsValue> = (0..LARGE_TABLE)
        .map(|i| signed_vote(&Keypair::new(), i as u64, now))
        .collect();
    let empty =
        network::serialized_size(&Protocol::PushMessage(feeder.keypair.pubkey(), vec![])).unwrap();
    let chunks = network::split_by_size(values, PACKET_DATA_SIZE - empty);
    // a few packets at a time, waiting for each batch, so nothing overruns the socket buffer
    for batch in chunks.chunks(20) {
        let expected =
            a.metrics().push_values_inserted + batch.iter().map(|c| c.len() as u64).sum::<u64>();
        for chunk in batch {
            feeder.send(
                a.gossip_addr(),
                &Protocol::PushMessage(feeder.keypair.pubkey(), chunk.clone()),
            );
        }
        assert!(
            wait_until(DEADLINE, || a.metrics().push_values_inserted >= expected),
            "{:?}",
            a.metrics()
        );
    }
    assert_eq!(a.num_values(), LARGE_TABLE + 1);

    let started = Instant::now();
    let b = Node::start(config(Some(a.gossip_addr())), Keypair::new()).unwrap();
    assert!(wait_until(DEADLINE, || b.num_values() == LARGE_TABLE + 2
        && a.table() == b.table()));
    let sync_ms = started.elapsed().as_millis();

    // a verified pull with an empty filter: many packets back, each within the limit, capped in total
    let observer = TestPeer::new();
    observer.handshake(a.gossip_addr());
    observer.send(
        a.gossip_addr(),
        &Protocol::PullRequest(empty_filter(), observer.contact_info()),
    );
    let mut packets = 0;
    let mut largest = 0;
    let mut value_bytes = 0;
    observer.recv_until(Duration::from_secs(2), |m, size| {
        if let Protocol::PullResponse(_, values) = m {
            packets += 1;
            largest = largest.max(size);
            value_bytes += values
                .iter()
                .map(|v| network::serialized_size(v).unwrap())
                .sum::<usize>();
        }
        false
    });
    assert!(packets > 1 && largest <= PACKET_DATA_SIZE && value_bytes <= PULL_RESPONSE_MAX_BYTES);
    for node in [&a, &b] {
        let m = node.metrics();
        assert!(
            m.max_packet_bytes <= PACKET_DATA_SIZE as u64,
            "sent a {} byte packet",
            m.max_packet_bytes
        );
        assert_eq!(m.oversized_messages, 0);
    }
    eprintln!(
        "metric: new node synced {} values in {sync_ms} ms; one pull = {packets} packets, largest {largest} bytes; max sent a={} b={}",
        LARGE_TABLE + 2,
        a.metrics().max_packet_bytes,
        b.metrics().max_packet_bytes
    );
}

#[test]
fn stale_values_are_purged() {
    // short timeout so a vanished node's values expire within the test
    const TIMEOUT: Duration = Duration::from_millis(1000);
    let nodes = cluster(2, |entrypoint| {
        let mut c = config(entrypoint);
        c.crds_timeout = TIMEOUT;
        c
    });
    for node in &nodes {
        node.publish_vote(1).unwrap();
    }
    assert!(wait_until(DEADLINE, || nodes[0].num_values() == 4 && converged(&nodes)));
    let mut nodes = nodes;
    let gone = nodes.pop().unwrap();
    let gone_pubkey = gone.pubkey();
    gone.shutdown();
    let survivor = &nodes[0];

    // the dead node's contact info and vote are purged; the survivor keeps its own values
    assert!(wait_until(DEADLINE, || survivor.num_values() == 2));
    assert!(
        survivor
            .get(&CrdsValueLabel::ContactInfo(gone_pubkey))
            .is_none()
    );
    assert!(survivor.get(&CrdsValueLabel::Vote(gone_pubkey)).is_none());
    assert!(survivor.get(&vote_label(survivor)).is_some());
    assert!(survivor.metrics().values_purged >= 2);
}

#[test]
fn table_capacity_is_enforced() {
    const CAPACITY: usize = 100;
    let mut c = config(None);
    c.crds_capacity = CAPACITY;
    let node = Node::start(c, Keypair::new()).unwrap();
    node.publish_vote(1).unwrap();
    let feeder = TestPeer::new();
    let now = timestamp();
    let empty =
        network::serialized_size(&Protocol::PushMessage(feeder.keypair.pubkey(), vec![])).unwrap();
    let values: Vec<CrdsValue> = (0..CAPACITY * 3)
        .map(|i| signed_vote(&Keypair::new(), 1, now + i as u64))
        .collect();
    let chunks = network::split_by_size(values, PACKET_DATA_SIZE - empty);
    for chunk in &chunks {
        feeder.send(
            node.gossip_addr(),
            &Protocol::PushMessage(feeder.keypair.pubkey(), chunk.clone()),
        );
    }
    assert!(wait_until(DEADLINE, || node.metrics().push_values_inserted
        >= (CAPACITY * 3) as u64));
    assert_eq!(node.num_values(), CAPACITY);
    // own values are never evicted
    assert!(node.get(&vote_label(&node)).is_some());
    assert!(
        node.get(&CrdsValueLabel::ContactInfo(node.pubkey()))
            .is_some()
    );
}

#[test]
fn prune_reduces_duplicate_pushes() {
    // updates published by one origin; the first and last windows are compared
    const UPDATES: u64 = 60;
    const WINDOW: u64 = 15;
    let nodes = cluster(5, |entrypoint| {
        let mut c = config(entrypoint);
        // no rotation during the measurement, so pruned paths stay pruned
        c.active_set_rotate_interval = Duration::from_secs(3600);
        c
    });
    assert!(wait_until(DEADLINE, || nodes
        .iter()
        .all(|n| n.active_set_len() == 4)));
    let origin = &nodes[0];
    let receivers = &nodes[1..];
    let duplicates = || {
        receivers
            .iter()
            .map(|n| n.metrics().push_duplicates)
            .sum::<u64>()
    };

    // cumulative duplicate count at the moment each update is published; one extra update
    // closes the last window, so every window counts the copies of exactly WINDOW updates
    let mut at_publish = Vec::new();
    for slot in 1..=UPDATES + 1 {
        at_publish.push(duplicates());
        origin.publish_vote(slot).unwrap();
        assert!(wait_until(DEADLINE, || receivers
            .iter()
            .all(
                |n| n.get(&vote_label(origin)).and_then(|v| slot_of(&v)) == Some(slot)
            )));
    }
    let first = at_publish[WINDOW as usize] - at_publish[0];
    let last = at_publish[UPDATES as usize] - at_publish[(UPDATES - WINDOW) as usize];
    let prunes: u64 = receivers.iter().map(|n| n.metrics().prunes_sent).sum();
    eprintln!(
        "metric: duplicate pushes per update across 4 receivers: first {WINDOW} = {:.2}, last {WINDOW} = {:.2} ({:.0}% fewer), {prunes} prunes sent",
        first as f64 / WINDOW as f64,
        last as f64 / WINDOW as f64,
        100.0 * (1.0 - last as f64 / first as f64)
    );
    assert!(prunes > 0);
    assert!(last * 2 < first, "first {first} last {last}");
}
