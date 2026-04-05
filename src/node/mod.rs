use crate::bloom::Bloom;
use crate::crds::{CrdsTable, CrdsEntry};
use crate::network::Network;
use std::collections::{HashSet, HashMap};
use std::time::Duration;
use serde::{Deserialize, Serialize};

// gossip protocol message types
//
// pull: "tell me what i'm missing"
//   node_a → PullRequest { filter } → node_b
//   node_b checks its CRDS entries against node_a's bloom filter
//   node_b → PullResponse { entries node_a is missing } → node_a
//
// push: "here's something new"
//   node_a → PushMessage { new entries } → node_b
//   node_b inserts into its CRDS table
//   (no response needed)
//
// ping/pong: "are you alive?"
//   node_a → Ping { token } → node_b
//   node_b → Pong { same token } → node_a
//   node_a now knows node_b is alive and will gossip with it

#[derive(Serialize, Deserialize)]
pub enum Protocol {
    PullRequest {
        from: String,
        filter: Bloom<u64>,
    },
    PullResponse {
        from: String,
        entries: Vec<CrdsEntry>,
    },
    PushMessage {
        from: String,
        entries: Vec<CrdsEntry>,
    },
    Ping {
        from: String,
        token: u64,
    },
    Pong {
        from: String,
        token: u64,
    },
}

pub struct Node {
    pub id: String,
    pub addr: String,
    pub crds: CrdsTable,
    pub alive_peers: HashSet<String>,
    pub known_peers: Vec<String>,           // addresses of peers
    pub pending_pings: HashMap<String, u64>, // peer addr -> expected token
}

impl Node {
    pub fn new(id: String, addr: String) -> Self {
        Node {
            id,
            addr,
            crds: CrdsTable::new(),
            alive_peers: HashSet::new(),
            known_peers: Vec::new(),
            pending_pings: HashMap::new(),
        }
    }

    // handle any incoming message and optionally return a response
    pub fn handle_message(&mut self, msg: Protocol, from: &str) -> Option<Protocol> {
        match msg {
            Protocol::PullRequest { filter, .. } => {
                let missing: Vec<CrdsEntry> = self.crds.entries.iter()
                    .filter(|(key, _)| !filter.contains(key.as_bytes()))
                    .map(|(_, entry)| entry.clone())
                    .collect();
                println!("  {} received pull request from {}, sending {} entries", self.id, from, missing.len());
                Some(Protocol::PullResponse {
                    from: self.id.clone(),
                    entries: missing,
                })
            }
            Protocol::PullResponse { entries, .. } => {
                println!("  {} received pull response: {} entries", self.id, entries.len());
                for entry in entries {
                    self.crds.insert(entry.pubkey.clone(), entry.value.clone(), entry.timestamp);
                }
                None
            }
            Protocol::PushMessage { entries, from: sender, .. } => {
                println!("  {} received push from {}: {} entries", self.id, sender, entries.len());
                for entry in entries {
                    self.crds.insert(entry.pubkey.clone(), entry.value.clone(), entry.timestamp);
                }
                None
            }
            Protocol::Ping { token, from: sender, .. } => {
                println!("  {} received ping from {}", self.id, sender);
                Some(Protocol::Pong {
                    from: self.id.clone(),
                    token,
                })
            }
            Protocol::Pong { token, from: sender, .. } => {
                if let Some(&expected) = self.pending_pings.get(from) {
                    if expected == token {
                        println!("  {} verified pong from {} -- peer is alive", self.id, sender);
                        self.alive_peers.insert(from.to_string());
                        self.pending_pings.remove(from);
                    }
                }
                None
            }
        }
    }

    // create pull request
    pub fn create_pull_request(&self) -> Protocol {
        let mut filter = Bloom::<u64>::new(100, 0.01, 10000);
        for key in self.crds.keys() {
            filter.add(key.as_bytes());
        }
        Protocol::PullRequest {
            from: self.id.clone(),
            filter,
        }
    }

    // create push message
    pub fn create_push_message(&self, entries: Vec<CrdsEntry>) -> Protocol {
        Protocol::PushMessage {
            from: self.id.clone(),
            entries,
        }
    }

    // create ping with random token
    pub fn create_ping(&mut self, peer_addr: &str) -> Protocol {
        let token: u64 = rand::random();
        self.pending_pings.insert(peer_addr.to_string(), token);
        Protocol::Ping {
            from: self.id.clone(),
            token,
        }
    }

    // run one gossip round: ping a random peer, pull from it, push new data
    pub fn gossip_round(&mut self, net: &Network) {
        if self.known_peers.is_empty() {
            return;
        }

        // pick a random peer
        use rand::RngExt;
        let peer_idx = rand::rng().random_range(0..self.known_peers.len());
        let peer_addr = self.known_peers[peer_idx].clone();

        // step 1: ping the peer
        let ping = self.create_ping(&peer_addr);
        net.send(&peer_addr, &ping);

        // wait for pong
        if let Some((msg, from)) = net.try_receive(Duration::from_millis(500)) {
            if let Some(response) = self.handle_message(msg, &from.to_string()) {
                net.send(&from.to_string(), &response);
            }
        }

        // only gossip with alive peers
        if !self.alive_peers.contains(&peer_addr) {
            println!("  {} peer {} not alive, skipping pull", self.id, peer_addr);
            return;
        }

        // step 2: pull from the peer
        let pull_req = self.create_pull_request();
        net.send(&peer_addr, &pull_req);

        // wait for pull response
        if let Some((msg, from)) = net.try_receive(Duration::from_millis(500)) {
            self.handle_message(msg, &from.to_string());
        }
    }

    // listen for incoming messages and respond
    pub fn listen_once(&mut self, net: &Network, timeout: Duration) {
        if let Some((msg, from)) = net.try_receive(timeout) {
            if let Some(response) = self.handle_message(msg, &from.to_string()) {
                net.send(&from.to_string(), &response);
            }
        }
    }
}
