// pull protocol

use crate::bloom::Bloom;
use crate::crds::{CrdsTable, CrdsEntry};
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
// gossip protocol message types
//
// pull: "tell me what i'm missing"
//   node A → PullRequest { filter } → node B
//   node B checks its CRDS entries against A's bloom filter
//   node B → PullResponse { entries A is missing } → node A
//
// push: "here's something new"
//   node A → PushMessage { new entries } → node B
//   node B inserts into its CRDS table
//   (no response needed)
//
// ping/pong: "are you alive?"
//   node A → Ping { token } → node B
//   node B → Pong { same token } → node A
//   A now knows B is alive and will gossip with it
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
    }
}

pub struct Node {
    pub id: String,
    pub crds: CrdsTable,
    pub alive_peers: HashSet<String>,
}

impl Node {
    pub fn new(id: String) -> Self {
        Node {
            id,
            crds: CrdsTable::new(),
            alive_peers: HashSet::new(),
        }
    }
    
    // pull
    pub fn create_pull_request(&self) -> Protocol {
        let mut filter = Bloom::<u64>::new(100, 0.01, 10000);
        for key in self.crds.keys() {
            filter.add(key.as_bytes());
        }
        
        Protocol::PullRequest { 
            from: self.id.clone(), 
            filter 
        }
    }
    
    pub fn handle_pull_request(&self, filter: &Bloom<u64>) -> Protocol {
        let missing: Vec<CrdsEntry> = self.crds.entries.iter()
            .filter(|(key, _)| !filter.contains(key.as_bytes()))
            .map(|(_, entry)| entry.clone())
            .collect();
        
        Protocol::PullResponse { 
            from: self.id.clone(), 
            entries: missing 
        }
    }
    
    pub fn handle_pull_response(&mut self, entries: Vec<CrdsEntry>) {
        for entry in entries {
            self.crds.insert(entry.pubkey.clone(), entry.value.clone(), entry.timestamp);
        }
    }
    
    // push
    pub fn create_push_message(&self, entries: Vec<CrdsEntry>) -> Protocol {
        Protocol::PushMessage { 
            from: self.id.clone(), 
            entries 
        }
    }
    
    pub fn handle_push_message(&mut self, entries: Vec<CrdsEntry>) {
        for entry in entries {
            self.crds.insert(entry.pubkey.clone(), entry.value.clone(), entry.timestamp);
        }
    }
    
    // ping-pong
    pub fn create_ping(&self) -> Protocol {
        Protocol::Ping {
            from: self.id.clone(),
            token: rand::random(),
        }
    }
  
    pub fn handle_ping(&self, token: u64) -> Protocol {
        Protocol::Pong {
            from: self.id.clone(),
            token,
        }
    }
    
    pub fn handle_pong(&mut self, from: String, expected_token: u64, received_token: u64) -> bool {
        if expected_token == received_token {
            self.alive_peers.insert(from);
            true
        } else {
            false
        }
    }
}