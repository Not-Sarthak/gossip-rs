mod bitvec;
mod bloom;
mod crds;
mod node;
mod network;

use std::thread;
use std::time::Duration;
use node::Node;
use crds::CrdsValue;
use network::Network;

fn run_node(mut node: Node, net: Network, rounds: usize) {
    // listen for incoming messages between gossip rounds
    for round in 0..rounds {
        println!("\n[round {}] {} has {} keys", round, node.id, node.crds.entries.len());

        // listen for any incoming messages (pull requests, pushes, pings)
        for _ in 0..5 {
            node.listen_once(&net, Duration::from_millis(100));
        }

        // do a gossip round (ping + pull from a random peer)
        node.gossip_round(&net);

        thread::sleep(Duration::from_millis(200));
    }

    println!("\n{} final state", node.id);
    println!("  keys: {:?}", node.crds.keys().collect::<Vec<_>>());
    println!("  alive peers: {:?}", node.alive_peers);
}

fn main() {
    let addr_a = "127.0.0.1:9000";
    let addr_b = "127.0.0.1:9001";
    let addr_c = "127.0.0.1:9002";

    let rounds = 5;

    // node_a
    let handle_a = thread::spawn(move || {
        let mut node_a = Node::new("node_a".into(), addr_a.into());
        node_a.known_peers.push(addr_b.into());
        node_a.known_peers.push(addr_c.into());
        node_a.crds.insert("AAA".into(), CrdsValue::ContactInfo { ip: "127.0.0.1".into(), port: 9000 }, 1000);
        node_a.crds.insert("AAA".into(), CrdsValue::Vote { slot: 100 }, 1000);

        let net = Network::new(addr_a);
        run_node(node_a, net, rounds);
    });

    // node_b
    let handle_b = thread::spawn(move || {
        let mut node_b = Node::new("node_b".into(), addr_b.into());
        node_b.known_peers.push(addr_a.into());
        node_b.known_peers.push(addr_c.into());
        node_b.crds.insert("BBB".into(), CrdsValue::ContactInfo { ip: "127.0.0.1".into(), port: 9001 }, 1000);
        node_b.crds.insert("BBB".into(), CrdsValue::Vote { slot: 200 }, 1000);

        let net = Network::new(addr_b);
        run_node(node_b, net, rounds);
    });

    // node_c
    let handle_c = thread::spawn(move || {
        let mut node_c = Node::new("node_c".into(), addr_c.into());
        node_c.known_peers.push(addr_a.into());
        node_c.known_peers.push(addr_b.into());
        node_c.crds.insert("CCC".into(), CrdsValue::ContactInfo { ip: "127.0.0.1".into(), port: 9002 }, 1000);
        node_c.crds.insert("CCC".into(), CrdsValue::Vote { slot: 300 }, 1000);

        let net = Network::new(addr_c);
        run_node(node_c, net, rounds);
    });

    handle_a.join().unwrap();
    handle_b.join().unwrap();
    handle_c.join().unwrap();
}
