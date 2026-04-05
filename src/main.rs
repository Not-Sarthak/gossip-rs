mod bitvec;
mod bloom;
mod crds;
mod node;
mod network;

use std::thread;
use std::time::Duration;
use node::{Node, Protocol};
use crds::CrdsValue;
use network::Network;

fn main() {
    // node_b runs in a separate thread, listening on port 9001
    let handle = thread::spawn(|| {
        let mut node_b = Node::new("BBB".into());
        node_b.crds.insert("BBB".into(), CrdsValue::ContactInfo { ip: "127.0.0.1".into(), port: 9001 }, 1000);
        node_b.crds.insert("BBB".into(), CrdsValue::Vote { slot: 200 }, 1000);

        let net = Network::new("127.0.0.1:9001");
        println!("node_b listening on 9001");

        // receive pull request from node_a
        let (msg, from) = net.receive();
        if let Protocol::PullRequest { filter, .. } = &msg {
            println!("node_b received pull request from {}", from);
            let response = node_b.handle_pull_request(filter);
            net.send(&from.to_string(), &response);
            println!("node_b sent pull response");
        }

        // receive push message from node_a
        let (msg, from) = net.receive();
        if let Protocol::PushMessage { entries, .. } = msg {
            println!("node_b received push from {}: {} entries", from, entries.len());
            node_b.handle_push_message(entries);
        }

        println!("node_b final keys: {:?}", node_b.crds.keys().collect::<Vec<_>>());
    });

    // give node_b time to start
    thread::sleep(Duration::from_millis(100));

    // node_a on port 9000
    let mut node_a = Node::new("AAA".into());
    node_a.crds.insert("AAA".into(), CrdsValue::ContactInfo { ip: "127.0.0.1".into(), port: 9000 }, 1000);
    node_a.crds.insert("AAA".into(), CrdsValue::Vote { slot: 100 }, 1000);

    let net = Network::new("127.0.0.1:9000");
    println!("node_a listening on 9000");

    // pull: node_a asks node_b for what it's missing
    let pull_request = node_a.create_pull_request();
    net.send("127.0.0.1:9001", &pull_request);
    println!("node_a sent pull request to node_b");

    let (response, _) = net.receive();
    if let Protocol::PullResponse { entries, .. } = response {
        println!("node_a received {} entries from node_b", entries.len());
        node_a.handle_pull_response(entries);
    }

    // push: node_a got new data, push it to node_b
    node_a.crds.insert("CCC".into(), CrdsValue::Vote { slot: 300 }, 2000);
    let new_entry = node_a.crds.get("CCC_Vote").unwrap().clone();
    let push = node_a.create_push_message(vec![new_entry]);
    net.send("127.0.0.1:9001", &push);
    println!("node_a pushed CCC_Vote to node_b");

    println!("node_a final keys: {:?}", node_a.crds.keys().collect::<Vec<_>>());

    handle.join().unwrap();
}
