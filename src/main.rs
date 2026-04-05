mod bitvec;
mod bloom;
mod crds;

use bloom::Bloom;
use crds::{CrdsTable, CrdsValue};
 
fn main() {
    let mut node_a = CrdsTable::new();
    let mut node_b = CrdsTable::new();
    
    // node_a knows about itself and one peer
    node_a.insert("AAA".into(), CrdsValue::ContactInfo { ip: "1.1.1.1".into(), port: 8001 }, 1000);
    node_a.insert("AAA".into(), CrdsValue::Vote { slot: 100 }, 1000);
    
    // node_b knows about itself and one peer
    node_b.insert("BBB".into(), CrdsValue::ContactInfo { ip: "2.2.2.2".into(), port: 8002 }, 1000);
    node_b.insert("BBB".into(), CrdsValue::Vote { slot: 200 }, 1000);
    
    // node_a builds bloom filter of its keys
    let mut filter = Bloom::<u64>::new(100, 0.01, 10000);
    for key in node_a.keys() {
        filter.add(key.as_bytes());
    }
    
    // node_b finds what node_a is missing
    let missing: Vec<String> = node_b.keys()
        .filter(|key| !filter.contains(key.as_bytes()))
        .cloned()
        .collect();
    
    println!("node_a keys: {:?}", node_a.keys().collect::<Vec<_>>());
    println!("node_b keys: {:?}", node_b.keys().collect::<Vec<_>>());
    println!("node_b sends to node_a: {:?}", missing);
}