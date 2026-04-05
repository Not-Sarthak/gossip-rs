mod bitvec;
mod bloom;

use bloom::Bloom;

fn main() {
    let node_a = vec!["txn_01", "txn_02", "txn_03", "txn_04"];
    let node_b = vec!["txn_04", "txn_05", "txn_06", "txn_07"];
    
    // node_a builds a bloom filter of what it has
    let mut filter = Bloom::<u64>::new(100, 0.01, 10000);
    for item in &node_a {
        filter.add(item.as_bytes());
    }
    
    // node_b checks what node_a is missing
    let mut missing: Vec<&str> = Vec::new();
    for item in &node_b {
        if !filter.contains(item.as_bytes()) {
            missing.push(item);
        }
    }
    
    println!("node_a has: {:?}", node_a);
    println!("node_b has: {:?}", node_b);
    println!("node_b sends to node_a: {:?}", missing);
}