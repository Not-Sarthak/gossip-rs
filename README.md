# gossip-rs

reimplementing solana's gossip protocol from scratch in rust

## components

- **bitvec** -- bit array packed into u64 chunks, used as the backing storage for the bloom filter
- **bloom filter** -- probabilistic data structure that tells you "definitely not in set" or "probably in set", used to avoid sending duplicate data during gossip
- **crds table** -- conflict-free replicated data store where higher timestamps win, holds all shared validator data
- **protocol** -- five message types that make up the entire gossip vocabulary: PullRequest, PullResponse, PushMessage, Ping, Pong
- **node** -- a gossip participant that can ping peers for liveness, pull missing data using bloom filters, and push new data
- **network** -- UDP socket wrapper that serializes messages with bincode and sends them over the wire

## how it works

each node runs in its own thread with its own udp socket. every round, a node picks a random peer, pings it to check liveness, then sends a bloom filter of what it knows. the peer checks the filter and responds with entries the node is missing. after a few rounds, all nodes converge to the same state.

## run

```
cargo run
```
