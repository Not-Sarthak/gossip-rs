# gossip-rs

solana's gossip protocol (agave core) in rust over udp.

## architecture

```
            ┌──────────────────────────── node ─────────────────────────────┐
 udp ──▶ receive ──▶ dispatch ──▶ crds (signed values, wallclock + hash wins)
            │           │  ├── PullRequest  ── ping-verified? ──▶ values not in the filter
            │           │  ├── PushMessage  ──▶ received cache ──▶ PruneMessage to slow senders
            │           │  ├── PruneMessage ──▶ active set drops that origin for that peer
            │           │  └── Ping / Pong  ──▶ ping cache (ttl)
            │         push ── every interval: refresh contact info, purge, ping peers,
            │           │      rotate active set, new values ──▶ fanout peers
            │         pull ── every 5 intervals: bloom filters of value hashes
            │           │      (split by mask bits) ──▶ random peer or entrypoint
 udp ◀── send ◀─────────┴── every packet ≤ 1232 bytes
            └───────────────────────────────────────────────────────────────┘
```

## layout

```
src/bitvec/    bit array behind the bloom filter, validated on decode
src/bloom/     bloom filter, sizing from n and p, validated on decode
src/crds/      pubkey, hash, keypair, CrdsValue / CrdsData, crds table
src/network/   PACKET_DATA_SIZE, bounded bincode, packet splitting, socket threads
src/node/      Protocol, Config, Metrics, node threads and dispatcher
src/ping/      Ping, Pong, ping cache
src/pull/      CrdsFilter, CrdsFilterSet, pull requests and responses
src/push/      active set, received cache, PruneData
src/main.rs    cli: node, demo, keygen
tests/         multi-node tests over real udp on 127.0.0.1
```

## message types

| # | message | carries | reply |
|---|---------|---------|-------|
| 0 | `PullRequest` | `CrdsFilter`, caller's signed `ContactInfo` | `PullResponse` if ping-verified, else `PingMessage` |
| 1 | `PullResponse` | sender, values missing from the filter | none |
| 2 | `PushMessage` | sender, new values | `PruneMessage` once duplicates are ranked |
| 3 | `PruneMessage` | sender, signed `PruneData` (origins, destination, wallclock) | none |
| 4 | `PingMessage` | random token, signed | `PongMessage` |
| 5 | `PongMessage` | `sha256("SOLANA_PING_PONG" ‖ token)`, signed | none |

## components

| component | rule |
|-----------|------|
| crds | cluster replicated data store; one value per (pubkey, kind) |
| `CrdsValue` | ed25519 signature over `CrdsData`; signer must be the value's pubkey |
| `CrdsData` | `ContactInfo { pubkey, gossip, wallclock }`, `Vote { from, slot, wallclock }` |
| override | newer wallclock wins; equal wallclock: larger value hash wins |
| wallclock window | rejected if > 30 s ahead; pushes rejected if > 30 s old |
| purge | values not refreshed within 15 s; own values kept; contact info re-signed every 3.75 s |
| capacity | 8192 values; oldest foreign value evicted |
| pull filter | bloom of value hashes plus recently purged hashes, p = 0.1, sized from the table |
| mask bits | `2^mask_bits` filters, one packet each, when one filter can't hold the table |
| pull response | 64 KiB of values per request, random order, split into packets |
| push | fanout 6 from an active set of 9 ping-verified peers, rotated every 7.5 s |
| prune | after 20 new values from an origin, keep the 2 best senders, prune the rest |
| ping cache | pong trusted 1280 s, re-ping at half ttl, one ping per remote per 20 s |
| threads | receive, dispatch, push, pull, send; bounded channels of 8192 packets |
| wire | bincode, fixed-width ints, 1232-byte limit both ways, trailing bytes rejected |

## metrics

release build, localhost, apple m3 pro.

| run | result |
|-----|-------:|
| `demo --nodes 3` (100 ms interval) | 1.0 to 1.5 s |
| `demo --nodes 5` | 1.0 to 2.0 s |
| `demo --nodes 10` | 2.0 to 2.5 s |
| `demo --nodes 20` | 2.0 to 3.2 s |
| 5-node test cluster (20 ms interval) | 227 to 329 ms |
| new node pulling a 3002-value table | 716 to 811 ms |

| measure | value |
|---------|------:|
| duplicate pushes per update, 4 receivers, before prunes | 10.0 to 11.7 |
| duplicate pushes per update, after prunes | 4.1 to 4.2 |
| reduction | 58 to 65 % |
| largest packet sent, 3002-value table | 1206 bytes |
| packets in one capped pull response | 57 |
| unverified pull (174 bytes) reply | one 132-byte ping |
| `ContactInfo` value | 118 bytes |
| bloom false positive rate, n = 1000, p = 0.01 | under 0.015 |

## build & run

```
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo run --release -- demo --nodes 5
cargo run --release -- keygen --outfile id.json
cargo run --release -- node --bind 127.0.0.1:8000 --keypair id.json
cargo run --release -- node --bind 127.0.0.1:8001 --entrypoint 127.0.0.1:8000 --vote-interval-ms 400
```
