use crate::node::{Metrics, Protocol};
use bincode::Options;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// largest gossip payload: the ipv6 minimum mtu (1280) minus the ipv6 (40) and udp (8) headers,
// so a packet never fragments on any path (agave's PACKET_DATA_SIZE)
pub const PACKET_DATA_SIZE: usize = 1280 - 40 - 8;

// how often the socket threads wake up to check for shutdown
const SOCKET_POLL: Duration = Duration::from_millis(50);

// one encoding for everything on the wire: fixed-width integers, and a hard size limit so
// neither side can produce or accept more than one packet's worth of bytes
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(PACKET_DATA_SIZE as u64)
        .with_fixint_encoding()
}

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    options().serialize(value)
}

pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::Error> {
    options().deserialize(bytes)
}

// size on the wire, without the packet limit, so callers can measure what would not fit
pub fn serialized_size<T: Serialize>(value: &T) -> Result<usize, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialized_size(value)
        .map(|size| size as usize)
}

// greedily packs items into chunks whose encoded size fits in budget bytes;
// an item that can never fit on its own is dropped
pub fn split_by_size<T: Serialize>(items: Vec<T>, budget: usize) -> Vec<Vec<T>> {
    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    let mut used = 0;
    for item in items {
        let Ok(size) = serialized_size(&item) else {
            continue;
        };
        if size > budget {
            continue;
        }
        if used + size > budget {
            chunks.push(std::mem::take(&mut chunk));
            used = 0;
        }
        used += size;
        chunk.push(item);
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    chunks
}

pub fn bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(SOCKET_POLL))?;
    Ok(socket)
}

// reads datagrams, decodes them and hands them to the dispatcher. anything oversized or
// malformed is counted and dropped; a full queue drops instead of growing without bound
pub fn spawn_receiver(
    name: String,
    socket: UdpSocket,
    exit: Arc<AtomicBool>,
    inbox: SyncSender<(Protocol, SocketAddr)>,
    metrics: Arc<Metrics>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name(name).spawn(move || {
        // one byte of headroom tells an oversized datagram apart from a full-size one
        let mut buf = [0u8; PACKET_DATA_SIZE + 1];
        while !exit.load(Ordering::Relaxed) {
            let (size, from) = match socket.recv_from(&mut buf) {
                Ok(received) => received,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    // e.g. an icmp port-unreachable surfacing from an earlier send
                    tracing::trace!("recv error: {e}");
                    continue;
                }
            };
            Metrics::inc(&metrics.packets_received);
            if size > PACKET_DATA_SIZE {
                Metrics::inc(&metrics.malformed_packets);
                continue;
            }
            let message = match deserialize::<Protocol>(&buf[..size]) {
                Ok(message) => message,
                Err(e) => {
                    tracing::debug!("malformed packet from {from}: {e}");
                    Metrics::inc(&metrics.malformed_packets);
                    continue;
                }
            };
            match inbox.try_send((message, from)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => Metrics::inc(&metrics.inbox_dropped),
                Err(TrySendError::Disconnected(_)) => break,
            }
        }
    })
}

// writes already-encoded packets to the socket; send errors are counted, never fatal
pub fn spawn_sender(
    name: String,
    socket: UdpSocket,
    exit: Arc<AtomicBool>,
    outbox: Receiver<(SocketAddr, Vec<u8>)>,
    metrics: Arc<Metrics>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name(name).spawn(move || {
        while !exit.load(Ordering::Relaxed) {
            let (addr, bytes) = match outbox.recv_timeout(SOCKET_POLL) {
                Ok(packet) => packet,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };
            match socket.send_to(&bytes, addr) {
                Ok(_) => {
                    Metrics::inc(&metrics.packets_sent);
                    Metrics::add(&metrics.bytes_sent, bytes.len() as u64);
                    metrics
                        .max_packet_bytes
                        .fetch_max(bytes.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::debug!("send to {addr} failed: {e}");
                    Metrics::inc(&metrics.send_errors);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_refuses_more_than_a_packet() {
        let small = vec![0u8; 100];
        assert!(deserialize::<Vec<u8>>(&serialize(&small).unwrap()).is_ok());
        // the 8 byte length prefix pushes it over
        let big = vec![0u8; PACKET_DATA_SIZE];
        assert!(serialize(&big).is_err());
        assert!(serialize(&vec![0u8; PACKET_DATA_SIZE - 8]).is_ok());
    }

    #[test]
    fn test_huge_length_prefix_is_an_error_not_an_allocation() {
        let mut bytes = u64::MAX.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 16]);
        assert!(deserialize::<Vec<u64>>(&bytes).is_err());
    }

    #[test]
    fn test_trailing_bytes_rejected() {
        let mut bytes = serialize(&7u64).unwrap();
        bytes.push(0);
        assert!(deserialize::<u64>(&bytes).is_err());
    }

    #[test]
    fn test_split_by_size() {
        let items: Vec<u64> = (0..100).collect();
        let chunks = split_by_size(items, 80);
        assert_eq!(chunks.len(), 10);
        assert!(chunks.iter().all(|c| c.len() == 10));
        // an item larger than the budget is dropped, the rest still packs
        let mixed = vec![vec![0u8; 10], vec![0u8; 500], vec![0u8; 10]];
        let chunks = split_by_size(mixed, 100);
        assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), 2);
    }
}
