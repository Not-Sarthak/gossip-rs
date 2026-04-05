use std::net::UdpSocket;
use std::time::Duration;
use crate::node::Protocol;

pub struct Network {
    pub socket: UdpSocket,
}

impl Network {
    pub fn new(addr: &str) -> Self {
        let socket = UdpSocket::bind(addr).expect("failed to bind socket");
        Network { socket }
    }

    pub fn send(&self, target: &str, message: &Protocol) {
        let bytes = bincode::serialize(message).expect("failed to serialize");
        self.socket.send_to(&bytes, target).expect("failed to send");
    }

    pub fn receive(&self) -> (Protocol, std::net::SocketAddr) {
        let mut buf = [0u8; 65535];
        let (size, from) = self.socket.recv_from(&mut buf).expect("failed to receive");
        let msg = bincode::deserialize(&buf[..size]).expect("failed to deserialize");
        (msg, from)
    }

    pub fn try_receive(&self, timeout: Duration) -> Option<(Protocol, std::net::SocketAddr)> {
        self.socket.set_read_timeout(Some(timeout)).ok()?;
        let mut buf = [0u8; 65535];
        match self.socket.recv_from(&mut buf) {
            Ok((size, from)) => {
                let msg = bincode::deserialize(&buf[..size]).ok()?;
                Some((msg, from))
            }
            Err(_) => None,
        }
    }
}
