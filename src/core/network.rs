//! Core-owned outbound network send boundary.
//!
//! Protocol code hands opaque frame bytes to this module. The current
//! implementation stages those bytes through the core network queues and TCP
//! pump, but that machinery is deliberately hidden from protocol handlers.

use std::time::Instant;

use crate::core::network_queues::OutboundNetworkRow;
pub use crate::core::network_queues::{NetworkTarget, SCHEMAS};
use crate::core::store::Store;
use crate::core::tcp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFrame {
    pub bytes: Vec<u8>,
    pub deadline: Option<Instant>,
    pub retry_key: Option<Vec<u8>>,
}

impl OutboundFrame {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            deadline: None,
            retry_key: None,
        }
    }
}

pub fn send(store: &Store, target: NetworkTarget, frame: OutboundFrame) -> Result<(), String> {
    let OutboundFrame {
        bytes,
        deadline: _,
        retry_key: _,
    } = frame;
    let row = OutboundNetworkRow::new(target, bytes);
    tcp::send_once(store, target, vec![row], (), |_, _| Ok(())).map(|_| ())
}
