//! Connection CLI summaries.
//!
//! Command execution lives in `protocol::cli`; this file only owns the shape of
//! connection-domain output. Keeping formatting data near the domain prevents
//! the top-level CLI from accumulating knowledge about which counters matter.

use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectSummary {
    pub addr: SocketAddr,
    pub established_routes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamSummary {
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeSummary {
    pub accepted_connections: usize,
    pub received_events: usize,
}

impl ServeSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("accepted_connections: {}", self.accepted_connections),
            format!("received_events: {}", self.received_events),
        ]
    }
}
