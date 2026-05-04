//! Transport-target value types.
//!
//! `TransportRoute` is the query shape consumed by the connection worker.
//! `TransportTargetEvent` is the local event shape admitted through the common
//! worker. Keeping both tiny makes the route boundary explicit.

use std::net::SocketAddr;

use super::super::types::ConnectionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportRoute {
    pub connection_id: ConnectionId,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTargetEvent {
    pub connection_id: ConnectionId,
    pub addr: SocketAddr,
}
