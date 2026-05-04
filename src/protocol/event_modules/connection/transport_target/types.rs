use std::net::SocketAddr;

use super::super::connection_record::types::ConnectionId;

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
