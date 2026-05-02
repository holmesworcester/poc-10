use std::net::SocketAddr;

use crate::store::StateChanges;

use super::super::connection_record::types::ConnectionId;
use super::projector;

pub fn record(connection_id: ConnectionId, addr: SocketAddr) -> StateChanges {
    StateChanges::rows(projector::transport_target(connection_id, addr))
}
