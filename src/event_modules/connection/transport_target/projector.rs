use std::net::SocketAddr;

use crate::store::ModuleRow;

use super::super::connection_record::types::ConnectionId;
use super::tables;

pub fn transport_target(connection_id: ConnectionId, addr: SocketAddr) -> Vec<ModuleRow> {
    vec![ModuleRow {
        table: tables::TRANSPORT_TARGETS,
        key: connection_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }]
}
