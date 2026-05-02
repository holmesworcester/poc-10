use std::net::SocketAddr;

use crate::store::TableRow;

use super::super::connection_record::types::ConnectionId;
use super::codec;
use super::tables;

pub fn project(bytes: &[u8]) -> Result<Vec<TableRow>, String> {
    let event = codec::decode(bytes)?;
    Ok(transport_target(event.connection_id, event.addr))
}

pub fn transport_target(connection_id: ConnectionId, addr: SocketAddr) -> Vec<TableRow> {
    vec![TableRow {
        table: tables::TRANSPORT_TARGETS,
        key: connection_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }]
}
