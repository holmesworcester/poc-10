use std::net::SocketAddr;

use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::super::types::ConnectionId;
use super::codec;
use super::tables;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    Ok(ProjectionOutput::rows(transport_target(
        event.connection_id,
        event.addr,
    )))
}

pub fn transport_target(connection_id: ConnectionId, addr: SocketAddr) -> Vec<TableRow> {
    vec![TableRow {
        table: tables::TRANSPORT_TARGETS,
        key: connection_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }]
}
