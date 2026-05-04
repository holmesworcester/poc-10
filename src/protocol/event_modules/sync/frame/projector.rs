//! Projector for sync frame events.
//!
//! Outbound sync frames queue exact bytes for the connection worker to wrap.
//! Inbound sync frames queue sync-owned work for the sync worker. Both branches
//! are row writes only; interpreting compare/have/need/data still happens in
//! the sync worker after projection.

use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use crate::protocol::event_modules::{connection, sync};

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let connection_id = codec::connection_id(bytes)?;
    let event_id = event_id(bytes);
    if codec::is_inbound_frame(bytes) {
        return Ok(ProjectionOutput::rows(vec![
            sync::schema::inbound_frame_row(
                connection_id,
                event_id,
                codec::raw_frame_bytes(bytes)?.to_vec(),
            ),
        ]));
    }
    Ok(ProjectionOutput::rows(vec![
        connection::schema::outbox_row(connection_id, event_id, bytes.to_vec()),
    ]))
}
