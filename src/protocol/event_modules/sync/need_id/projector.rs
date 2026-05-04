//! Projector for sync need-id events.
//!
//! A local need-id is sent to the peer like any other connection-scoped event.
//! A received need-id becomes sync work; the sync worker answers it by queuing
//! the requested durable event id, not by manufacturing a data packet.

use crate::protocol::event_modules::sync::types::SyncDirection;
use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::ProjectionOutput;
use crate::protocol::event_modules::{connection, sync};

use super::codec;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    let id = event_id(bytes);
    match event.direction {
        SyncDirection::Outbound => Ok(ProjectionOutput::rows(vec![
            connection::schema::connection_scoped_event_row(id, bytes.to_vec()),
            connection::schema::outbox_row(event.connection_id, id),
        ])),
        SyncDirection::Inbound => Ok(ProjectionOutput::rows(vec![
            sync::schema::inbound_event_row(event.connection_id, id, bytes.to_vec()),
        ])),
    }
}
