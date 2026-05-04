//! Projector for sync compare events.
//!
//! Connection-scoped compare events are projected according to their admission
//! scope. Locally proposed compare events are cached and queued for the connection;
//! received compare events become sync work rows. The comparison itself is
//! stateful worker work, not projection work.

use crate::protocol::event_modules::types::{ConnectionScope, EventScope};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};
use crate::protocol::event_modules::{connection, sync};

use super::codec;

pub fn project(envelope: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = &envelope.record.canonical_bytes;
    let compare = codec::decode(bytes)?;
    match envelope.record.scope {
        EventScope::Connection(ConnectionScope::Outgoing { connection_id }) => {
            ensure_connection(compare.connection_id, connection_id)?;
            Ok(ProjectionOutput::rows(vec![
                connection::schema::connection_scoped_event_row(
                    envelope.context.event_id,
                    bytes.to_vec(),
                ),
                connection::schema::outbox_row(connection_id, envelope.context.event_id),
            ]))
        }
        EventScope::Connection(ConnectionScope::Incoming { connection_id }) => {
            ensure_connection(compare.connection_id, connection_id)?;
            Ok(ProjectionOutput::rows(vec![
                sync::schema::inbound_event_row(
                    connection_id,
                    envelope.context.event_id,
                    bytes.to_vec(),
                ),
            ]))
        }
        _ => Err("sync compare requires connection scope".to_string()),
    }
}

fn ensure_connection(actual: [u8; 32], scoped: [u8; 32]) -> Result<(), String> {
    if actual == scoped {
        Ok(())
    } else {
        Err("sync compare connection scope mismatch".to_string())
    }
}
