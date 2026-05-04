//! Projector for connection ack events.
//!
//! Acks are connection facts, not transport effects. Locally-created acks only
//! record their bytes. Received acks carry receive metadata from the worker; in
//! that case projection records the established connection and the route we just
//! observed in the same row output.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::schema as projection;
use super::super::types;
use super::codec;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.record.receive;
    let event = codec::decode(&bytes)?;
    let expected_connection_id = types::connection_id(&event.request_id, &event.from_endpoint);
    if event.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }

    let mut rows = vec![projection::connection_event_row(
        types::event_id(&bytes),
        bytes,
    )];
    if let Some(receive) = receive {
        if event.to_endpoint != receive.local_endpoint {
            return Err("connection ack addressed to a different endpoint".to_string());
        }
        rows.push(projection::connection_row(
            event.connection_id,
            event.from_endpoint,
        ));
        if receive.remember_route {
            rows.push(projection::transport_target_row(
                event.connection_id,
                receive.origin,
            ));
        }
    }
    Ok(ProjectionOutput::rows(rows))
}
