//! Projector for connection ack events.
//!
//! Acks are connection facts, not transport effects. Locally-created acks only
//! record their bytes. Received acks carry receive metadata from the worker; in
//! that case projection records the established connection and the route we just
//! observed in the same row output.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::connection_request;
use super::super::schema as projection;
use super::super::types;
use super::codec;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.record.receive;
    let ack = codec::decode(&bytes)?;
    let expected_connection_id = types::connection_id(&ack.request_id, &ack.from_endpoint);
    if ack.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }
    let request = event
        .context
        .dependency(&ack.request_id)
        .ok_or_else(|| "connection ack missing request dependency".to_string())?;
    let request = connection_request::codec::decode(&request.canonical_bytes)
        .map_err(|_| "connection ack references a non-request event".to_string())?;
    if request.from_endpoint != ack.to_endpoint {
        return Err("connection ack references another endpoint's request".to_string());
    }

    let mut rows = vec![projection::connection_event_row(
        types::event_id(&bytes),
        bytes,
    )];
    if let Some(receive) = receive {
        if ack.to_endpoint != receive.local_endpoint {
            return Err("connection ack addressed to a different endpoint".to_string());
        }
        rows.push(projection::connection_row(
            ack.connection_id,
            ack.from_endpoint,
        ));
        if receive.remember_route {
            rows.push(projection::transport_target_row(
                ack.connection_id,
                receive.origin,
            ));
        }
    }
    Ok(ProjectionOutput::rows(rows))
}
