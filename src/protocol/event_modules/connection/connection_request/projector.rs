//! Projector for connection request events.
//!
//! The projector writes the request bytes for later validation. When the common
//! worker supplies receive metadata, the same projection also learns the
//! subjective local connection fact: "this endpoint received the request from
//! this route." That keeps route learning atomic with connection establishment
//! without turning socket addresses into separate semantic events.

use super::super::schema as projection;
use super::super::types;
use super::codec;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.record.receive;
    let event = codec::decode(&bytes)?;
    let request_id = types::event_id(&bytes);
    let mut rows = vec![projection::connection_event_row(request_id, bytes)];
    if let Some(receive) = receive {
        let connection_id = types::connection_id(&request_id, &receive.local_endpoint);
        rows.push(projection::connection_row(
            connection_id,
            event.from_endpoint,
        ));
        if receive.remember_route {
            rows.push(projection::transport_target_row(
                connection_id,
                receive.origin,
            ));
        }
    }

    Ok(ProjectionOutput::rows(rows))
}
