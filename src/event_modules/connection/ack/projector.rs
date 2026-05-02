use crate::store::EventId;

use super::super::shared::projection::{self, Projection};
use super::super::shared::types::{self, EndpointId};
use super::codec;

pub fn inbound(
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    expected_request_id: EventId,
) -> Result<Projection, String> {
    let event = codec::decode(&bytes)?;
    if event.to_endpoint != local_endpoint {
        return Err("connection ack addressed to a different endpoint".to_string());
    }
    if event.request_id != expected_request_id {
        return Err("connection ack references a different request".to_string());
    }
    let expected_connection_id = types::connection_id(&event.request_id, &event.from_endpoint);
    if event.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }
    Ok(Projection {
        rows: vec![
            projection::connection_event_row(types::event_id(&bytes), bytes),
            projection::connection_row(event.connection_id, event.from_endpoint),
        ],
        response: None,
        connection_id: Some(event.connection_id),
    })
}
