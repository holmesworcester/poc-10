use crate::core::store::ProjectionOutput;

use super::super::connection_request;
use super::super::tables as projection;
use super::super::types;
use super::codec;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

pub fn outbound(bytes: Vec<u8>, local_endpoint: EndpointId) -> Result<ProjectionOutput, String> {
    let event = codec::decode(&bytes)?;
    if event.from_endpoint != local_endpoint {
        return Err("connection ack was not created by this endpoint".to_string());
    }
    Ok(ProjectionOutput::rows(vec![
        projection::connection_event_row(types::event_id(&bytes), bytes),
    ]))
}

pub fn inbound(
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    request_bytes: Vec<u8>,
) -> Result<ProjectionOutput, String> {
    let event = codec::decode(&bytes)?;
    let request = connection_request::codec::decode(&request_bytes)
        .map_err(|_| "connection ack references a non-request event".to_string())?;
    if request.from_endpoint != local_endpoint {
        return Err("connection ack references another endpoint's request".to_string());
    }
    if event.request_id != types::event_id(&request_bytes) {
        return Err("connection ack references a different request".to_string());
    }
    if event.to_endpoint != local_endpoint {
        return Err("connection ack addressed to a different endpoint".to_string());
    }
    let expected_connection_id = types::connection_id(&event.request_id, &event.from_endpoint);
    if event.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }
    Ok(ProjectionOutput::rows(vec![
        projection::connection_event_row(types::event_id(&bytes), bytes),
        projection::connection_row(event.connection_id, event.from_endpoint),
    ]))
}
