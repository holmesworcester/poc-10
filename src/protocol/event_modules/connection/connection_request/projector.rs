use super::super::connection_record::projector as projection;
use super::super::connection_record::types;
use super::codec;
use crate::core::store::ProjectionOutput;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

pub fn project(bytes: Vec<u8>, local_endpoint: EndpointId) -> Result<ProjectionOutput, String> {
    let event = codec::decode(&bytes)?;
    if event.from_endpoint == local_endpoint {
        outbound(bytes)
    } else {
        inbound(bytes, local_endpoint, event.bootstrap_hash)
    }
}

pub fn outbound(bytes: Vec<u8>) -> Result<ProjectionOutput, String> {
    codec::decode(&bytes)?;
    let request_id = types::event_id(&bytes);
    Ok(ProjectionOutput::rows(vec![
        projection::connection_event_row(request_id, bytes),
    ]))
}

pub fn inbound(
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    expected_bootstrap_hash: [u8; 32],
) -> Result<ProjectionOutput, String> {
    let event = codec::decode(&bytes)?;
    if event.bootstrap_hash != expected_bootstrap_hash {
        return Err("bootstrap hash rejected".to_string());
    }

    let request_id = types::event_id(&bytes);
    let connection_id = types::connection_id(&request_id, &local_endpoint);

    Ok(ProjectionOutput::rows(vec![
        projection::connection_event_row(request_id, bytes),
        projection::connection_row(connection_id, event.from_endpoint),
    ]))
}
