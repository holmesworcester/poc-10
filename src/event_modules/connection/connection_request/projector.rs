use super::super::connection_ack;
use super::super::connection_record::projector::{self as projection, Projection};
use super::super::connection_record::types;
use super::codec;
use crate::event_modules::connection::connection_ack::types::AckEvent;
use crate::event_modules::identity::endpoint::types::EndpointId;
use crate::store::StateChanges;

pub fn project(bytes: Vec<u8>, local_endpoint: EndpointId) -> Result<Projection, String> {
    let event = codec::decode(&bytes)?;
    if event.from_endpoint == local_endpoint {
        outbound(bytes)
    } else {
        inbound(bytes, local_endpoint, event.bootstrap_hash)
    }
}

pub fn outbound(bytes: Vec<u8>) -> Result<Projection, String> {
    codec::decode(&bytes)?;
    let request_id = types::event_id(&bytes);
    Ok(Projection {
        changes: StateChanges::rows(vec![projection::connection_event_row(request_id, bytes)]),
        emitted_events: Vec::new(),
        connection_id: None,
    })
}

pub fn inbound(
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    expected_bootstrap_hash: [u8; 32],
) -> Result<Projection, String> {
    let event = codec::decode(&bytes)?;
    if event.bootstrap_hash != expected_bootstrap_hash {
        return Err("bootstrap hash rejected".to_string());
    }

    let request_id = types::event_id(&bytes);
    let connection_id = types::connection_id(&request_id, &local_endpoint);
    let ack = AckEvent {
        from_endpoint: local_endpoint,
        to_endpoint: event.from_endpoint,
        request_id,
        connection_id,
    };
    let ack_bytes = connection_ack::codec::encode(&ack);

    Ok(Projection {
        changes: StateChanges::rows(vec![
            projection::connection_event_row(request_id, bytes),
            projection::connection_event_row(types::event_id(&ack_bytes), ack_bytes.clone()),
            projection::connection_row(connection_id, event.from_endpoint),
        ]),
        emitted_events: vec![ack_bytes],
        connection_id: Some(connection_id),
    })
}
