//! Connection domain.
//!
//! Connection events establish the semantic relationship between two endpoints.
//! They are distinct from transport targets, which are merely addresses where
//! bytes might be sent right now. The domain owns request/ack event syntax,
//! route facts, transit wrapping helpers, and the connection worker that bridges
//! opaque network frames to canonical event bytes.

pub mod cli;
pub mod connection_ack;
pub mod connection_request;
pub mod queries;
pub mod schema;
pub mod transit;
pub mod transport_target;
pub mod types;
pub mod worker;

use crate::core::store::Store;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn is_projection_record(bytes: &[u8]) -> bool {
    connection_request::codec::is_request(bytes)
        || connection_ack::codec::is_ack(bytes)
        || bytes.first() == Some(&transport_target::codec::TYPE_TRANSPORT_TARGET)
}

pub fn project_record(
    store: &Store,
    bytes: &[u8],
    local_endpoint: EndpointId,
) -> Result<ProjectionOutput, String> {
    if connection_request::codec::is_request(bytes) {
        return connection_request::projector::project(bytes.to_vec(), local_endpoint);
    }
    if connection_ack::codec::is_ack(bytes) {
        let event = connection_ack::codec::decode(bytes)?;
        if event.from_endpoint == local_endpoint {
            return connection_ack::projector::outbound(bytes.to_vec(), local_endpoint);
        }
        let request_bytes = queries::event_bytes(store, &event.request_id)?
            .ok_or_else(|| "connection ack references unknown request".to_string())?;
        return connection_ack::projector::inbound(bytes.to_vec(), local_endpoint, request_bytes);
    }
    if bytes.first() == Some(&transport_target::codec::TYPE_TRANSPORT_TARGET) {
        return transport_target::projector::project(bytes);
    }
    Err("not a connection projection record".to_string())
}
