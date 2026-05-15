//! Connection-response fact shape for the poc-10 target tree.
//!
//! A response is the connection fact: its id is the connection id, and its
//! body carries the connection secret used to derive short-lived transit keys.
//! The response also copies the request's dependency edges so receive-side
//! validation does not need to walk transitive dependency context.

use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];
pub type EventId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionResponseFact {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: EventId,
    pub invite_secret_event_id: EventId,
    pub initiator_ephemeral_secret_event_id: EventId,
    pub responder_ephemeral_secret_event_id: EventId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}
