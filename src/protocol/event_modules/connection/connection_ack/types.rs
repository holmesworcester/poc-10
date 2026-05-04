//! Connection ack event fields.
//!
//! The ack is the accepting endpoint's commitment to a specific request and
//! derived connection id. Both peers can recompute the id, so a mismatched ack
//! is rejected before any connection row is projected.

use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckEvent {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: EventId,
    pub connection_id: ConnectionId,
}
