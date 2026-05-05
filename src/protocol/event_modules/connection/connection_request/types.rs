//! Connection request event fields.
//!
//! The request names both endpoints, carries a nonce to keep ids unique, and
//! commits to an invite bootstrap secret by hash. The secret itself stays local
//! to the invite holder and the accepting endpoint.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestEvent {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub nonce: [u8; 32],
    pub bootstrap_hash: [u8; 32],
}
