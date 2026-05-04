//! Invite value types.
//!
//! `Invite` is the parsed link used by commands. `InviteSecretEvent` is the
//! local event projected into authorization state. Keeping them separate makes
//! it clear which fields travel in a link and which fields enter the store.

use std::net::SocketAddr;

use crate::protocol::event_modules::types::EventId;

use super::super::endpoint::types::EndpointId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub endpoint: EndpointId,
    pub bootstrap_secret: [u8; 32],
    pub addr: SocketAddr,
    pub invite_event_id: EventId,
    pub workspace_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSecretEvent {
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_secret: [u8; 32],
}
