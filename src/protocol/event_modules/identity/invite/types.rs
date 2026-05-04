use std::net::SocketAddr;

use crate::core::store::EventId;

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
