//! Device-invite event types.
//!
//! A signed device invite is the shared authority a later endpoint-shared event
//! uses to bind one endpoint into one workspace under one user authority. The
//! invite public key is an Ed25519 verifying key; the matching private key
//! travels as out-of-band invite material and is not projected as shared state.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::legacy::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteEvent {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
    pub user_invite_event_id: Option<EventId>,
    pub public_key: Ed25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteRow {
    pub workspace_id: EventId,
    pub device_invite_id: EventId,
    pub created_at_ms: u64,
    pub user_authority_event_id: EventId,
    pub user_invite_event_id: Option<EventId>,
    pub public_key: Ed25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteKeypair {
    pub public_key: Ed25519PublicKey,
    pub private_key: Ed25519PrivateKey,
}
