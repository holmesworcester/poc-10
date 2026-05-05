//! User event types.

use crate::core::crypto::Ed25519PublicKey;
use crate::protocol::event_modules::types::EventId;

pub const USERNAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEvent {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub workspace_id: EventId,
    pub user_id: EventId,
    pub user_invite_id: EventId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}
