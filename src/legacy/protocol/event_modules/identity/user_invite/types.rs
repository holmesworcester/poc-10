//! User-invite event types.
//!
//! `UserInviteEvent` is the signed shared fact. Its event id is the signed
//! envelope id, not the inner payload id, and rows are scoped by workspace.

use crate::core::crypto::Ed25519PublicKey;
use crate::legacy::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInviteEvent {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInviteRow {
    pub workspace_id: EventId,
    pub user_invite_id: EventId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub authority_event_id: EventId,
}
