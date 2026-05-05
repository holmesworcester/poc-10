//! Types for workspace-scoped admin grants.

use crate::core::crypto::Ed25519PublicKey;
use crate::protocol::event_modules::types::EventId;

use super::super::workspace::types::WorkspaceId;

pub type AdminId = EventId;
pub type UserId = EventId;
pub type AdminPublicKey = Ed25519PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminEvent {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub public_key: AdminPublicKey,
    pub authority_event_id: EventId,
    pub user_event_id: UserId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRow {
    pub workspace_id: WorkspaceId,
    pub admin_id: AdminId,
    pub created_at_ms: u64,
    pub public_key: AdminPublicKey,
    pub authority_event_id: EventId,
    pub user_event_id: UserId,
}
