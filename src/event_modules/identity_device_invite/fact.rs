//! Device-invite fact shape for the poc-10 target tree.
//!
//! A device-invite fact is the shared authority a later endpoint-shared event
//! uses to bind one endpoint into one workspace under one user authority. The
//! invite public key is an Ed25519 verifying key; the matching private key
//! travels as out-of-band invite material and is not projected as shared
//! state.
//!
//! `user_invite_event_id` is optional: user-signed device invites carry the
//! user_invite dependency that originally admitted the signing user, while
//! endpoint_shared-signed device invites omit it.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInviteFact {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub user_authority_event_id: FactId,
    pub user_invite_event_id: Option<FactId>,
    pub public_key: Ed25519PublicKey,
}
