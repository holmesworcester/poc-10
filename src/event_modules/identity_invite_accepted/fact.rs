//! Invite-accepted fact shape for the poc-10 target tree.
//!
//! Records that this endpoint accepted an invite link naming a workspace and a
//! shared `invite` event, together with the local scoped `invite_secret` event
//! id used by bootstrap and the bootstrap-hash binding. Local-only fact.

use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];
pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedFact {
    pub workspace_id: WorkspaceId,
    pub invite_event_id: FactId,
    pub invite_secret_event_id: FactId,
    pub bootstrap_hash: FactId,
    pub accepted_endpoint_id: EndpointId,
}
