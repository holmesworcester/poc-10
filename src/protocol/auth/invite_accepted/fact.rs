//! Invite-accepted fact shape for the poc-10 target tree.
//!
//! Records that this endpoint accepted an invite link. The fact carries the
//! replayable bootstrap context from the link plus the local endpoint that
//! accepted it. Local-only fact.

use crate::core::facts::FactId;
use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
use std::net::SocketAddr;

pub type EndpointId = [u8; 32];
pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedFact {
    pub workspace_id: WorkspaceId,
    pub invite_fact_id: FactId,
    pub bootstrap_hash: FactId,
    pub bootstrap_secret: [u8; 32],
    pub accepted_endpoint_id: EndpointId,
    pub bootstrap_endpoint_id: EndpointId,
    pub bootstrap_addr: SocketAddr,
    pub user_authority_fact_id: Option<FactId>,
    pub endpoint_role: EndpointRole,
    pub identity_scope: bool,
}
