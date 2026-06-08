//! Invite-accepted fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
use std::net::SocketAddr;

use super::encode;
use super::fact::InviteAcceptedFact;

pub fn accepted_fact(
    workspace_id: FactId,
    invite_fact_id: FactId,
    bootstrap_hash: FactId,
    bootstrap_secret: [u8; 32],
    accepted_endpoint_id: FactId,
    bootstrap_endpoint_id: FactId,
    bootstrap_addr: SocketAddr,
    user_authority_fact_id: Option<FactId>,
    endpoint_role: EndpointRole,
    identity_scope: bool,
    created_at_ms: u64,
) -> Result<(InviteAcceptedFact, Fact), String> {
    let accepted = InviteAcceptedFact {
        workspace_id,
        invite_fact_id,
        bootstrap_hash,
        bootstrap_secret,
        accepted_endpoint_id,
        bootstrap_endpoint_id,
        bootstrap_addr,
        user_authority_fact_id,
        endpoint_role,
        identity_scope,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&accepted)?,
    );
    Ok((accepted, fact))
}
