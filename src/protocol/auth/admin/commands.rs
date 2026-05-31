//! Command constructors for admin grant facts.
//!
//! Admin grants are authority-changing identity facts. Command code must prove
//! the local endpoint belongs to the workspace, find the local user's existing
//! admin authority, and sign the new grant with local signing material. This
//! file owns that local orchestration; projection still validates the signed
//! grant when it is later submitted or received.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId};
use crate::protocol::auth;

use super::create;
use super::fact::AdminFact;
use super::rows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAdmin {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub user_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAdminReceipt {
    pub admin_id: FactId,
}

pub fn grant_admin(
    ctx: &CommandContext<'_>,
    input: GrantAdmin,
) -> Result<CommandOutput<GrantAdminReceipt>, String> {
    let membership = auth::workspace::queries::local_membership(ctx.store(), input.workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    let authority_admin_id = ctx
        .store()
        .table_rows_with_key_prefix(rows::ADMIN_ROWS, &input.workspace_id, usize::MAX)
        .map_err(|err| format!("load admin rows: {err}"))?
        .into_iter()
        .map(|(key, value)| rows::decode_admin_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|admin| admin.user_fact_id == membership.user_authority_fact_id)
        .map(|admin| admin.admin_id)
        .ok_or_else(|| "local user is not an admin in this workspace".to_string())?;
    let target = auth::user::queries::users_in_workspace(ctx.store(), input.workspace_id)?
        .into_iter()
        .find(|user| user.user_id == input.user_id)
        .ok_or_else(|| "target user is not in this workspace".to_string())?;
    let local_endpoint = auth::endpoint::create::local_endpoint(ctx.store())?
        .ok_or_else(|| "local endpoint has not been created".to_string())?;
    let grant = AdminFact {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key: target.public_key,
        authority_fact_id: authority_admin_id,
        user_fact_id: target.user_id,
        signer_id: authority_admin_id,
        signer_public_key: local_endpoint.signing_public_key,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let fact = create::signed_admin_fact(
        input.created_at_ms,
        authority_admin_id,
        local_endpoint.signing_secret,
        grant,
    )?;
    Ok(CommandOutput::new(GrantAdminReceipt { admin_id: fact.id }).with_facts(vec![fact]))
}

pub fn signed_admin_fact(
    created_at_ms: u64,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
    grant: AdminFact,
) -> Result<Fact, String> {
    create::signed_admin_fact(created_at_ms, signer_id, signer_private_key, grant)
}
