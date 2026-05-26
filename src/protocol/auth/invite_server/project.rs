//! Poc-10 invite-server projector.
//!
//! POLICY. An invite_server grant is admitted iff:
//!   1. STRUCTURAL. The fact is global, signed, contains an invite_server
//!      payload, and all selector fields are non-zero.
//!   2. AUTHORITY. Bootstrap grants are signed directly by the workspace root;
//!      delegated grants are signed by an endpoint_shared fact whose user owns
//!      the named admin grant in the same workspace.
//!   3. MATERIALIZE. Once the authority path validates, write the invite_server
//!      row, publish exact/key offers, and mark the fact shareable.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth::invite_server::fact::InviteServerFact;
use crate::protocol::auth::{admin, endpoint_shared, workspace};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::rows::invite_server_row;

#[derive(Debug, Clone, Default)]
pub struct InviteServerProjector;

impl InviteServerProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteServerProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for InviteServerProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        invite_server: InviteServerFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("invite_server fact must have global scope".to_string());
        }
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_fact_id == [0; 32] {
            return Err("invite_server fact has empty authority_fact_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }
        super::layout::verify_signature(&invite_server)?;

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        if invite_server.authority_fact_id == invite_server.workspace_id {
            project_workspace_signed(fact, &invite_server, context)
        } else {
            project_endpoint_signed(fact, &invite_server, context)
        }
    }
}

fn project_workspace_signed(
    fact: &Fact,
    invite: &InviteServerFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceSignedNeeds::new(fact.id, invite);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if invite.signer_id != invite.workspace_id {
        return Err(
            "bootstrap invite_server must use workspace as signer and authority".to_string(),
        );
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("invite_server workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "invite_server authority is not a workspace fact".to_string())?;
    workspace::layout::verify_signature(&workspace)?;
    if workspace.public_key != invite.signer_public_key {
        return Err(
            "signed invite_server signer key does not match workspace public key".to_string(),
        );
    }
    let context_have = context_have_from_needs(context, [&needs.workspace]);

    // 3. Materialize.
    materialized_output(fact, invite, needs.output(), context_have)
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &InviteServerFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointAdminNeeds::new(fact.id, invite, invite.signer_id);
    let Some(endpoint_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };
    let Some(admin_fact) = context.payload_for(&needs.admin) else {
        return Ok(needs.output());
    };

    if endpoint_fact.id != invite.signer_id {
        return Err("invite_server signer endpoint context payload id mismatch".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(endpoint_fact.body())
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    endpoint_shared::layout::verify_signature(&endpoint)?;
    if endpoint.signing_public_key != invite.signer_public_key {
        return Err(
            "signed invite_server signer key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("invite_server signer endpoint belongs to a different workspace".to_string());
    }

    if admin_fact.id != invite.authority_fact_id {
        return Err("invite_server admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "invite_server authority must be an admin fact".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("invite_server signer user does not match admin authority user".to_string());
    }
    let context_have = context_have_from_needs(context, [&needs.endpoint_shared, &needs.admin]);

    // 3. Materialize.
    materialized_output(fact, invite, needs.output(), context_have)
}

struct WorkspaceSignedNeeds {
    workspace: ContextNeed,
}

impl WorkspaceSignedNeeds {
    fn new(owner: FactId, invite: &InviteServerFact) -> Self {
        Self {
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                invite.workspace_id,
                invite.workspace_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new().need(self.workspace.clone())
    }
}

struct EndpointAdminNeeds {
    endpoint_shared: ContextNeed,
    admin: ContextNeed,
}

impl EndpointAdminNeeds {
    fn new(owner: FactId, invite: &InviteServerFact, signer_id: FactId) -> Self {
        Self {
            endpoint_shared: crate::core::context::ContextNeed::range(
                owner,
                "auth_endpoint_shared",
                crate::core::facts::FactScope::Global,
                signer_id,
                signer_id,
            ),
            admin: crate::core::context::ContextNeed::range(
                owner,
                "auth_admin",
                crate::core::facts::FactScope::Global,
                invite.authority_fact_id,
                invite.authority_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.endpoint_shared.clone())
            .need(self.admin.clone())
    }
}

fn materialized_output(
    fact: &Fact,
    invite: &InviteServerFact,
    output: ProjectionOutput,
    context_have: Vec<FactId>,
) -> Result<ProjectionOutput, String> {
    Ok(share_fact_with_sync(
        output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_invite_server",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_invite_server_key",
                crate::protocol::auth::workspace::scope(invite.workspace_id),
                invite.public_key.to_vec(),
                invite.public_key,
            ))
            .row_mutation(RowMutation::PutRow(invite_server_row(fact.id, invite)?)),
        invite.workspace_id,
        fact,
        context_have,
    ))
}

fn decode_admin_payload(
    fact: &Fact,
) -> Result<crate::protocol::auth::admin::fact::AdminFact, String> {
    let admin = admin::decode_fact_payload(fact.body())?;
    admin::layout::verify_signature(&admin)?;
    Ok(admin)
}
