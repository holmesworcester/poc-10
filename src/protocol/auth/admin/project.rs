//! Poc-10 admin grant projector.
//!
//! POLICY. An admin grant is admitted iff:
//!   1. STRUCTURAL. The fact is global, signed, contains an admin payload, and
//!      all selector fields are non-zero.
//!   2. AUTHORITY. Bootstrap grants require signature evidence from the workspace root and target
//!      a real user who joined through a workspace-signed bootstrap invite;
//!      delegated grants require signature evidence from the named admin authority and target a
//!      user in the same workspace.
//!   3. MATERIALIZE. Once the authority path validates, write the admin row,
//!      publish exact/key offers, and mark the fact shareable with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::auth::admin::fact::AdminFact;
use crate::protocol::auth::signature;
use crate::protocol::auth::user;
use crate::protocol::auth::user_invite;
use crate::protocol::auth::workspace;
use crate::protocol::auth::workspace::fact::WorkspaceFact;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::admin_row;

/// Staged read pipeline for the admin-grant fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::admin::Codec",
    authenticate: "auth::admin::authenticate::AdminAuthenticator",
    adapt: "auth::admin::adapt::AdminAdapter",
    project: "auth::admin::project::AdminProjector",
};

#[derive(Debug, Clone, Default)]
pub struct AdminProjector;

impl AdminProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for AdminProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::AdminAuthenticator,
            super::adapt::AdminAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<AdminFact> for AdminProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        admin: AdminFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes, the signer
        // signature, and non-zero selector fields. Scope is interpretation.
        // 1. Scope.
        if fact.scope != FactScope::Global {
            return Err("admin fact must have global scope".to_string());
        }

        // 2. Authority.
        //
        // The workspace id is the bootstrap discriminator: if the admin's
        // authority is the workspace itself, the workspace root key may grant
        // admin to a real user from the workspace-signed bootstrap invite.
        // Otherwise the signer must be the named admin authority, and the
        // target user must match the grant.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(admin.workspace_id),
            fact.id,
            admin.signer_public_key,
        )?;
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            admin.workspace_id,
            fact.id,
            admin.signer_public_key,
            "admin",
        )? {
            return Ok(ProjectionOutput::new().need(signature_need));
        }

        if admin.authority_fact_id == admin.workspace_id {
            project_bootstrap_admin(fact, &admin, context, signature_need)
        } else {
            project_delegated_admin(fact, &admin, context, signature_need)
        }
    }
}

fn project_bootstrap_admin(
    fact: &Fact,
    admin: &AdminFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = BootstrapAdminNeeds::new(fact.id, admin, signature_need);
    let Some(workspace_fact) = context.payload_for_checked(&needs.workspace, "admin workspace")?
    else {
        return Ok(needs.output());
    };
    let workspace = decode_workspace_context(workspace_fact, admin.workspace_id)?;
    let Some(user_fact) = context.payload_for_checked(&needs.user, "bootstrap admin user")? else {
        return Ok(needs.output());
    };
    let user = decode_user_context(user_fact, admin)?;
    let user_invite_need = auth_user_invite_need(fact.id, user.signer_id);
    let Some(user_invite_fact) =
        context.payload_for_checked(&user_invite_need, "bootstrap admin user_invite")?
    else {
        return Ok(needs.output().need(user_invite_need));
    };
    let invite = decode_user_invite_context(user_invite_fact, &user, admin.workspace_id)?;

    if admin.signer_id != admin.workspace_id {
        return Err("bootstrap admin must use workspace as signer and authority".to_string());
    }
    if admin.signer_public_key != workspace.public_key {
        return Err(
            "signed bootstrap admin signer key does not match workspace public key".to_string(),
        );
    }
    if invite.authority_fact_id != admin.workspace_id || invite.signer_id != admin.workspace_id {
        return Err(
            "bootstrap admin target user must come from workspace bootstrap invite".to_string(),
        );
    }
    // Redundant with a correctly projected workspace-signed auth_user_invite,
    // but repeated here to make the bootstrap-admin rule self-contained.
    if invite.signer_public_key != workspace.public_key {
        return Err(
            "bootstrap user_invite signer key does not match workspace public key".to_string(),
        );
    }
    let context_have = context_have_from_needs(
        context,
        [
            &needs.signature,
            &needs.workspace,
            &needs.user,
            &user_invite_need,
        ],
    );

    // 3. Materialize.
    materialized_output(
        fact,
        admin,
        needs.output().need(user_invite_need),
        context_have,
    )
}

fn project_delegated_admin(
    fact: &Fact,
    admin: &AdminFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = DelegatedAdminNeeds::new(fact.id, admin, signature_need);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(authority_fact) = context.payload_for(&needs.authority) else {
        return Ok(needs.output());
    };
    let Some(user_fact) = context.payload_for(&needs.user) else {
        return Ok(needs.output());
    };
    decode_workspace_context(workspace_fact, admin.workspace_id)?;

    if admin.signer_id != admin.authority_fact_id {
        return Err("signed admin grant signer must be the authority admin".to_string());
    }

    if authority_fact.id != admin.authority_fact_id {
        return Err("admin authority context payload id mismatch".to_string());
    }
    let authority = decode_admin_payload(authority_fact)
        .map_err(|_| "signed admin authority must be an admin fact".to_string())?;
    if authority.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }
    if admin.signer_public_key != authority.public_key {
        return Err("signed admin signer key does not match authority admin".to_string());
    }

    if user_fact.id != admin.user_fact_id {
        return Err("admin user context payload id mismatch".to_string());
    }
    let user = decode_user_payload(user_fact)
        .map_err(|_| "admin user dependency must be a user fact".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("admin user belongs to a different workspace".to_string());
    }
    if user.public_key != admin.public_key {
        return Err("admin public_key does not match user public_key".to_string());
    }
    let context_have = context_have_from_needs(
        context,
        [
            &needs.signature,
            &needs.workspace,
            &needs.authority,
            &needs.user,
        ],
    );

    // 3. Materialize.
    materialized_output(fact, admin, needs.output(), context_have)
}

struct BootstrapAdminNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
    user: ContextNeed,
}

impl BootstrapAdminNeeds {
    fn new(owner: FactId, admin: &AdminFact, signature: ContextNeed) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                admin.workspace_id,
                admin.workspace_id,
            ),
            user: crate::core::context::ContextNeed::range(
                owner,
                "auth_user",
                crate::core::facts::FactScope::Global,
                admin.user_fact_id,
                admin.user_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
            .need(self.user.clone())
    }
}

struct DelegatedAdminNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
    authority: ContextNeed,
    user: ContextNeed,
}

impl DelegatedAdminNeeds {
    fn new(owner: FactId, admin: &AdminFact, signature: ContextNeed) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                admin.workspace_id,
                admin.workspace_id,
            ),
            authority: crate::core::context::ContextNeed::range(
                owner,
                "auth_admin",
                crate::core::facts::FactScope::Global,
                admin.authority_fact_id,
                admin.authority_fact_id,
            ),
            user: crate::core::context::ContextNeed::range(
                owner,
                "auth_user",
                crate::core::facts::FactScope::Global,
                admin.user_fact_id,
                admin.user_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
            .need(self.authority.clone())
            .need(self.user.clone())
    }
}

fn decode_workspace_context(
    workspace_fact: &Fact,
    workspace_id: FactId,
) -> Result<WorkspaceFact, String> {
    if workspace_fact.id != workspace_id {
        return Err("admin workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "admin workspace dependency must be a workspace fact".to_string())?;
    Ok(workspace)
}

fn materialized_output(
    fact: &Fact,
    admin: &AdminFact,
    output: ProjectionOutput,
    context_have: Vec<FactId>,
) -> Result<ProjectionOutput, String> {
    Ok(share_fact_with_sync(
        output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_admin",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_admin",
                crate::protocol::auth::workspace::scope(admin.workspace_id),
                admin.user_fact_id,
                admin.user_fact_id,
            ))
            .row_mutation(RowMutation::PutRow(admin_row(fact.id, admin)?)),
        admin.workspace_id,
        fact,
        context_have,
    ))
}

fn decode_admin_payload(fact: &Fact) -> Result<super::fact::AdminFact, String> {
    let admin = super::decode_fact_payload(fact.body())?;
    Ok(admin)
}

fn decode_user_payload(fact: &Fact) -> Result<crate::protocol::auth::user::fact::UserFact, String> {
    let user = user::decode_fact_payload(fact.body())?;
    Ok(user)
}

fn auth_user_invite_need(owner: FactId, invite_id: FactId) -> ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        "auth_user_invite",
        crate::core::facts::FactScope::Global,
        invite_id,
        invite_id,
    )
}

fn decode_user_context(
    user_fact: &Fact,
    admin: &AdminFact,
) -> Result<crate::protocol::auth::user::fact::UserFact, String> {
    if user_fact.id != admin.user_fact_id {
        return Err("bootstrap admin user context payload id mismatch".to_string());
    }
    let user = decode_user_payload(user_fact)
        .map_err(|_| "bootstrap admin user dependency must be a user fact".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("bootstrap admin user belongs to a different workspace".to_string());
    }
    // Mostly implied by auth_user projection, which already validated the user
    // against its invite. Keep the cheap defensive check at the admin boundary.
    if user.public_key != admin.public_key {
        return Err("bootstrap admin public_key does not match user public_key".to_string());
    }
    Ok(user)
}

fn decode_user_invite_context(
    user_invite_fact: &Fact,
    user: &crate::protocol::auth::user::fact::UserFact,
    workspace_id: FactId,
) -> Result<crate::protocol::auth::user_invite::fact::UserInviteFact, String> {
    if user_invite_fact.id != user.signer_id {
        return Err("bootstrap admin user_invite context payload id mismatch".to_string());
    }
    let invite = user_invite::decode_fact_payload(user_invite_fact.body())
        .map_err(|_| "bootstrap admin user signer must be a user_invite fact".to_string())?;
    if invite.workspace_id != workspace_id {
        return Err("bootstrap admin user_invite belongs to a different workspace".to_string());
    }
    // Mostly implied by auth_user projection because this invite id is the
    // user's signer_id; repeated here to keep the boundary explicit.
    if invite.public_key != user.signer_public_key {
        return Err("bootstrap admin user_invite key does not match user".to_string());
    }
    Ok(invite)
}
