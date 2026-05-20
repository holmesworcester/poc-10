//! Poc-10 admin grant projector.
//!
//! POLICY. An admin grant is admitted iff:
//!   1. STRUCTURAL. The fact is global, signed, contains an admin payload, and
//!      all selector fields are non-zero.
//!   2. AUTHORITY. Bootstrap grants are signed by the workspace root and grant
//!      that same root user; delegated grants are signed by the named admin
//!      authority and target a user in the same workspace.
//!   3. MATERIALIZE. Once the authority path validates, write the admin row,
//!      publish exact/key offers, and mark the fact shareable with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::admin::fact::AdminFact;
use crate::protocol::facts::identity::user;
use crate::protocol::facts::identity::workspace;
use crate::protocol::facts::identity::workspace::fact::WorkspaceFact;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::layout;
use super::rows::admin_row;

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for AdminProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: identity::signed_fact::SignedPayload<AdminFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("admin fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let admin = signed.payload;
        if admin.workspace_id == [0u8; 32] {
            return Err("admin workspace_id must not be zero".to_string());
        }
        if admin.public_key == [0u8; 32] {
            return Err("admin public_key must not be zero".to_string());
        }
        if admin.authority_fact_id == [0u8; 32] {
            return Err("admin authority_fact_id must not be zero".to_string());
        }
        if admin.user_fact_id == [0u8; 32] {
            return Err("admin user_fact_id must not be zero".to_string());
        }

        // 2. Authority.
        //
        // The workspace id is the bootstrap discriminator: if the admin's
        // authority is the workspace itself, the workspace root key must sign a
        // root admin for that same workspace. Otherwise the signer must be the
        // named admin authority, and the target user must match the grant.
        if admin.authority_fact_id == admin.workspace_id {
            project_bootstrap_admin(fact, &admin, &envelope, context)
        } else {
            project_delegated_admin(fact, &admin, &envelope, context)
        }
    }
}

fn project_bootstrap_admin(
    fact: &Fact,
    admin: &AdminFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = BootstrapAdminNeeds::new(fact.id, admin);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let workspace = decode_workspace_context(workspace_fact, admin.workspace_id)?;

    if envelope.signer_id != admin.workspace_id {
        return Err("bootstrap admin must use workspace as signer and authority".to_string());
    }
    if admin.user_fact_id != admin.workspace_id {
        return Err("workspace admin authority can only bootstrap root admin".to_string());
    }
    if envelope.signer_public_key != workspace.public_key {
        return Err(
            "signed bootstrap admin signer key does not match workspace public key".to_string(),
        );
    }
    if admin.public_key != workspace.public_key {
        return Err("admin public_key does not match root workspace public_key".to_string());
    }
    identity::signed_fact::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, admin, needs.output())
}

fn project_delegated_admin(
    fact: &Fact,
    admin: &AdminFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = DelegatedAdminNeeds::new(fact.id, admin);
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

    if envelope.signer_id != admin.authority_fact_id {
        return Err("signed admin grant signer must be the authority admin".to_string());
    }

    if authority_fact.id != admin.authority_fact_id {
        return Err("admin authority context payload id mismatch".to_string());
    }
    let authority = decode_admin_payload(authority_fact)
        .map_err(|_| "signed admin authority must be an admin event".to_string())?;
    if authority.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }
    if envelope.signer_public_key != authority.public_key {
        return Err("signed admin signer key does not match authority admin".to_string());
    }

    if user_fact.id != admin.user_fact_id {
        return Err("admin user context payload id mismatch".to_string());
    }
    let user = decode_user_payload(user_fact)
        .map_err(|_| "admin user dependency must be a user event".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("admin user belongs to a different workspace".to_string());
    }
    if user.public_key != admin.public_key {
        return Err("admin public_key does not match user public_key".to_string());
    }
    identity::signed_fact::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, admin, needs.output())
}

struct BootstrapAdminNeeds {
    workspace: ContextNeed,
}

impl BootstrapAdminNeeds {
    fn new(owner: FactId, admin: &AdminFact) -> Self {
        Self {
            workspace: matchers::exact_need(owner, matchers::workspace_role(), admin.workspace_id),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new().need(self.workspace.clone())
    }
}

struct DelegatedAdminNeeds {
    workspace: ContextNeed,
    authority: ContextNeed,
    user: ContextNeed,
}

impl DelegatedAdminNeeds {
    fn new(owner: FactId, admin: &AdminFact) -> Self {
        Self {
            workspace: matchers::exact_need(owner, matchers::workspace_role(), admin.workspace_id),
            authority: matchers::exact_need(owner, matchers::admin_role(), admin.authority_fact_id),
            user: matchers::exact_need(owner, matchers::user_role(), admin.user_fact_id),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
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
    workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "admin workspace dependency must be a workspace fact".to_string())
}

fn materialized_output(
    fact: &Fact,
    admin: &AdminFact,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    Ok(output
        .offer(matchers::exact_offer(fact.id, matchers::admin_role()))
        .offer(matchers::scoped_key_offer(
            fact.id,
            matchers::admin_role(),
            admin.workspace_id,
            admin.user_fact_id.to_vec(),
        ))
        .intent(AtomicIntent::PutRow(admin_row(fact.id, admin)?).into_intent())
        .intent(share_fact_with_workspace_intent_for_fact(
            admin.workspace_id,
            fact,
        )))
}

fn decode_admin_payload(fact: &Fact) -> Result<super::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(layout::TYPE_ADMIN) => super::decode_fact_payload(fact.body()),
        Some(identity::signed_fact::TYPE_SIGNED_FACT) => {
            let envelope = identity::signed_fact::decode_envelope(fact.body())?;
            if envelope.inner_type != layout::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            super::decode_fact_payload(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}

fn decode_user_payload(
    fact: &Fact,
) -> Result<crate::protocol::facts::identity::user::fact::UserFact, String> {
    match fact.bytes.first().copied() {
        Some(user::TYPE_USER) => user::decode_fact_payload(fact.body()),
        Some(identity::signed_fact::TYPE_SIGNED_FACT) => {
            let envelope = identity::signed_fact::decode_envelope(fact.body())?;
            if envelope.inner_type != user::TYPE_USER {
                return Err("expected signed user".to_string());
            }
            user::decode_fact_payload(&envelope.payload)
        }
        _ => Err("expected user".to_string()),
    }
}
