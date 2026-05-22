//! Poc-10 user-invite projector.
//!
//! POLICY. A user_invite is admitted iff:
//!   1. STRUCTURAL. The fact is global, signed, contains a user_invite payload,
//!      and all selector fields are non-zero.
//!   2. AUTHORITY. Bootstrap invites are signed directly by the workspace root;
//!      delegated invites are signed by an endpoint_shared fact whose user owns
//!      the named admin grant in the same workspace.
//!   3. MATERIALIZE. Once the authority path validates, write the user_invite
//!      row, publish exact/key offers, and mark the fact shareable.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::context_keys;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user_invite::fact::UserInviteFact;
use crate::protocol::facts::identity::{admin, endpoint_shared, workspace};
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::user_invite_row;

#[derive(Debug, Clone, Default)]
pub struct UserInviteProjector;

impl UserInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for UserInviteProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: identity::signed_fact::SignedPayload<UserInviteFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user_invite fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let user_invite = signed.payload;
        if user_invite.workspace_id == [0; 32] {
            return Err("user_invite fact has empty workspace_id".to_string());
        }
        if user_invite.authority_fact_id == [0; 32] {
            return Err("user_invite fact has empty authority_fact_id".to_string());
        }
        if user_invite.public_key == [0; 32] {
            return Err("user_invite fact has empty public_key".to_string());
        }

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        if user_invite.authority_fact_id == user_invite.workspace_id {
            project_workspace_signed(fact, &user_invite, &envelope, context)
        } else {
            project_endpoint_signed(fact, &user_invite, &envelope, context)
        }
    }
}

fn project_workspace_signed(
    fact: &Fact,
    invite: &UserInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceSignedNeeds::new(fact.id, invite);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if envelope.signer_id != invite.workspace_id {
        return Err("bootstrap user_invite must use workspace as signer and authority".to_string());
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("user_invite workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "user_invite authority is not a workspace fact".to_string())?;
    if workspace.public_key != envelope.signer_public_key {
        return Err(
            "signed user_invite signer key does not match workspace public key".to_string(),
        );
    }
    identity::signed_fact::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &UserInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointAdminNeeds::new(fact.id, invite, envelope.signer_id);
    let Some(endpoint_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };
    let Some(admin_fact) = context.payload_for(&needs.admin) else {
        return Ok(needs.output());
    };

    if endpoint_fact.id != envelope.signer_id {
        return Err("user_invite signer endpoint context payload id mismatch".to_string());
    }
    let endpoint_envelope = identity::signed_fact::decode_envelope(endpoint_fact.body())
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err("user_invite signer must be workspace or endpoint_shared".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(&endpoint_envelope.payload)
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != envelope.signer_public_key {
        return Err(
            "signed user_invite signer key does not match endpoint_shared signing key".to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("user_invite signer endpoint belongs to a different workspace".to_string());
    }

    if admin_fact.id != invite.authority_fact_id {
        return Err("user_invite admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "user_invite authority must be an admin event".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("user_invite admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("user_invite signer user does not match admin authority user".to_string());
    }
    identity::signed_fact::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

struct WorkspaceSignedNeeds {
    workspace: ContextNeed,
}

impl WorkspaceSignedNeeds {
    fn new(owner: FactId, invite: &UserInviteFact) -> Self {
        Self {
            workspace: context_keys::exact_need(
                owner,
                context_keys::workspace_role(),
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
    fn new(owner: FactId, invite: &UserInviteFact, signer_id: FactId) -> Self {
        Self {
            endpoint_shared: context_keys::exact_need(
                owner,
                context_keys::endpoint_shared_role(),
                signer_id,
            ),
            admin: context_keys::exact_need(
                owner,
                context_keys::admin_role(),
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
    invite: &UserInviteFact,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    Ok(output
        .offer(context_keys::user_invite_offer(fact.id))
        .offer(context_keys::user_invite_key_offer(
            fact.id,
            invite.workspace_id,
            invite.public_key,
        ))
        .row_mutation(RowMutation::PutRow(user_invite_row(fact.id, invite)?))
        .intent(share_fact_with_workspace_intent_for_fact(
            invite.workspace_id,
            fact,
        )))
}

fn decode_admin_payload(
    fact: &Fact,
) -> Result<crate::protocol::facts::identity::admin::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(admin::TYPE_ADMIN) => admin::decode_fact_payload(fact.body()),
        Some(identity::signed_fact::TYPE_SIGNED_FACT) => {
            let envelope = identity::signed_fact::decode_envelope(fact.body())?;
            if envelope.inner_type != admin::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            admin::decode_fact_payload(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}
