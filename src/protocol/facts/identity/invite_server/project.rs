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
use crate::core::intents::AtomicIntent;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::invite_server::fact::InviteServerFact;
use crate::protocol::facts::identity::{admin, endpoint_shared, workspace};
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

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
        signed: identity::signed_fact::SignedPayload<InviteServerFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("invite_server fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let invite_server = signed.payload;
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_fact_id == [0; 32] {
            return Err("invite_server fact has empty authority_fact_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        if invite_server.authority_fact_id == invite_server.workspace_id {
            project_workspace_signed(fact, &invite_server, &envelope, context)
        } else {
            project_endpoint_signed(fact, &invite_server, &envelope, context)
        }
    }
}

fn project_workspace_signed(
    fact: &Fact,
    invite: &InviteServerFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceSignedNeeds::new(fact.id, invite);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if envelope.signer_id != invite.workspace_id {
        return Err(
            "bootstrap invite_server must use workspace as signer and authority".to_string(),
        );
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("invite_server workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "invite_server authority is not a workspace fact".to_string())?;
    if workspace.public_key != envelope.signer_public_key {
        return Err(
            "signed invite_server signer key does not match workspace public key".to_string(),
        );
    }
    identity::signed_fact::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &InviteServerFact,
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
        return Err("invite_server signer endpoint context payload id mismatch".to_string());
    }
    let endpoint_envelope = identity::signed_fact::decode_envelope(endpoint_fact.body())
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err("invite_server signer must be workspace or endpoint_shared".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(&endpoint_envelope.payload)
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != envelope.signer_public_key {
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
        .map_err(|_| "invite_server authority must be an admin event".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("invite_server signer user does not match admin authority user".to_string());
    }
    identity::signed_fact::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

struct WorkspaceSignedNeeds {
    workspace: ContextNeed,
}

impl WorkspaceSignedNeeds {
    fn new(owner: FactId, invite: &InviteServerFact) -> Self {
        Self {
            workspace: matchers::exact_need(owner, matchers::workspace_role(), invite.workspace_id),
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
            endpoint_shared: matchers::exact_need(
                owner,
                matchers::endpoint_shared_role(),
                signer_id,
            ),
            admin: matchers::exact_need(owner, matchers::admin_role(), invite.authority_fact_id),
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
) -> Result<ProjectionOutput, String> {
    Ok(output
        .offer(matchers::invite_server_offer(fact.id))
        .offer(matchers::invite_server_key_offer(
            fact.id,
            invite.workspace_id,
            invite.public_key,
        ))
        .intent(AtomicIntent::PutRow(invite_server_row(fact.id, invite)?).into_intent())
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
