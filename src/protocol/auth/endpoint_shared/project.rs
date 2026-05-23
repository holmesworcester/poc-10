//! Poc-10 endpoint-shared projector.
//!
//! POLICY. An endpoint_shared fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains endpoint_shared,
//!      and endpoint/workspace/signing fields are valid.
//!   2. AUTHORITY. Device endpoints require device_invite context; invite-server
//!      endpoints require invite_server context. The signer key, workspace, and
//!      user authority must match that grant.
//!   3. MATERIALIZE. Write the endpoint_shared row, publish signer/exact
//!      context, and share the fact with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth;
use crate::protocol::auth::device_invite;
use crate::protocol::auth::invite_server;
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::fact::EndpointRole;
use super::rows::endpoint_shared_row;

#[derive(Debug, Clone, Default)]
pub struct EndpointSharedProjector;

impl EndpointSharedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointSharedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for EndpointSharedProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: auth::signed_fact::SignedPayload<super::fact::EndpointSharedFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("endpoint shared fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let event = signed.payload;
        if event.endpoint_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared endpoint_id cannot be empty".to_string());
        }
        if event.signing_public_key.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared signing_public_key cannot be empty".to_string());
        }
        if event.workspace_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared workspace_id cannot be empty".to_string());
        }
        if event.device_name.as_bytes().contains(&0) {
            return Err("endpoint device name cannot contain NUL".to_string());
        }

        // 2. Authority.
        let authority_need = authority_need(fact, &event, envelope.signer_id);
        if !has_valid_authority(&authority_need, &event, &envelope, context)? {
            return Ok(ProjectionOutput::new().need(authority_need));
        }
        auth::signed_fact::verify_envelope(&envelope)?;

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(authority_need)
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "content_signer",
                crate::protocol::auth::workspace::scope(event.workspace_id),
                event.endpoint_id,
                event.endpoint_id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_endpoint_shared",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .row_mutation(RowMutation::PutRow(endpoint_shared_row(fact.id, &event)?))
            .intent(share_fact_with_workspace_intent_for_fact(
                event.workspace_id,
                fact,
            )))
    }
}

fn authority_need(
    fact: &Fact,
    event: &super::fact::EndpointSharedFact,
    signer_id: [u8; 32],
) -> ContextNeed {
    match event.endpoint_role {
        EndpointRole::InviteServer => crate::core::context::ContextNeed::range(
            fact.id,
            "auth_invite_server",
            crate::core::facts::FactScope::Global,
            signer_id,
            signer_id,
        ),
        EndpointRole::Device => crate::core::context::ContextNeed::range(
            fact.id,
            "auth_device_invite",
            crate::core::facts::FactScope::Global,
            signer_id,
            signer_id,
        ),
    }
}

fn has_valid_authority(
    need: &ContextNeed,
    event: &super::fact::EndpointSharedFact,
    envelope: &auth::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<bool, String> {
    let Some(authority_fact) = context.payload_for(need) else {
        return Ok(false);
    };
    if authority_fact.id != envelope.signer_id {
        return Err("endpoint_shared authority context payload id mismatch".to_string());
    }
    if authority_fact.scope != FactScope::Global {
        return Err("endpoint_shared authority must have global scope".to_string());
    }
    if event.endpoint_role == EndpointRole::Device {
        let invite_envelope =
            auth::signed_fact::decode_envelope(authority_fact.body()).map_err(|_| {
                "endpoint_shared dependency is not a signed endpoint invite".to_string()
            })?;
        if invite_envelope.inner_type != device_invite::TYPE_DEVICE_INVITE {
            return Err("endpoint_shared dependency is not a signed endpoint invite".to_string());
        }
        let invite =
            device_invite::decode_fact_payload(&invite_envelope.payload).map_err(|_| {
                "endpoint_shared dependency is not a signed endpoint invite".to_string()
            })?;
        if invite.public_key != envelope.signer_public_key {
            return Err(
                "endpoint_shared signer public key does not match device_invite".to_string(),
            );
        }
        if invite.workspace_id != event.workspace_id {
            return Err("endpoint_shared workspace does not match device_invite".to_string());
        }
        if invite.user_authority_fact_id != event.user_authority_fact_id {
            return Err("endpoint_shared user authority does not match device_invite".to_string());
        }
        return Ok(true);
    }

    let invite_envelope = auth::signed_fact::decode_envelope(authority_fact.body())
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite_envelope.inner_type != invite_server::TYPE_INVITE_SERVER {
        return Err("endpoint_shared dependency is not a signed endpoint invite".to_string());
    }
    let invite_server = invite_server::decode_fact_payload(&invite_envelope.payload)
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite_server.workspace_id != event.workspace_id {
        return Err("endpoint_shared workspace does not match invite_server".to_string());
    }
    if invite_server.public_key != envelope.signer_public_key {
        return Err("endpoint_shared signer public key does not match invite_server".to_string());
    }
    if envelope.signer_id != event.user_authority_fact_id {
        return Err("endpoint_shared user authority does not match invite_server".to_string());
    }
    Ok(true)
}
