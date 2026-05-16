//! Poc-10 endpoint-shared projector.
//!
//! Decodes a shared endpoint identity fact, requires the matching authority
//! context currently expressible by target matchers, then emits a `PutRow`
//! intent into `identity_endpoint_shared_rows` keyed by
//! `workspace_id || endpoint_shared_id` (the endpoint shared id is the fact id).
//!
//! Invite-server endpoints can name their invite-server authority directly in
//! `user_authority_event_id`, so this projector waits for that exact context
//! and validates its workspace before materializing. Device endpoints still
//! need the signed envelope signer id/public key to identify and validate the
//! authorizing device invite; the raw target fact does not carry that context,
//! so the device path is blocked rather than projected from guessed authority.
//!
//! The legacy `identity.endpoint_memberships` index row is still deferred until
//! target membership facts/rows have their own validated context surface.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_invite_server::layout as invite_server_layout;
use crate::event_modules::identity_matchers;

use super::fact::EndpointRole;
use super::layout;
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
        if fact.scope != FactScope::Global {
            return Err("endpoint shared fact must have global scope".to_string());
        }
        let event = layout::decode_fact(&fact.bytes)?;
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
        if let Some(need) = authority_need(fact, &event, context)? {
            return Ok(ProjectionOutput::new().need(need));
        }
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::exact_offer(
                fact.id,
                identity_matchers::endpoint_shared_role(),
            ))
            .intent(AtomicIntent::PutRow(endpoint_shared_row(fact.id, &event)?).into_intent()))
    }
}

fn authority_need(
    fact: &Fact,
    event: &super::fact::EndpointSharedFact,
    context: &ProjectionContext,
) -> Result<Option<ContextNeed>, String> {
    match event.endpoint_role {
        EndpointRole::InviteServer => invite_server_authority_need(fact, event, context),
        EndpointRole::Device => {
            Err("endpoint_shared device authority requires signed envelope context".to_string())
        }
    }
}

fn invite_server_authority_need(
    fact: &Fact,
    event: &super::fact::EndpointSharedFact,
    context: &ProjectionContext,
) -> Result<Option<ContextNeed>, String> {
    let need = identity_matchers::exact_need(
        fact.id,
        identity_matchers::invite_server_role(),
        event.user_authority_event_id,
    );
    let Some(invite_server_fact) = context.payload_for(&need) else {
        return Ok(Some(need));
    };
    if invite_server_fact.id != event.user_authority_event_id {
        return Err("endpoint_shared invite_server context payload id mismatch".to_string());
    }
    if invite_server_fact.scope != FactScope::Global {
        return Err("endpoint_shared invite_server authority must have global scope".to_string());
    }
    let invite_server = invite_server_layout::decode_fact(&invite_server_fact.bytes)
        .map_err(|_| "endpoint_shared authority must be an invite_server fact".to_string())?;
    if invite_server.workspace_id != event.workspace_id {
        return Err("endpoint_shared workspace does not match invite_server".to_string());
    }
    if invite_server.public_key != event.signing_public_key {
        return Err("endpoint_shared signer public key does not match invite_server".to_string());
    }
    if invite_server.public_key == [0; 32] {
        return Err("endpoint_shared invite_server authority has empty public_key".to_string());
    }
    Ok(None)
}
