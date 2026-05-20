//! Poc-10 user projector.
//!
//! POLICY. A user fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains a user payload,
//!      and the workspace/public key/name fields are non-empty.
//!   2. AUTHORITY. Matched user_invite context must match the signer id,
//!      signer public key, and workspace.
//!   3. MATERIALIZE. Write the user row, publish user context, and share the
//!      fact with the workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user_invite;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::user_row;

#[derive(Debug, Clone, Default)]
pub struct UserProjector;

impl UserProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for UserProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: identity::signed_fact::SignedPayload<super::fact::UserFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let user = signed.payload;
        if user.workspace_id == [0; 32] {
            return Err("user workspace_id must not be empty".to_string());
        }
        if user.public_key == [0; 32] {
            return Err("user public_key must not be empty".to_string());
        }
        if user.username.trim().is_empty() {
            return Err("username must not be empty".to_string());
        }

        // 2. Authority.
        let invite_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_invite_role(),
            envelope.signer_id,
        );
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(ProjectionOutput::new().need(invite_need));
        };
        identity::signed_fact::verify_envelope(&envelope)?;
        if invite_fact.id != envelope.signer_id {
            return Err("user signer context payload id mismatch".to_string());
        }
        let invite_envelope = identity::signed_fact::decode_envelope(invite_fact.body())
            .map_err(|_| "user signer context must be a signed user_invite fact".to_string())?;
        if invite_envelope.inner_type != user_invite::TYPE_USER_INVITE {
            return Err("user signer context must be a signed user_invite fact".to_string());
        }
        let invite = user_invite::decode_fact_payload(&invite_envelope.payload)
            .map_err(|_| "user signer context must be a user_invite fact".to_string())?;
        if invite.workspace_id != user.workspace_id {
            return Err("user workspace does not match user_invite workspace".to_string());
        }
        if invite.public_key != envelope.signer_public_key {
            return Err("signed user signer key does not match user_invite public key".to_string());
        }
        let user_invite_id = invite_fact.id;

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(invite_need)
            .offer(crate::protocol::matchers::exact_offer(
                fact.id,
                crate::protocol::matchers::user_role(),
            ))
            .intent(AtomicIntent::PutRow(user_row(fact.id, user_invite_id, &user)?).into_intent())
            .intent(share_fact_with_workspace_intent_for_fact(
                user.workspace_id,
                fact,
            )))
    }
}
