//! Poc-10 user projector.
//!
//! Validates the user fact payload and emits a single `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional): this validates the user-invite key context
//! and records the matched invite id, but it still does not unwrap or verify
//! the legacy signed envelope. This will be tightened once signed-fact
//! integration lands.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;

use super::layout;
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
        if fact.scope != FactScope::Global {
            return Err("user fact must have global scope".to_string());
        }
        let user = layout::decode_fact(&fact.bytes)?;
        if user.workspace_id == [0; 32] {
            return Err("user workspace_id must not be empty".to_string());
        }
        if user.public_key == [0; 32] {
            return Err("user public_key must not be empty".to_string());
        }
        if user.username.trim().is_empty() {
            return Err("username must not be empty".to_string());
        }
        let invite_need = identity_matchers::scoped_key_need(
            fact.id,
            identity_matchers::user_invite_key_role(),
            user.workspace_id,
            user.public_key.to_vec(),
        );
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(ProjectionOutput::new().need(invite_need));
        };
        let invite = user_invite_layout::decode_fact(&invite_fact.bytes)
            .map_err(|_| "user signer context must be a user_invite fact".to_string())?;
        if invite.workspace_id != user.workspace_id {
            return Err("user_invite belongs to a different workspace".to_string());
        }
        if invite.public_key != user.public_key {
            return Err("user public_key does not match user_invite public_key".to_string());
        }
        let user_invite_id = invite_fact.id;
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::exact_offer(
                fact.id,
                identity_matchers::user_role(),
            ))
            .intent(AtomicIntent::PutRow(user_row(fact.id, user_invite_id, &user)?).into_intent()))
    }
}
