//! Poc-10 invite-accepted projector.
//!
//! Validates that no event id field in the fact is zero and emits a single
//! `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional): this validates the invite-secret context
//! that the target tree can request exactly, but it still does not perform any
//! broader legacy transit/bootstrap side effects.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_invite::layout as invite_layout;
use crate::event_modules::identity_matchers;

use super::layout;
use super::rows::invite_accepted_row;

#[derive(Debug, Clone, Default)]
pub struct InviteAcceptedProjector;

impl InviteAcceptedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteAcceptedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("invite_accepted fact must have local scope".to_string());
        }
        let accepted = layout::decode_fact(&fact.bytes)?;
        if accepted.workspace_id == [0; 32]
            || accepted.invite_event_id == [0; 32]
            || accepted.invite_secret_event_id == [0; 32]
            || accepted.bootstrap_hash == [0; 32]
            || accepted.accepted_endpoint_id == [0; 32]
        {
            return Err("invite_accepted fact has empty event id field".to_string());
        }

        let secret_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::invite_secret_role(),
            accepted.invite_secret_event_id,
        );
        let Some(secret_fact) = context.payload_for(&secret_need) else {
            return Ok(ProjectionOutput::new().need(secret_need));
        };
        if secret_fact.id != accepted.invite_secret_event_id {
            return Err("invite_accepted invite_secret context payload id mismatch".to_string());
        }
        let secret = invite_layout::decode_fact(&secret_fact.bytes)
            .map_err(|_| "invite_accepted dependency is not an invite_secret fact".to_string())?;
        if secret.bootstrap_hash != accepted.bootstrap_hash {
            return Err("invite_accepted bootstrap hash does not match invite_secret".to_string());
        }
        if secret.workspace_id != Some(accepted.workspace_id)
            || secret.invite_event_id != Some(accepted.invite_event_id)
        {
            return Err(
                "invite_accepted invite_secret scope does not match acceptance".to_string(),
            );
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(invite_accepted_row(fact.id, &accepted)?).into_intent()))
    }
}
