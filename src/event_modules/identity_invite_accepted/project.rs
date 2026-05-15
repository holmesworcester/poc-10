//! Poc-10 invite-accepted projector.
//!
//! Validates that no event id field in the fact is zero and emits a single
//! `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional, see commit message): the legacy projector
//! also resolves the `invite_secret` dependency to confirm that its workspace,
//! invite-event id, and bootstrap hash match the acceptance. The
//! `identity_invite_secret` module has not been ported to the target tree yet,
//! so we skip the cross-event verification here and trust the local fact body.
//! This will be tightened once the sibling module lands.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

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
        _context: &ProjectionContext,
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
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(invite_accepted_row(fact.id, &accepted)?).into_intent(),
        ))
    }
}
