//! Poc-10 user-invite projector.
//!
//! Validates the user-invite fact payload and emits a single `PutRow` atomic
//! intent.
//!
//! Legacy parity gap (intentional, see commit message): the legacy projector
//! unwraps a `signed` envelope and checks the signer is either the bootstrap
//! workspace event (authority must equal workspace id) or an admin-authorised
//! endpoint-shared event for the same workspace. The signed-envelope,
//! workspace admin, and endpoint_shared modules have not been ported into the
//! target tree, so the target projector accepts the raw fact and trusts its
//! declared authority. The legacy `SendBootstrapRequest` intent emitted by the
//! invite triplet is also deferred; the bootstrap intent will be wired when
//! transit handlers land. This will be tightened once the sibling identity
//! modules and signed-fact integration land.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let user_invite = layout::decode_fact(&fact.bytes)?;
        if user_invite.workspace_id == [0; 32] {
            return Err("user_invite fact has empty workspace_id".to_string());
        }
        if user_invite.authority_event_id == [0; 32] {
            return Err("user_invite fact has empty authority_event_id".to_string());
        }
        if user_invite.public_key == [0; 32] {
            return Err("user_invite fact has empty public_key".to_string());
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(user_invite_row(fact.id, &user_invite)?).into_intent()))
    }
}
