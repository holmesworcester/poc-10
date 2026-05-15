//! Poc-10 invite-server projector.
//!
//! Validates the invite-server fact payload and emits a single `PutRow` atomic
//! intent.
//!
//! Legacy parity gap (intentional, see commit message): the legacy projector
//! unwraps a `signed` envelope and checks the signer is either the bootstrap
//! workspace event (where authority must equal the workspace id) or an admin-
//! authorised endpoint-shared event for the same workspace. The
//! `identity_signed`, `identity_workspace_admin`, and `identity_endpoint_shared`
//! materials needed to enforce those rules have not been ported into the target
//! tree, so the target projector accepts the raw fact and trusts its declared
//! authority. This will be tightened once the sibling identity modules land.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let invite_server = layout::decode_fact(&fact.bytes)?;
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_event_id == [0; 32] {
            return Err("invite_server fact has empty authority_event_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(invite_server_row(fact.id, &invite_server)?).into_intent()))
    }
}
