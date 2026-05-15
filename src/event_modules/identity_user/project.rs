//! Poc-10 user projector.
//!
//! Validates the user fact payload and emits a single `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional, see commit message): the legacy projector
//! also required a signed envelope wrapping the payload and a user-invite
//! dependency naming the signer key. The signed envelope and `user_invite`
//! modules have not yet been ported into the target tree, so the target
//! projector accepts the raw fact and synthesises a zero user-invite id in the
//! row. This will be tightened once `user_invite` lands.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let user = layout::decode_fact(&fact.bytes)?;
        if user.username.trim().is_empty() {
            return Err("username must not be empty".to_string());
        }
        let user_invite_id = [0u8; 32];
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(user_row(fact.id, user_invite_id, &user)?).into_intent()))
    }
}
