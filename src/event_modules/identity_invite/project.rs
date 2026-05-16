//! Poc-10 invite-secret projector.
//!
//! Validates the invite-secret fact (hash matches secret, scope fields are
//! both present or both absent) and emits a single `PutRow` atomic intent
//! keyed by the bootstrap hash.
//!
//! Legacy parity gap (intentional, see commit message): the legacy invite
//! triplet also emitted a `SendBootstrapRequest` transit intent that consumed
//! the optional dial `SocketAddr` carried in the invite link. The target tree
//! omits the addr field and the bootstrap intent: the transit handlers and
//! signed-fact wiring needed to send a bootstrap request have not been ported
//! yet. This will be tightened once `transit` handlers and the
//! `SendBootstrapRequest` intent are real.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;

use super::layout;
use super::rows::invite_secret_row;

#[derive(Debug, Clone, Default)]
pub struct InviteSecretProjector;

impl InviteSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("invite_secret fact must have local scope".to_string());
        }
        let invite_secret = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::invite_secret_offer(fact.id))
            .intent(AtomicIntent::PutRow(invite_secret_row(&invite_secret)?).into_intent()))
    }
}
