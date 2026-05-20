//! Poc-10 invite-secret projector.
//!
//! POLICY. An invite_secret fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and the invite-secret payload
//!      decodes with internally consistent hash/scope fields.
//!   2. CONTEXT. No remote context is accepted; this is local bootstrap secret
//!      material.
//!   3. MATERIALIZE. Write the invite_secret row and publish both identity and
//!      connection invite-secret context offers.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for InviteSecretProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        invite_secret: super::fact::InviteSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("invite_secret fact must have local scope".to_string());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(crate::protocol::matchers::invite_secret_offer(fact.id))
            .offer(crate::protocol::matchers::connection_invite_secret_offer(
                fact.id, fact.id,
            ))
            .intent(AtomicIntent::PutRow(invite_secret_row(&invite_secret)?).into_intent()))
    }
}
