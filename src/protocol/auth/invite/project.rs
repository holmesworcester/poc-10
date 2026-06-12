//! Poc-10 invite-secret projector.
//!
//! POLICY. An invite_secret fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and the invite-secret payload
//!      decodes with internally consistent hash/scope fields.
//!   2. CONTEXT. No remote context is accepted; this is local bootstrap secret
//!      material.
//!   3. MATERIALIZE. Write the invite_secret row and publish both auth and
//!      connection invite-secret context offers.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

use super::invite_secret_row;

/// Projector route metadata for the invite fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("auth::invite::project::InviteSecretProjector");

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
        let decoded = super::decode::decode_fact(fact.body())?;
        let authenticated = super::authenticate::authenticate(fact, decoded, context)?;
        let semantic = super::adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl InviteSecretProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        invite_secret: super::fact::InviteSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("invite_secret fact must have local scope".to_string());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_invite_secret",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_invite_secret",
                crate::core::facts::FactScope::Local,
                fact.id,
                fact.id,
            ))
            .row_mutation(RowMutation::PutRow(invite_secret_row(&invite_secret)?)))
    }
}
