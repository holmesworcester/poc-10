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
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
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
        project_authenticated::<super::authenticate::InviteSecretAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::InviteSecretAuthenticator>
    for InviteSecretProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::InviteSecretFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, invite_secret) = authenticated.into_parts();
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
