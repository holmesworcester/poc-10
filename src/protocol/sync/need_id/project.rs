//! Poc-10 sync need-id projector.
//!
//! POLICY. A sync_need_id fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes.
//!   2. CONTEXT. No matched context is required; idempotent handler work decides
//!      whether this store can answer.
//!   3. MATERIALIZE. Write the need-id row and emit deferred send-requested-fact
//!      work.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::sync::send_requested_fact::{send_requested_fact_intent, SendRequestedFact};

use super::rows::sync_need_id_row;

#[derive(Debug, Clone, Default)]
pub struct SyncNeedIdProjector;

impl SyncNeedIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncNeedIdProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::SyncNeedIdAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::SyncNeedIdAuthenticator> for SyncNeedIdProjector {
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::SyncNeedIdFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, need) = authenticated.into_parts();
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_need_id_row(fact.id, &need)?))
            .intent(send_requested_fact_intent(SendRequestedFact {
                need_fact_id: fact.id,
            })))
    }
}
