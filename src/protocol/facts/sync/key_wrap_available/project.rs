//! Projector for sync key-wrap availability offers.
//!
//! POLICY. A sync key_wrap_available fact is admitted iff:
//!   1. STRUCTURAL. The body decodes and the outer fact scope matches its
//!      workspace id.
//!   2. CONTEXT. No incoming context is required; the fact advertises that the
//!      named key wrap is available locally.
//!   3. MATERIALIZE. Publish exact-fact and key-wrap offers for range-request
//!      dependency matching.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::facts::sync::encrypted_root::project::require_fact_scope;
use crate::protocol::matchers;

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncKeyWrapAvailableProjector;

impl SyncKeyWrapAvailableProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncKeyWrapAvailableProjector {
    fn project(
        &self,
        fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let key = layout::decode_fact(fact.body())?;
        let scope = matchers::workspace_scope(key.workspace_id);
        require_fact_scope(fact, &scope)?;
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(matchers::exact_fact_offer(
                fact.id,
                scope.clone(),
                key.key_wrap_id,
                fact.id,
            ))
            .offer(matchers::key_wrap_offer(fact.id, scope, key.key_wrap_id)))
    }
}
