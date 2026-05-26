//! Projector for sync shared-fact offers.
//!
//! POLICY. A sync shared_fact is admitted iff:
//!   1. STRUCTURAL. The body decodes and the outer fact scope matches its
//!      workspace id.
//!   2. CONTEXT. No incoming context is required; this fact advertises a shared
//!      payload id that is already present.
//!   3. MATERIALIZE. Publish an exact-fact offer for range-request dependency
//!      matching.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use std::collections::BTreeSet;

use crate::protocol::sync::share_fact_with_sync as share_sync;

#[derive(Debug, Clone, Default)]
pub struct SyncSharedFactProjector;

impl SyncSharedFactProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncSharedFactProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for SyncSharedFactProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        shared: super::fact::SharedFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(shared.workspace_id);
        require_fact_scope(fact, &scope)?;
        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                scope,
                shared.fact_id,
                shared.fact_id,
            )),
        )
    }
}

pub fn share_fact_with_sync(
    output: ProjectionOutput,
    workspace_id: FactId,
    fact: &Fact,
    context_have: Vec<FactId>,
) -> ProjectionOutput {
    output.intent(share_sync::share_fact_with_sync_intent_for_fact(
        workspace_id,
        fact.id,
        fact.timestamp,
        context_have,
    ))
}

pub fn retract_fact_from_sync(
    output: ProjectionOutput,
    workspace_id: FactId,
    fact_id: FactId,
    timestamp_ms: u64,
) -> ProjectionOutput {
    output.intent(share_sync::retract_fact_from_sync_intent(
        workspace_id,
        fact_id,
        timestamp_ms,
    ))
}

pub fn context_have_from_needs<'a>(
    context: &ProjectionContext,
    needs: impl IntoIterator<Item = &'a ContextNeed>,
) -> Vec<FactId> {
    let mut ids = BTreeSet::new();
    for need in needs {
        for (_offer, payload) in context.matched_payloads_for(need) {
            ids.insert(payload.id);
        }
    }
    ids.into_iter().collect()
}

pub fn context_have_from_optional_needs<'a>(
    context: &ProjectionContext,
    needs: impl IntoIterator<Item = Option<&'a ContextNeed>>,
) -> Vec<FactId> {
    context_have_from_needs(context, needs.into_iter().flatten())
}

fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}
