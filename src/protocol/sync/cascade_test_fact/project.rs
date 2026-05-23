//! Poc-10 sync cascade projector.
//!
//! POLICY. A cascade_test_fact is admitted iff:
//!   1. STRUCTURAL. The body decodes and its timestamp matches the outer fact
//!      timestamp.
//!   2. CONTEXT. Every declared dependency must be present as an exact-fact
//!      matched payload in the same scope.
//!   3. MATERIALIZE. Once dependencies are ready, publish this fact as exact
//!      context for downstream sync work.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

#[derive(Debug, Clone, Default)]
pub struct CascadeTestFactProjector;

impl CascadeTestFactProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for CascadeTestFactProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for CascadeTestFactProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: super::fact::CascadeTestFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if decoded.timestamp != fact.timestamp {
            return Err("cascade fact timestamp does not match fact timestamp".to_string());
        }

        // 2. Context.
        let mut output = ProjectionOutput::new();
        for dependency_id in decoded.dependencies {
            let need = crate::core::context::ContextNeed::range(
                fact.id,
                "sync_exact_fact",
                fact.scope.clone(),
                dependency_id,
                dependency_id,
            );
            if !has_matched_dependency(context, &need, dependency_id)? {
                output = output.need(need);
            }
        }

        // 3. Materialize.
        if output.needs.is_empty() {
            output = output.offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                fact.scope.clone(),
                fact.id,
                fact.id,
            ));
        }
        Ok(output)
    }
}

fn has_matched_dependency(
    context: &ProjectionContext,
    need: &crate::core::context::ContextNeed,
    dependency_id: crate::core::facts::FactId,
) -> Result<bool, String> {
    let Some(payload) = context.payload_for_checked(need, "cascade dependency")? else {
        return Ok(false);
    };
    if payload.id != dependency_id {
        return Err("cascade dependency payload does not match need".to_string());
    }
    Ok(true)
}
