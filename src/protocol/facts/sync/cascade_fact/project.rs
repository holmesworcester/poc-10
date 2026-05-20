//! Poc-10 sync cascade projector.
//!
//! POLICY. A cascade_fact is admitted iff:
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
use crate::protocol::matchers;

#[derive(Debug, Clone, Default)]
pub struct CascadeFactProjector;

impl CascadeFactProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for CascadeFactProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for CascadeFactProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: super::fact::CascadeFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if decoded.timestamp != fact.timestamp {
            return Err("cascade fact timestamp does not match fact timestamp".to_string());
        }

        // 2. Context.
        let mut output = ProjectionOutput::new();
        for dependency_id in decoded.dependencies {
            let need = matchers::exact_fact_need(fact.id, fact.scope.clone(), dependency_id);
            if !has_matched_dependency(context, &need, dependency_id)? {
                output = output.need(need);
            }
        }

        // 3. Materialize.
        if output.needs.is_empty() {
            output = output.offer(matchers::exact_fact_offer(
                fact.id,
                fact.scope.clone(),
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
