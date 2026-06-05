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
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

/// Staged read pipeline for the cascade_test_fact fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "sync::cascade_test_fact::Codec",
    authenticate: "sync::cascade_test_fact::authenticate::CascadeTestFactAuthenticator",
    adapt: "sync::cascade_test_fact::adapt::CascadeTestFactAdapter",
    project: "sync::cascade_test_fact::project::CascadeTestFactProjector",
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
        project_staged::<
            super::Codec,
            super::authenticate::CascadeTestFactAuthenticator,
            super::adapt::CascadeTestFactAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::CascadeTestFact> for CascadeTestFactProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        decoded: super::fact::CascadeTestFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 2. Context.
        let mut output = ProjectionOutput::new();
        for dependency_id in decoded.dependencies.iter() {
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
