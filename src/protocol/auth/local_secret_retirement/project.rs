//! Local secret-retirement projector.
//!
//! POLICY. A local_secret_retirement is admitted iff:
//!   1. STRUCTURAL. The fact is local-scoped and names a supported retirement
//!      reason plus target secret-source id.
//!   2. CONTEXT. Projection waits for the target `local_secret_source` context
//!      and validates it belongs to the same workspace.
//!   3. MATERIALIZE. Once validated, projection publishes exact retirement
//!      context for the target; the target secret projector owns self-purge.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth::{local_history_node_secret, local_key_secret};

use super::fact::LocalSecretRetirementFact;

#[derive(Debug, Clone, Default)]
pub struct LocalSecretRetirementProjector;

impl LocalSecretRetirementProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalSecretRetirementProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for LocalSecretRetirementProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        retirement: LocalSecretRetirementFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("local secret retirement fact must have local scope".to_string());
        }

        // 2. Context.
        let target_need = ContextNeed::range(
            fact.id,
            "local_secret_source",
            FactScope::Local,
            retirement.target_secret_id,
            retirement.target_secret_id,
        );
        let Some(target) = context.payload_for(&target_need) else {
            return Ok(ProjectionOutput::new().need(target_need));
        };
        validate_target_secret(target, &retirement)?;

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(target_need)
            .offer(super::secret_retired_offer(
                fact.id,
                retirement.target_secret_id,
            )))
    }
}

fn validate_target_secret(
    target: &Fact,
    retirement: &LocalSecretRetirementFact,
) -> Result<(), String> {
    if target.id != retirement.target_secret_id {
        return Err("local secret retirement target context payload id mismatch".to_string());
    }
    if target.scope != FactScope::Local {
        return Err("local secret retirement target context must be local".to_string());
    }
    if let Ok(secret) = local_key_secret::decode_fact_payload(target.body()) {
        if secret.workspace_id != retirement.workspace_id {
            return Err("local key secret retirement workspace mismatch".to_string());
        }
        return Ok(());
    }
    if let Ok(secret) = local_history_node_secret::decode_fact_payload(target.body()) {
        if secret.workspace_id != retirement.workspace_id {
            return Err("local history secret retirement workspace mismatch".to_string());
        }
        return Ok(());
    }
    Err("local secret retirement target context is not key material".to_string())
}
