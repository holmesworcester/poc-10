//! Local key secret projector.
//!
//! POLICY. A local key secret is admitted iff it is local-scoped and ties to its
//! removal frontier. Projection publishes frontier-root wrap-source and
//! secret-coverage offers.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth::key_wrap::project::{
    frontier_root_wrap_source_offers, require_local_scope,
};
use crate::protocol::auth::local_history_node_secret::project::secret_offer;
use crate::protocol::auth::removal_frontier;

use super::fact::LocalKeySecretFact;

#[derive(Debug, Clone, Default)]
pub struct LocalKeySecretProjector;

impl LocalKeySecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalKeySecretProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for LocalKeySecretProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        secret: LocalKeySecretFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_local_key_secret(fact, context, secret)
    }
}

fn project_local_key_secret(
    fact: &Fact,
    projection_context: &ProjectionContext,
    secret: LocalKeySecretFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(secret.workspace_id);
    require_local_scope(fact)?;
    // 2. Context: removal-frontier match.
    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        secret.frontier_id,
        secret.frontier_id,
    );
    let Some(frontier_fact) = projection_context.payload_for(&frontier_need) else {
        return Ok(ProjectionOutput::new().need(frontier_need));
    };
    validate_local_key_frontier(frontier_fact, &secret)?;

    // 3. Materialize: publish wrap-source and coverage offers.
    let mut output = ProjectionOutput::new().need(frontier_need);
    for offer in frontier_root_wrap_source_offers(
        fact.id,
        scope.clone(),
        secret.workspace_id,
        secret.frontier_id,
        secret.owner_endpoint_id,
        secret.created_at_ms,
    ) {
        output = output.offer(offer);
    }
    Ok(output
        .offer(ContextOffer::range(
            fact.id,
            "local_secret_source",
            FactScope::Local,
            fact.id,
            fact.id,
        ))
        .offer(secret_offer(
            fact.id,
            scope,
            secret.workspace_id,
            secret.frontier_id,
            0,
            u64::MAX,
            0,
            [0; 32],
        )))
}

fn validate_local_key_frontier(
    frontier_fact: &Fact,
    secret: &LocalKeySecretFact,
) -> Result<(), String> {
    if frontier_fact.id != secret.frontier_id {
        return Err("local key secret frontier context payload id mismatch".to_string());
    }
    let frontier = removal_frontier::decode_fact_payload(&frontier_fact.bytes)
        .map_err(|_| "local key secret frontier context must be a removal frontier".to_string())?;
    if frontier.workspace_id != secret.workspace_id {
        return Err("local key secret frontier workspace mismatch".to_string());
    }
    if frontier.owner_endpoint_id != secret.owner_endpoint_id {
        return Err("local key secret frontier owner mismatch".to_string());
    }
    Ok(())
}
