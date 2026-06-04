//! Local key secret projector.
//!
//! POLICY. A local key secret is admitted iff it is local-scoped and ties to its
//! removal frontier. Projection publishes frontier-root wrap-source and
//! secret-coverage offers while live, and self-purges when retirement context
//! for this secret arrives.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::auth::key_wrap::project::{
    frontier_root_wrap_source_offers, require_local_scope,
};
use crate::protocol::auth::local_history_node_secret::project::secret_offer;
use crate::protocol::auth::local_secret_retirement;
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
        project_authenticated::<super::authenticate::LocalKeySecretAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::LocalKeySecretAuthenticator>
    for LocalKeySecretProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, LocalKeySecretFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, secret) = authenticated.into_parts();
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
    // 2. Context: retirement and removal-frontier match.
    let retirement_need = local_secret_retirement::secret_retired_need(fact.id, fact.id);
    if let Some(retirement_fact) = projection_context.payload_for(&retirement_need) {
        validate_local_key_retirement(retirement_fact, fact.id, &secret)?;
        return Ok(ProjectionOutput::new().purge_self(fact.id));
    }

    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        secret.frontier_id,
        secret.frontier_id,
    );
    let Some(frontier_fact) = projection_context.payload_for(&frontier_need) else {
        return Ok(ProjectionOutput::new()
            .need(frontier_need)
            .need(retirement_need));
    };
    validate_local_key_frontier(frontier_fact, &secret)?;

    // 3. Materialize: publish wrap-source and coverage offers.
    let mut output = ProjectionOutput::new()
        .need(frontier_need)
        .need(retirement_need);
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

fn validate_local_key_retirement(
    retirement_fact: &Fact,
    target_id: crate::core::facts::FactId,
    secret: &LocalKeySecretFact,
) -> Result<(), String> {
    if retirement_fact.scope != FactScope::Local {
        return Err("local key secret retirement context must be local".to_string());
    }
    let retirement = local_secret_retirement::decode_fact_payload(retirement_fact.body())
        .map_err(|_| "local key secret retirement context is not a retirement fact".to_string())?;
    if retirement.workspace_id != secret.workspace_id {
        return Err("local key secret retirement workspace mismatch".to_string());
    }
    if retirement.target_secret_id != target_id {
        return Err("local key secret retirement target mismatch".to_string());
    }
    Ok(())
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
