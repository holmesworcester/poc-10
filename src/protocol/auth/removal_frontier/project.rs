//! Removal frontier projector.
//!
//! POLICY. A removal frontier is admitted iff its scope matches the workspace
//! and its owner endpoint is proven by either an endpoint_shared signer offer or
//! a local signer secret. Projection publishes frontier context and shares the
//! fact with the workspace.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth;
use crate::protocol::auth::key_wrap::project::require_fact_scope;
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::fact::RemovalFrontierFact;

#[derive(Debug, Clone, Default)]
pub struct RemovalFrontierProjector;

impl RemovalFrontierProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RemovalFrontierProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for RemovalFrontierProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        frontier: RemovalFrontierFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        removal_frontier(fact, context, frontier)
    }
}

fn removal_frontier(
    fact: &Fact,
    context: &ProjectionContext,
    frontier: RemovalFrontierFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;
    super::layout::verify_signature(&frontier)?;

    // 2. Authority.
    let owner_signer_need = ContextNeed::range(
        fact.id,
        "content_signer",
        scope.clone(),
        frontier.owner_endpoint_id,
        frontier.owner_endpoint_id,
    );
    let local_signer_need = ContextNeed::range(
        fact.id,
        "local_signer_secret",
        scope.clone(),
        frontier.owner_endpoint_id,
        frontier.owner_endpoint_id,
    );
    let waiting = ProjectionOutput::new()
        .need(owner_signer_need.clone())
        .need(local_signer_need.clone());
    match (
        context.payload_for(&owner_signer_need),
        context.payload_for(&local_signer_need),
    ) {
        (Some(owner_fact), _) => validate_frontier_endpoint_shared_owner(owner_fact, &frontier)?,
        (None, Some(owner_fact)) => validate_frontier_local_owner(owner_fact, &frontier)?,
        (None, None) => return Ok(waiting),
    }

    // 3. Materialize.
    Ok(waiting
        .offer(ContextOffer::range(
            fact.id,
            "auth_removal_frontier",
            scope,
            fact.id,
            fact.id,
        ))
        .intent(share_fact_with_workspace_intent_for_fact(
            frontier.workspace_id,
            fact,
        )))
}

fn validate_frontier_endpoint_shared_owner(
    owner_fact: &Fact,
    frontier: &RemovalFrontierFact,
) -> Result<(), String> {
    let owner = auth::endpoint_shared::decode_fact_payload(owner_fact.body())
        .map_err(|_| "removal frontier owner context must be endpoint_shared".to_string())?;
    auth::endpoint_shared::layout::verify_signature(&owner)?;
    if owner.workspace_id != frontier.workspace_id {
        return Err("removal frontier owner workspace mismatch".to_string());
    }
    if owner.endpoint_id != frontier.owner_endpoint_id {
        return Err("removal frontier owner endpoint mismatch".to_string());
    }
    if owner.signing_public_key != frontier.signer_public_key {
        return Err("removal frontier owner signing key mismatch".to_string());
    }
    Ok(())
}

fn validate_frontier_local_owner(
    owner_fact: &Fact,
    frontier: &RemovalFrontierFact,
) -> Result<(), String> {
    let owner =
        auth::local_signer_secret::decode_fact_payload(owner_fact.body()).map_err(|_| {
            "removal frontier local owner context must be local signer secret".to_string()
        })?;
    if owner.workspace_id != frontier.workspace_id {
        return Err("removal frontier local owner workspace mismatch".to_string());
    }
    if owner.signer_id != frontier.owner_endpoint_id {
        return Err("removal frontier local owner endpoint mismatch".to_string());
    }
    if owner.public_key != frontier.signer_public_key {
        return Err("removal frontier local owner signing key mismatch".to_string());
    }
    Ok(())
}
