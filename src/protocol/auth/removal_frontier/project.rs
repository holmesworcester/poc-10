//! Removal frontier projector.
//!
//! POLICY. A removal frontier is admitted iff its scope matches the workspace
//! and its owner endpoint is proven by either an endpoint_shared signer offer or
//! a local signer secret. Projection publishes frontier context and shares the
//! fact with the workspace.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::auth;
use crate::protocol::auth::key_wrap::project::require_fact_scope;
use crate::protocol::auth::signature;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::fact::RemovalFrontierFact;

/// Staged read pipeline for the removal_frontier fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::removal_frontier::Codec",
    authenticate: "auth::removal_frontier::authenticate::RemovalFrontierAuthenticator",
    adapt: "auth::removal_frontier::adapt::RemovalFrontierAdapter",
    project: "auth::removal_frontier::project::RemovalFrontierProjector",
};

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
        project_staged::<
            super::Codec,
            super::authenticate::RemovalFrontierAuthenticator,
            super::adapt::RemovalFrontierAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<RemovalFrontierFact> for RemovalFrontierProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        frontier: RemovalFrontierFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and the
        // signer signature. Scope is interpretation.
        // 1. Scope.
        let scope = crate::protocol::auth::workspace::scope(frontier.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            frontier.signer_public_key,
        )?;
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
            .need(signature_need.clone())
            .need(owner_signer_need.clone())
            .need(local_signer_need.clone());
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            frontier.workspace_id,
            fact.id,
            frontier.signer_public_key,
            "removal frontier",
        )? {
            return Ok(waiting);
        }
        let context_have = match (
            context.payload_for(&owner_signer_need),
            context.payload_for(&local_signer_need),
        ) {
            (Some(owner_fact), _) => {
                validate_frontier_endpoint_shared_owner(owner_fact, &frontier)?;
                context_have_from_needs(context, [&signature_need, &owner_signer_need])
            }
            (None, Some(owner_fact)) => {
                validate_frontier_local_owner(owner_fact, &frontier)?;
                context_have_from_needs(context, [&signature_need])
            }
            (None, None) => return Ok(waiting),
        };

        // 3. Materialize.
        Ok(share_fact_with_sync(
            waiting.offer(ContextOffer::range(
                fact.id,
                "auth_removal_frontier",
                scope,
                fact.id,
                fact.id,
            )),
            frontier.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn validate_frontier_endpoint_shared_owner(
    owner_fact: &Fact,
    frontier: &RemovalFrontierFact,
) -> Result<(), String> {
    let owner = auth::endpoint_shared::decode_fact_payload(owner_fact.body())
        .map_err(|_| "removal frontier owner context must be endpoint_shared".to_string())?;
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
