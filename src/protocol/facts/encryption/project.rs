//! Poc-10 encryption projector for key healing and wrap requests.
//!
//! POLICY. An encryption-family fact is admitted iff:
//!   1. DISPATCH. The first byte selects a known encryption payload or signed
//!      key-wrap envelope.
//!   2. CONTEXT. Subprojectors validate local secrets, recipients, requests,
//!      signer authority, and workspace scope for their specific fact type.
//!   3. MATERIALIZE. Subprojectors publish wrap/secret/frontier offers, share
//!      workspace facts, or emit key-healing work.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::fact::ProjectionPayload;
use super::key_request::key_request;
use super::local_material::{project_local_history_node_secret, project_local_key_secret};
use super::local_recipient_key::local_recipient_key;
use super::recipient_key::recipient_key;
use super::signed_key_wrap::signed_key_wrap;
use super::validation::require_fact_scope;
use crate::protocol::facts::identity;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

#[derive(Debug, Clone, Default)]
pub struct EncryptionProjector;

impl EncryptionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EncryptionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::fact::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::fact::Codec> for EncryptionProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        payload: ProjectionPayload,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Dispatch.
        match payload {
            ProjectionPayload::RecipientKey(recipient) => recipient_key(fact, context, recipient),
            ProjectionPayload::RemovalFrontier(frontier) => {
                removal_frontier(fact, context, frontier)
            }
            ProjectionPayload::LocalKeySecret(secret) => {
                project_local_key_secret(fact, context, secret)
            }
            ProjectionPayload::LocalHistoryNodeSecret(node) => {
                project_local_history_node_secret(fact, context, node)
            }
            ProjectionPayload::LocalRecipientKey(local) => {
                local_recipient_key(fact, context, local)
            }
            ProjectionPayload::KeyRequest(request) => key_request(fact, context, request),
            ProjectionPayload::SignedKeyWrap(signed) => signed_key_wrap(fact, context, signed),
        }
    }
}

fn removal_frontier(
    fact: &Fact,
    context: &ProjectionContext,
    frontier: super::fact::RemovalFrontierFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = matchers::workspace_scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;

    // 2. Authority.
    //
    // The legacy-shaped removal frontier names the endpoint that owns the
    // root key secret. That endpoint must be proven either by a workspace
    // endpoint_shared signer offer (the normal received/public path) or by the
    // local signer secret for the same endpoint (the local authoring path)
    // before this fact can become usable frontier context. Otherwise an
    // unauthenticated workspace-scoped byte string could advertise a key
    // frontier.
    let owner_signer_need =
        matchers::signer_need(fact.id, scope.clone(), frontier.owner_endpoint_id);
    let local_signer_need =
        matchers::local_signer_secret_need(fact.id, scope.clone(), frontier.owner_endpoint_id);
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
        .offer(matchers::frontier_offer(fact.id, scope, fact.id))
        .intent(share_fact_with_workspace_intent_for_fact(
            frontier.workspace_id,
            fact,
        )))
}

fn validate_frontier_endpoint_shared_owner(
    owner_fact: &Fact,
    frontier: &super::fact::RemovalFrontierFact,
) -> Result<(), String> {
    if let Ok(owner) = identity::signed_fact::decode_signed_fact_payload(
        owner_fact,
        identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        "endpoint_shared",
        identity::endpoint_shared::decode_fact_payload,
    ) {
        let owner = owner.payload;
        if owner.workspace_id != frontier.workspace_id {
            return Err("removal frontier owner workspace mismatch".to_string());
        }
        if owner.endpoint_id != frontier.owner_endpoint_id {
            return Err("removal frontier owner endpoint mismatch".to_string());
        }
        return Ok(());
    }
    Err("removal frontier owner context must be endpoint_shared".to_string())
}

fn validate_frontier_local_owner(
    owner_fact: &Fact,
    frontier: &super::fact::RemovalFrontierFact,
) -> Result<(), String> {
    let owner = identity::signed_fact::decode_local_signer_secret_payload(owner_fact.body())
        .map_err(|_| {
            "removal frontier local owner context must be local signer secret".to_string()
        })?;
    if owner.workspace_id != frontier.workspace_id {
        return Err("removal frontier local owner workspace mismatch".to_string());
    }
    if owner.signer_id != frontier.owner_endpoint_id {
        return Err("removal frontier local owner endpoint mismatch".to_string());
    }
    Ok(())
}
