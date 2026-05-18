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
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::fact::ProjectionPayload;
use super::key_request::key_request;
use super::local_material::{project_local_history_node_secret, project_local_key_secret};
use super::local_recipient_key::local_recipient_key;
use super::recipient_key::recipient_key;
use super::signed_key_wrap::signed_key_wrap;
use super::validation::require_fact_scope;
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
            ProjectionPayload::RemovalFrontier(frontier) => removal_frontier(fact, frontier),
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
    frontier: super::fact::RemovalFrontierFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = matchers::workspace_scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;
    // 3. Materialize.
    Ok(ProjectionOutput::new()
        .offer(matchers::frontier_offer(fact.id, scope, fact.id))
        .intent(share_fact_with_workspace_intent_for_fact(
            frontier.workspace_id,
            fact,
        )))
}
