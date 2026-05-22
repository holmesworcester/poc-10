//! Key request projector.
//!
//! POLICY. A key request is admitted iff its scope matches the workspace.
//! Projection validates requester/responder context, finds eligible wrap
//! sources, and emits create-key-wrap intents once local signer material is
//! available.

use crate::core::context::ContextNeed;
use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::encryption::create_key_wrap::create_key_wrap_intent;
use crate::protocol::encryption::key_wrap::project::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    require_fact_scope, requested_wrap_source_need,
};
use crate::protocol::encryption::recipient_key;
use crate::protocol::encryption::removal_frontier;
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::fact::KeyRequestFact;

#[derive(Debug, Clone, Default)]
pub struct KeyRequestProjector;

impl KeyRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for KeyRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for KeyRequestProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        request: KeyRequestFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        key_request(fact, context, request)
    }
}

fn key_request(
    fact: &Fact,
    projection_context: &ProjectionContext,
    request: KeyRequestFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::identity::workspace::scope(request.workspace_id);
    require_fact_scope(fact, &scope)?;

    // 2. Context: recipient, frontier, and wrap-source needs.
    let recipient_need = ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        request.recipient_key_id,
        request.recipient_key_id,
    );
    let frontier_need = ContextNeed::range(
        fact.id,
        "encryption_removal_frontier",
        scope.clone(),
        request.frontier_id,
        request.frontier_id,
    );
    let source_need = requested_wrap_source_need(
        fact.id,
        scope,
        request.workspace_id,
        request.frontier_id,
    );

    let recipient_fact = matched_payload_fact(projection_context, &recipient_need);
    let frontier_fact = matched_payload_fact(projection_context, &frontier_need);
    let mut output = ProjectionOutput::new()
        .need(recipient_need)
        .need(frontier_need)
        .need(source_need.clone())
        .intent(share_fact_with_workspace_intent_for_fact(
            request.workspace_id,
            fact,
        ));

    // 3. Materialize: emit create-key-wrap work for eligible sources.
    if let (Some(recipient_fact), Some(frontier_fact)) = (recipient_fact, frontier_fact) {
        if recipient_fact.id != request.recipient_key_id {
            return Err("key request recipient context payload id mismatch".to_string());
        }
        let recipient = recipient_key::decode_fact_payload(&recipient_fact.bytes)?;
        if recipient.workspace_id != request.workspace_id {
            return Err("key request recipient workspace mismatch".to_string());
        }
        if recipient.endpoint_id != request.requester_endpoint_id {
            return Err("key request recipient is not requester endpoint".to_string());
        }
        if frontier_fact.id != request.frontier_id {
            return Err("key request frontier context payload id mismatch".to_string());
        }
        let frontier = removal_frontier::decode_fact_payload(&frontier_fact.bytes)?;
        if frontier.workspace_id != request.workspace_id {
            return Err("key request frontier workspace mismatch".to_string());
        }
        if frontier.owner_endpoint_id != request.responder_endpoint_id {
            return Err("key request frontier is not owned by responder".to_string());
        }
        output = add_signer_needs_for_matching_sources(output, projection_context, &source_need)?;
        for (source_fact_id, signer_secret_fact_id, source) in
            matching_wrap_sources_with_signer(projection_context, &source_need)?
        {
            if source.owner_endpoint_id != request.responder_endpoint_id {
                continue;
            }
            output = output.intent(create_key_wrap_intent(
                request.recipient_key_id,
                source_fact_id,
                signer_secret_fact_id,
                source,
            ));
        }
    }
    Ok(output)
}
