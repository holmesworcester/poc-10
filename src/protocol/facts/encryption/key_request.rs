//! Key-request projection helper.
//!
//! Key requests ask an endpoint that owns a removal frontier to produce a wrap
//! for a requester recipient key. This helper keeps the request-specific
//! projection policy together: validate requester/responder context, find
//! eligible wrap sources, add signer-secret needs, and emit create-key-wrap
//! intents once the required local signer material is available.

use crate::core::facts::Fact;
use crate::core::projectors::{ProjectionContext, ProjectionOutput};
use crate::protocol::facts::encryption::fact::KeyRequestFact;
use crate::protocol::facts::encryption::intent::create_key_wrap_intent;
use crate::protocol::facts::encryption::layout;
use crate::protocol::facts::encryption::wrap_source;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::validation::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    require_fact_scope,
};

pub(super) fn key_request(
    fact: &Fact,
    projection_context: &ProjectionContext,
    request: KeyRequestFact,
) -> Result<ProjectionOutput, String> {
    let scope = crate::protocol::facts::identity::workspace::scope(request.workspace_id);
    require_fact_scope(fact, &scope)?;

    let recipient_need = crate::core::context::ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        request.recipient_key_id,
        request.recipient_key_id,
    );
    let frontier_need = crate::core::context::ContextNeed::range(
        fact.id,
        "encryption_removal_frontier",
        scope.clone(),
        request.frontier_id,
        request.frontier_id,
    );
    let source_need = wrap_source::requested_wrap_source_need(
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

    if let (Some(recipient_fact), Some(frontier_fact)) = (recipient_fact, frontier_fact) {
        if recipient_fact.id != request.recipient_key_id {
            return Err("key request recipient context payload id mismatch".to_string());
        }
        let recipient = layout::decode_recipient_key(&recipient_fact.bytes)?;
        if recipient.workspace_id != request.workspace_id {
            return Err("key request recipient workspace mismatch".to_string());
        }
        if recipient.endpoint_id != request.requester_endpoint_id {
            return Err("key request recipient is not requester endpoint".to_string());
        }
        if frontier_fact.id != request.frontier_id {
            return Err("key request frontier context payload id mismatch".to_string());
        }
        let frontier = layout::decode_removal_frontier(&frontier_fact.bytes)?;
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
