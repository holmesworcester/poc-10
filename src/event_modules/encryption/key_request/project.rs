//! Projection for key-request facts.

use super::layout;
use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::encryption::key_wrap::intent::materialize_key_wraps_intent;
use crate::event_modules::encryption::project::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    require_fact_scope,
};
use crate::event_modules::encryption::recipient_key::context as recipient_context;
use crate::event_modules::encryption::recipient_key::layout as recipient_layout;
use crate::event_modules::encryption::wrap_source::context as wrap_source_context;
use crate::event_modules::encryption::wrap_source::layout as wrap_source_layout;
use crate::event_modules::sealed_message;

pub fn project_key_request(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let request = layout::decode_key_request(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(request.workspace_id);
    require_fact_scope(fact, &scope)?;

    let recipient_need =
        recipient_context::recipient_key_need(fact.id, scope.clone(), request.recipient_key_id);
    let frontier_need =
        wrap_source_context::frontier_need(fact.id, scope.clone(), request.frontier_id);
    let source_need = wrap_source_context::requested_wrap_source_need(
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
        .need(source_need.clone());

    if let (Some(recipient_fact), Some(frontier_fact)) = (recipient_fact, frontier_fact) {
        let recipient = recipient_layout::decode_recipient_key(&recipient_fact.bytes)?;
        if recipient.workspace_id != request.workspace_id {
            return Err("key request recipient workspace mismatch".to_string());
        }
        if recipient.endpoint_id != request.requester_endpoint_id {
            return Err("key request recipient is not requester endpoint".to_string());
        }
        let frontier = wrap_source_layout::decode_removal_frontier(&frontier_fact.bytes)?;
        if frontier.workspace_id != request.workspace_id {
            return Err("key request frontier workspace mismatch".to_string());
        }
        if frontier.owner_endpoint_id != request.responder_endpoint_id {
            return Err("key request frontier is not owned by responder".to_string());
        }
        output = add_signer_needs_for_matching_sources(
            output,
            projection_context.offers(),
            &source_need,
        );
        for (source_fact_id, signer_secret_fact_id, source) in
            matching_wrap_sources_with_signer(projection_context.offers(), &source_need)
        {
            if source.owner_endpoint_id != request.responder_endpoint_id {
                continue;
            }
            output = output.intent(materialize_key_wraps_intent(
                request.recipient_key_id,
                source_fact_id,
                signer_secret_fact_id,
                source,
            ));
        }
    }
    Ok(output)
}
