//! Projection for recipient-key facts (public and local).

use super::context as recipient_context;
use super::fact::NO_PREVIOUS_RECIPIENT_KEY;
use super::intent::{purge_retired_recipient_material_intent, PurgeRetiredRecipientMaterialIntent};
use super::layout;
use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::encryption::key_wrap::intent::materialize_key_wraps_intent;
use crate::event_modules::encryption::project::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    require_fact_scope, require_local_scope,
};
use crate::event_modules::encryption::wrap_source::context as wrap_source_context;
use crate::event_modules::sealed_message;

pub fn project_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let recipient = layout::decode_recipient_key(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(recipient.workspace_id);
    require_fact_scope(fact, &scope)?;

    let superseded_need =
        recipient_context::recipient_superseded_need(fact.id, scope.clone(), fact.id);
    let is_superseded = projection_context.offers().iter().any(|offer| {
        offer.role == superseded_need.role && offer.selector == superseded_need.selector
    });
    let mut output = ProjectionOutput::new()
        .offer(recipient_context::recipient_key_offer(
            fact.id,
            scope.clone(),
            fact.id,
        ))
        .need(superseded_need);

    if recipient.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        output = output.offer(recipient_context::recipient_superseded_offer(
            fact.id,
            scope.clone(),
            recipient.previous_recipient_key_id,
        ));
    }

    if is_superseded {
        return Ok(output);
    }

    let min_frontier_created_at_ms =
        if recipient.previous_recipient_key_id == NO_PREVIOUS_RECIPIENT_KEY {
            0
        } else {
            recipient.created_at_ms
        };
    let wrap_need = wrap_source_context::proactive_wrap_source_need(
        fact.id,
        scope.clone(),
        recipient.workspace_id,
        min_frontier_created_at_ms,
    );
    output = output.need(wrap_need.clone());

    output = add_signer_needs_for_matching_sources(output, projection_context.offers(), &wrap_need);
    for (source_fact_id, signer_secret_fact_id, source) in
        matching_wrap_sources_with_signer(projection_context.offers(), &wrap_need)
    {
        output = output.intent(materialize_key_wraps_intent(
            fact.id,
            source_fact_id,
            signer_secret_fact_id,
            source,
        ));
    }
    Ok(output)
}

pub fn project_local_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let local = layout::decode_local_recipient_key(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(local.workspace_id);
    require_local_scope(fact)?;

    let recipient_need = recipient_context::recipient_key_need(
        fact.id,
        scope.clone(),
        local.recipient_key_id,
    );
    let Some(recipient_fact) = matched_payload_fact(projection_context, &recipient_need) else {
        return Ok(ProjectionOutput::new().need(recipient_need));
    };
    let recipient = layout::decode_recipient_key(&recipient_fact.bytes)?;
    if recipient.workspace_id != local.workspace_id {
        return Err("local recipient key workspace does not match recipient".to_string());
    }
    if recipient.recipient_key != local.recipient_key {
        return Err("local recipient key public key does not match recipient".to_string());
    }

    let superseded_need = recipient_context::recipient_superseded_need(
        fact.id,
        scope.clone(),
        local.recipient_key_id,
    );
    let is_superseded = projection_context.offers().iter().any(|offer| {
        offer.role == superseded_need.role && offer.selector == superseded_need.selector
    });
    let output = ProjectionOutput::new()
        .need(recipient_need)
        .need(superseded_need);
    if is_superseded {
        return Ok(output.intent(purge_retired_recipient_material_intent(
            PurgeRetiredRecipientMaterialIntent {
                workspace_id: local.workspace_id,
                recipient_key_id: local.recipient_key_id,
                local_recipient_key_id: fact.id,
            },
        )));
    }

    Ok(output.offer(recipient_context::local_recipient_key_offer(
        fact.id,
        scope,
        local.recipient_key_id,
    )))
}

