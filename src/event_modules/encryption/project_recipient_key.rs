use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::encryption::fact::NO_PREVIOUS_RECIPIENT_KEY;
use crate::event_modules::encryption::intent::materialize_key_wraps_intent;
use crate::event_modules::encryption::{layout, matchers};
use crate::event_modules::sealed_message;

use super::project_helpers::{
    add_signer_needs_for_matching_sources, matching_wrap_sources_with_signer, require_fact_scope,
};

pub(super) fn project_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let recipient = layout::decode_recipient_key(&fact.bytes)?;
    let scope = sealed_message::matchers::workspace_scope(recipient.workspace_id);
    require_fact_scope(fact, &scope)?;

    let superseded_need = matchers::recipient_superseded_need(fact.id, scope.clone(), fact.id);
    let is_superseded = projection_context.offers().iter().any(|offer| {
        offer.role == superseded_need.role && offer.selector == superseded_need.selector
    });
    let mut output = ProjectionOutput::new()
        .offer(matchers::recipient_key_offer(
            fact.id,
            scope.clone(),
            fact.id,
        ))
        .need(superseded_need);

    if recipient.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        output = output.offer(matchers::recipient_superseded_offer(
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
    let wrap_need = matchers::proactive_wrap_source_need(
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
