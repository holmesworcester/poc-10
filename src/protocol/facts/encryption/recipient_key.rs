use crate::core::facts::Fact;
use crate::core::projectors::{ProjectionContext, ProjectionOutput};
use crate::protocol::facts::encryption::fact::RecipientKeyFact;
use crate::protocol::facts::encryption::fact::NO_PREVIOUS_RECIPIENT_KEY;
use crate::protocol::facts::encryption::intent::create_key_wrap_intent;
use crate::protocol::facts::encryption::layout;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::validation::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    require_fact_scope,
};

pub(super) fn recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
    recipient: RecipientKeyFact,
) -> Result<ProjectionOutput, String> {
    let scope = crate::protocol::matchers::workspace_scope(recipient.workspace_id);
    require_fact_scope(fact, &scope)?;
    if recipient.previous_recipient_key_id == fact.id {
        return Err(
            "recipient key cannot supersede itself (previous_recipient_key_id == fact_id)"
                .to_string(),
        );
    }

    let superseded_need = matchers::recipient_superseded_need(fact.id, scope.clone(), fact.id);
    let is_superseded = projection_context.offers().iter().any(|offer| {
        offer.role == superseded_need.role && offer.selector == superseded_need.selector
    });
    let mut output = ProjectionOutput::new().need(superseded_need);

    if recipient.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        let previous_need = matchers::recipient_key_need(
            fact.id,
            scope.clone(),
            recipient.previous_recipient_key_id,
        );
        output = output.need(previous_need.clone());
        let Some(previous_fact) = matched_payload_fact(projection_context, &previous_need) else {
            return Ok(output);
        };
        validate_previous_recipient_key(previous_fact, &recipient)?;
        output = output.offer(matchers::recipient_superseded_offer(
            fact.id,
            scope.clone(),
            recipient.previous_recipient_key_id,
        ));
    }

    output = output
        .offer(matchers::recipient_key_offer(
            fact.id,
            scope.clone(),
            fact.id,
        ))
        .intent(share_fact_with_workspace_intent_for_fact(
            recipient.workspace_id,
            fact,
        ));

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

    output = add_signer_needs_for_matching_sources(output, projection_context, &wrap_need)?;
    for (source_fact_id, signer_secret_fact_id, source) in
        matching_wrap_sources_with_signer(projection_context, &wrap_need)?
    {
        output = output.intent(create_key_wrap_intent(
            fact.id,
            source_fact_id,
            signer_secret_fact_id,
            source,
        ));
    }
    Ok(output)
}

fn validate_previous_recipient_key(
    previous_fact: &Fact,
    recipient: &crate::protocol::facts::encryption::fact::RecipientKeyFact,
) -> Result<(), String> {
    if previous_fact.id != recipient.previous_recipient_key_id {
        return Err("recipient key supersession previous context payload id mismatch".to_string());
    }
    let previous = layout::decode_recipient_key(&previous_fact.bytes).map_err(|_| {
        "recipient key supersession previous dependency is not a recipient key".to_string()
    })?;
    if previous.workspace_id != recipient.workspace_id {
        return Err(
            "recipient key supersession previous_recipient_key workspace does not match"
                .to_string(),
        );
    }
    if previous.endpoint_id != recipient.endpoint_id {
        return Err(
            "recipient key supersession previous_recipient_key endpoint does not match \
             (cross-endpoint supersession is rejected)"
                .to_string(),
        );
    }
    Ok(())
}
