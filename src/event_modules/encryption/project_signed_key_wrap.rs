use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::encryption::intent::{unwrap_key_wrap_intent, UnwrapKeyWrapIntent};
use crate::event_modules::encryption::rows::{key_wrap_row, KeyWrapRow};
use crate::event_modules::encryption::{layout, matchers};
use crate::event_modules::{sealed_message, signed_fact, sync};

use super::project_helpers::{
    has_matching_signer_public_key, matched_payload_fact, require_fact_scope,
};

pub(super) fn project_signed_key_wrap(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
    if envelope.inner_type != layout::TYPE_KEY_WRAP {
        return Err("signed fact does not contain an encryption key wrap".to_string());
    }
    let wrap = layout::decode_key_wrap(&envelope.payload)?;
    let scope = sealed_message::matchers::workspace_scope(wrap.workspace_id);
    require_fact_scope(fact, &scope)?;
    if envelope.signer_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not match signed envelope signer".to_string());
    }

    let signer_need =
        sealed_message::matchers::signer_need(fact.id, scope.clone(), envelope.signer_id);
    let recipient_need =
        matchers::recipient_key_need(fact.id, scope.clone(), wrap.recipient_key_id);
    let frontier_need = matchers::frontier_need(fact.id, scope.clone(), wrap.frontier_id);
    let local_recipient_need =
        matchers::local_recipient_key_need(fact.id, scope.clone(), wrap.recipient_key_id);

    let signer_ready = has_matching_signer_public_key(
        projection_context,
        &signer_need,
        &envelope.signer_public_key,
    );
    let recipient_fact = matched_payload_fact(projection_context, &recipient_need);
    let frontier_fact = matched_payload_fact(projection_context, &frontier_need);
    let local_recipient_fact = matched_payload_fact(projection_context, &local_recipient_need);

    if !signer_ready || recipient_fact.is_none() || frontier_fact.is_none() {
        return Ok(ProjectionOutput::new()
            .need(signer_need)
            .need(recipient_need)
            .need(frontier_need));
    }

    let recipient = layout::decode_recipient_key(&recipient_fact.expect("checked").bytes)?;
    if recipient.workspace_id != wrap.workspace_id {
        return Err("key wrap recipient key workspace does not match event".to_string());
    }
    let frontier = layout::decode_removal_frontier(&frontier_fact.expect("checked").bytes)?;
    if frontier.workspace_id != wrap.workspace_id {
        return Err("key wrap removal frontier workspace does not match event".to_string());
    }
    if frontier.owner_endpoint_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not own removal frontier".to_string());
    }

    let mut output = ProjectionOutput::new()
        .intent(
            AtomicIntent::PutRow(key_wrap_row(KeyWrapRow {
                key_wrap_id: fact.id,
                signer_public_key: envelope.signer_public_key,
                wrap: wrap.clone(),
            })?)
            .into_intent(),
        )
        .offer(sync::matchers::exact_event_offer(
            fact.id,
            scope.clone(),
            fact.id,
            fact.id,
        ))
        .offer(sync::matchers::key_wrap_offer(fact.id, scope, fact.id));

    if let Some(local_recipient_fact) = local_recipient_fact {
        output = output.intent(unwrap_key_wrap_intent(UnwrapKeyWrapIntent {
            workspace_id: wrap.workspace_id,
            frontier_id: wrap.frontier_id,
            recipient_key_id: wrap.recipient_key_id,
            key_wrap_id: fact.id,
            local_recipient_key_id: local_recipient_fact.id,
        }));
    } else {
        output = output
            .need(signer_need)
            .need(recipient_need)
            .need(frontier_need)
            .need(local_recipient_need);
    }

    Ok(output)
}
