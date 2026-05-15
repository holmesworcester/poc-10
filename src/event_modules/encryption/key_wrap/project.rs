//! Projection for signed key-wrap envelope facts.

use super::intent::{unwrap_key_wrap_intent, UnwrapKeyWrapIntent};
use super::layout;
use super::rows::{key_wrap_row, KeyWrapRow};
use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::encryption::project::{
    has_matching_signer_public_key, matched_payload_fact, require_fact_scope,
};
use crate::event_modules::encryption::recipient_key::context as recipient_context;
use crate::event_modules::encryption::recipient_key::layout as recipient_layout;
use crate::event_modules::encryption::wrap_source::context as wrap_source_context;
use crate::event_modules::encryption::wrap_source::layout as wrap_source_layout;
use crate::event_modules::sealed_message;
use crate::event_modules::signed_fact;
use crate::event_modules::sync;

pub fn project_signed_key_wrap(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
    if envelope.inner_type != layout::TYPE_KEY_WRAP {
        return Err("signed fact does not contain an encryption key wrap".to_string());
    }
    let wrap = layout::decode_key_wrap(&envelope.payload)?;
    let scope = sealed_message::context::workspace_scope(wrap.workspace_id);
    require_fact_scope(fact, &scope)?;
    if envelope.signer_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not match signed envelope signer".to_string());
    }

    let signer_need =
        sealed_message::context::signer_need(fact.id, scope.clone(), envelope.signer_id);
    let recipient_need =
        recipient_context::recipient_key_need(fact.id, scope.clone(), wrap.recipient_key_id);
    let frontier_need =
        wrap_source_context::frontier_need(fact.id, scope.clone(), wrap.frontier_id);
    let local_recipient_need = recipient_context::local_recipient_key_need(
        fact.id,
        scope.clone(),
        wrap.recipient_key_id,
    );

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

    let recipient = recipient_layout::decode_recipient_key(&recipient_fact.expect("checked").bytes)?;
    if recipient.workspace_id != wrap.workspace_id {
        return Err("key wrap recipient key workspace does not match event".to_string());
    }
    let frontier =
        wrap_source_layout::decode_removal_frontier(&frontier_fact.expect("checked").bytes)?;
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
        .offer(sync::context::exact_event_offer(
            fact.id,
            scope.clone(),
            fact.id,
            fact.id,
        ))
        .offer(sync::context::key_wrap_offer(fact.id, scope, fact.id));

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
