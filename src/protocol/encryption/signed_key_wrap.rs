//! Projection helper for signed key wraps.
//!
//! A key wrap is shared encrypted material signed by the frontier owner.
//! Projection validates signer, recipient, frontier, and optional local
//! recipient context before materializing the accepted wrap row. If this store
//! has matching local recipient material, projection emits an unwrap intent.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{ProjectionContext, ProjectionOutput};
use crate::protocol::encryption::intent::{unwrap_key_wrap_intent, UnwrapKeyWrapIntent};
use crate::protocol::encryption::layout;
use crate::protocol::encryption::rows::{key_wrap_row, KeyWrapRow};
use crate::protocol::identity::signed_fact;
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::validation::{has_matching_signer_public_key, matched_payload_fact, require_fact_scope};

pub(super) fn signed_key_wrap(
    fact: &Fact,
    projection_context: &ProjectionContext,
    signed: signed_fact::SignedPayload<crate::protocol::encryption::fact::KeyWrapFact>,
) -> Result<ProjectionOutput, String> {
    let envelope = signed.envelope;
    let wrap = signed.payload;
    let scope = crate::protocol::identity::workspace::scope(wrap.workspace_id);
    require_fact_scope(fact, &scope)?;
    if envelope.signer_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not match signed envelope signer".to_string());
    }

    let signer_need = crate::core::context::ContextNeed::range(
        fact.id,
        "content_signer",
        scope.clone(),
        envelope.signer_id,
        envelope.signer_id,
    );
    let recipient_need = crate::core::context::ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        wrap.recipient_key_id,
        wrap.recipient_key_id,
    );
    let frontier_need = crate::core::context::ContextNeed::range(
        fact.id,
        "encryption_removal_frontier",
        scope.clone(),
        wrap.frontier_id,
        wrap.frontier_id,
    );
    let local_recipient_need = crate::core::context::ContextNeed::range(
        fact.id,
        "local_recipient_key",
        scope.clone(),
        wrap.recipient_key_id,
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

    let mut output = ProjectionOutput::new()
        .need(signer_need)
        .need(recipient_need)
        .need(frontier_need)
        .need(local_recipient_need);

    if !signer_ready || recipient_fact.is_none() || frontier_fact.is_none() {
        return Ok(output);
    }
    signed_fact::layout::verify_signed_fact(&envelope)?;

    let recipient_fact = recipient_fact.expect("checked");
    if recipient_fact.id != wrap.recipient_key_id {
        return Err("key wrap recipient context payload id mismatch".to_string());
    }
    let recipient = layout::decode_recipient_key(&recipient_fact.bytes)?;
    if recipient.workspace_id != wrap.workspace_id {
        return Err("key wrap recipient key workspace does not match event".to_string());
    }
    let frontier_fact = frontier_fact.expect("checked");
    if frontier_fact.id != wrap.frontier_id {
        return Err("key wrap frontier context payload id mismatch".to_string());
    }
    let frontier = layout::decode_removal_frontier(&frontier_fact.bytes)?;
    if frontier.workspace_id != wrap.workspace_id {
        return Err("key wrap removal frontier workspace does not match event".to_string());
    }
    if frontier.owner_endpoint_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not own removal frontier".to_string());
    }

    output = output
        .row_mutation(RowMutation::PutRow(key_wrap_row(KeyWrapRow {
            key_wrap_id: fact.id,
            signer_public_key: envelope.signer_public_key,
            wrap: wrap.clone(),
        })?))
        .offer(crate::core::context::ContextOffer::range(
            fact.id,
            "sync_exact_fact",
            scope.clone(),
            fact.id,
            fact.id,
        ))
        .offer(crate::core::context::ContextOffer::range(
            fact.id,
            "sync_key_wrap",
            scope,
            fact.id,
            fact.id,
        ))
        .intent(share_fact_with_workspace_intent_for_fact(
            wrap.workspace_id,
            fact,
        ));

    if let Some(local_recipient_fact) = local_recipient_fact {
        if local_recipient_fact.scope != FactScope::Local {
            return Err("key wrap local recipient context is not local".to_string());
        }
        let local = layout::decode_local_recipient_key(&local_recipient_fact.bytes)?;
        if local.workspace_id != wrap.workspace_id {
            return Err("key wrap local recipient workspace does not match event".to_string());
        }
        if local.recipient_key_id != wrap.recipient_key_id {
            return Err("key wrap local recipient key id does not match event".to_string());
        }
        if local.recipient_key != recipient.recipient_key {
            return Err("key wrap local recipient public key does not match recipient".to_string());
        }
        output = output.intent(unwrap_key_wrap_intent(UnwrapKeyWrapIntent {
            workspace_id: wrap.workspace_id,
            frontier_id: wrap.frontier_id,
            recipient_key_id: wrap.recipient_key_id,
            key_wrap_id: fact.id,
            local_recipient_key_id: local_recipient_fact.id,
        }));
    }

    Ok(output)
}
