//! Projection helper for local recipient private material.
//!
//! A local recipient key lets this store unwrap key wraps addressed to a
//! recipient public key. Projection proves the local secret matches the shared
//! recipient fact, offers local-recipient context while the key is live, and
//! emits purge work when a superseding recipient key makes the material retired.

use crate::core::facts::Fact;
use crate::core::projectors::{ProjectionContext, ProjectionOutput};
use crate::protocol::facts::encryption::fact::LocalRecipientKeyFact;
use crate::protocol::facts::encryption::intent::{
    purge_retired_recipient_material_intent, PurgeRetiredRecipientMaterialIntent,
};
use crate::protocol::facts::encryption::layout;

use super::validation::{matched_payload_fact, require_local_scope};

pub(super) fn local_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
    local: LocalRecipientKeyFact,
) -> Result<ProjectionOutput, String> {
    let scope = crate::protocol::facts::identity::workspace::scope(local.workspace_id);
    require_local_scope(fact)?;

    let recipient_need = crate::core::context::ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        local.recipient_key_id,
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

    let superseded_need = crate::core::context::ContextNeed::range(
        fact.id,
        "recipient_superseded",
        scope.clone(),
        local.recipient_key_id,
        local.recipient_key_id,
    );
    let is_superseded = projection_context.payload_for(&superseded_need).is_some();
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

    Ok(output.offer(crate::core::context::ContextOffer::range(
        fact.id,
        "local_recipient_key",
        scope,
        local.recipient_key_id,
        local.recipient_key_id,
    )))
}
