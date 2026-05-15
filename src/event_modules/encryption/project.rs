//! Poc-10 encryption projector for key healing and wrap requests.

use crate::core::context::ContextOffer;
use crate::core::facts::Fact;
use crate::core::facts::FactId;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::context::{self, WrapSourceSelector};
use super::fact::{
    KeyRequestFact, LocalHistoryNodeSecretFact, LocalKeySecretFact, RecipientKeyFact,
    RemovalFrontierFact, NO_PREVIOUS_RECIPIENT_KEY,
};
use super::intent::{
    materialize_key_wraps_intent, purge_retired_recipient_material_intent,
    PurgeRetiredRecipientMaterialIntent,
};
use super::layout;
use super::rows::{key_wrap_row, KeyWrapRow};
use crate::event_modules::sealed_message;
use crate::event_modules::signed_fact;
use crate::event_modules::sync;

#[derive(Debug, Clone, Default)]
pub struct EncryptionProjector;

impl EncryptionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EncryptionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_RECIPIENT_KEY) => project_recipient_key(fact, context),
            Some(layout::TYPE_REMOVAL_FRONTIER) => project_removal_frontier(fact),
            Some(layout::TYPE_LOCAL_KEY_SECRET) => project_local_key_secret(fact),
            Some(layout::TYPE_LOCAL_HISTORY_NODE_SECRET) => project_local_history_node_secret(fact),
            Some(layout::TYPE_KEY_REQUEST) => project_key_request(fact, context),
            Some(signed_fact::layout::TYPE_SIGNED_FACT) => project_signed_key_wrap(fact, context),
            _ => Err("unknown encryption fact type".to_string()),
        }
    }
}

fn project_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let recipient = layout::decode_recipient_key(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(recipient.workspace_id);
    require_fact_scope(fact, &scope)?;

    let superseded_need = context::recipient_superseded_need(fact.id, scope.clone(), fact.id);
    let is_superseded = projection_context.offers().iter().any(|offer| {
        offer.role == superseded_need.role && offer.selector == superseded_need.selector
    });
    if is_superseded {
        return Ok(
            ProjectionOutput::new().intent(purge_retired_recipient_material_intent(
                PurgeRetiredRecipientMaterialIntent {
                    workspace_id: recipient.workspace_id,
                    recipient_key_id: fact.id,
                },
            )),
        );
    }

    let min_frontier_created_at_ms =
        if recipient.previous_recipient_key_id == NO_PREVIOUS_RECIPIENT_KEY {
            0
        } else {
            recipient.created_at_ms
        };
    let wrap_need = context::proactive_wrap_source_need(
        fact.id,
        scope.clone(),
        recipient.workspace_id,
        min_frontier_created_at_ms,
    );
    let mut output = ProjectionOutput::new()
        .offer(context::recipient_key_offer(
            fact.id,
            scope.clone(),
            fact.id,
        ))
        .need(superseded_need)
        .need(wrap_need.clone());

    if recipient.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        output = output.offer(context::recipient_superseded_offer(
            fact.id,
            scope,
            recipient.previous_recipient_key_id,
        ));
    }

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

fn project_removal_frontier(fact: &Fact) -> Result<ProjectionOutput, String> {
    let frontier = layout::decode_removal_frontier(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(context::frontier_offer(fact.id, scope, fact.id)))
}

fn project_local_key_secret(fact: &Fact) -> Result<ProjectionOutput, String> {
    let secret = layout::decode_local_key_secret(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(secret.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(context::frontier_root_wrap_source_offer(
            fact.id,
            scope.clone(),
            secret.workspace_id,
            secret.frontier_id,
            secret.owner_endpoint_id,
            secret.created_at_ms,
        ))
        .offer(sealed_message::context::secret_offer(
            fact.id,
            scope,
            secret.workspace_id,
            secret.frontier_id,
            0,
            u64::MAX,
            0,
            [0; 32],
        )))
}

fn project_local_history_node_secret(fact: &Fact) -> Result<ProjectionOutput, String> {
    let node = layout::decode_local_history_node_secret(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(node.workspace_id);
    require_fact_scope(fact, &scope)?;
    let end_minute = node
        .range_start
        .checked_add(node.range_width - 1)
        .ok_or_else(|| "history node range end overflow".to_string())?;
    if node.bit_depth % 8 != 0 {
        return Err("sealed-message bridge only accepts byte-aligned history prefixes".to_string());
    }
    let prefix_bytes = (node.bit_depth / 8)
        .try_into()
        .map_err(|_| "history node prefix byte width overflow".to_string())?;
    Ok(ProjectionOutput::new()
        .offer(context::history_node_wrap_source_offer(
            fact.id,
            scope.clone(),
            node.workspace_id,
            node.frontier_id,
            node.owner_endpoint_id,
            node.range_start,
            node.range_width,
            node.bit_depth,
            node.event_id_prefix,
        ))
        .offer(sealed_message::context::secret_offer(
            fact.id,
            scope,
            node.workspace_id,
            node.frontier_id,
            node.range_start,
            end_minute,
            prefix_bytes,
            node.event_id_prefix,
        )))
}

fn project_key_request(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let request = layout::decode_key_request(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(request.workspace_id);
    require_fact_scope(fact, &scope)?;

    let recipient_need =
        context::recipient_key_need(fact.id, scope.clone(), request.recipient_key_id);
    let frontier_need = context::frontier_need(fact.id, scope.clone(), request.frontier_id);
    let source_need = context::requested_wrap_source_need(
        fact.id,
        scope,
        request.workspace_id,
        request.frontier_id,
    );

    let has_recipient = has_exact_offer(projection_context.offers(), &recipient_need);
    let has_frontier = has_exact_offer(projection_context.offers(), &frontier_need);
    let mut output = ProjectionOutput::new()
        .need(recipient_need)
        .need(frontier_need)
        .need(source_need.clone());

    if has_recipient && has_frontier {
        output = add_signer_needs_for_matching_sources(
            output,
            projection_context.offers(),
            &source_need,
        );
        for (source_fact_id, signer_secret_fact_id, source) in
            matching_wrap_sources_with_signer(projection_context.offers(), &source_need)
        {
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

fn project_signed_key_wrap(
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
    let recipient_need = context::recipient_key_need(fact.id, scope.clone(), wrap.recipient_key_id);
    let frontier_need = context::frontier_need(fact.id, scope.clone(), wrap.frontier_id);

    let signer_ready = has_matching_signer_public_key(
        projection_context,
        &signer_need,
        &envelope.signer_public_key,
    );
    let recipient_fact = matched_payload_fact(projection_context, &recipient_need);
    let frontier_fact = matched_payload_fact(projection_context, &frontier_need);

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

    Ok(ProjectionOutput::new()
        .intent(
            AtomicIntent::PutRow(key_wrap_row(KeyWrapRow {
                key_wrap_id: fact.id,
                signer_public_key: envelope.signer_public_key,
                wrap,
            })?)
            .into_intent(),
        )
        .offer(sync::context::exact_event_offer(
            fact.id,
            scope.clone(),
            fact.id,
            fact.id,
        ))
        .offer(sync::context::key_wrap_offer(fact.id, scope, fact.id)))
}

fn matching_wrap_sources_with_signer(
    offers: &[ContextOffer],
    need: &crate::core::context::ContextNeed,
) -> Vec<(FactId, FactId, WrapSourceSelector)> {
    offers
        .iter()
        .filter_map(|offer| {
            context::wrap_source_offer_matches_need(need, offer).and_then(|source| {
                local_signer_secret_payload_ref(
                    offers,
                    need.owner,
                    &need.scope,
                    source.owner_endpoint_id,
                )
                .map(|signer_secret_fact_id| (offer.payload_ref, signer_secret_fact_id, source))
            })
        })
        .collect()
}

fn add_signer_needs_for_matching_sources(
    mut output: ProjectionOutput,
    offers: &[ContextOffer],
    need: &crate::core::context::ContextNeed,
) -> ProjectionOutput {
    for offer in offers {
        let Some(source) = context::wrap_source_offer_matches_need(need, offer) else {
            continue;
        };
        output = output.need(signed_fact::context::local_signer_secret_need(
            need.owner,
            need.scope.clone(),
            source.owner_endpoint_id,
        ));
    }
    output
}

fn local_signer_secret_payload_ref(
    offers: &[ContextOffer],
    owner: FactId,
    scope: &crate::core::facts::FactScope,
    signer_id: FactId,
) -> Option<FactId> {
    let need = signed_fact::context::local_signer_secret_need(owner, scope.clone(), signer_id);
    offers
        .iter()
        .filter(|offer| offer.role == need.role && offer.selector == need.selector)
        .map(|offer| offer.payload_ref)
        .min()
}

fn has_exact_offer(offers: &[ContextOffer], need: &crate::core::context::ContextNeed) -> bool {
    offers
        .iter()
        .any(|offer| offer.role == need.role && offer.selector == need.selector)
}

fn matched_payload_fact<'a>(
    projection_context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
) -> Option<&'a Fact> {
    projection_context
        .matched_context()
        .iter()
        .find(|matched| matched.need.role == need.role && matched.need.selector == need.selector)
        .map(|matched| &matched.payload)
}

fn has_matching_signer_public_key(
    projection_context: &ProjectionContext,
    need: &crate::core::context::ContextNeed,
    signer_public_key: &[u8; 32],
) -> bool {
    projection_context
        .matched_context()
        .iter()
        .filter(|matched| matched.need.role == need.role && matched.need.selector == need.selector)
        .any(|matched| {
            sealed_message::layout::decode_signer_pubkey(&matched.payload.bytes)
                .map(|signer| {
                    signer.signer_id.as_slice() == need.selector.as_bytes()
                        && signer.public_key == *signer_public_key
                })
                .unwrap_or(false)
        })
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("encryption fact scope does not match body workspace".to_string())
    }
}

#[allow(dead_code)]
fn _keep_fact_types_visible(
    _: RecipientKeyFact,
    _: RemovalFrontierFact,
    _: LocalKeySecretFact,
    _: LocalHistoryNodeSecretFact,
    _: KeyRequestFact,
) {
}
