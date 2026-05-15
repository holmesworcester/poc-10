//! Poc-10 encryption projector for key healing and wrap requests.

use crate::core::context::ContextOffer;
use crate::core::facts::Fact;
use crate::core::facts::FactId;
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
use crate::event_modules::sealed_message;

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

    for (source_fact_id, source) in matching_wrap_sources(projection_context.offers(), &wrap_need) {
        output = output.intent(materialize_key_wraps_intent(
            fact.id,
            source_fact_id,
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
        for (source_fact_id, source) in
            matching_wrap_sources(projection_context.offers(), &source_need)
        {
            output = output.intent(materialize_key_wraps_intent(
                request.recipient_key_id,
                source_fact_id,
                source,
            ));
        }
    }
    Ok(output)
}

fn matching_wrap_sources(
    offers: &[ContextOffer],
    need: &crate::core::context::ContextNeed,
) -> Vec<(FactId, WrapSourceSelector)> {
    offers
        .iter()
        .filter_map(|offer| {
            context::wrap_source_offer_matches_need(need, offer)
                .map(|source| (offer.payload_ref, source))
        })
        .collect()
}

fn has_exact_offer(offers: &[ContextOffer], need: &crate::core::context::ContextNeed) -> bool {
    offers
        .iter()
        .any(|offer| offer.role == need.role && offer.selector == need.selector)
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
