//! Projector for sync range requests.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactId};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::facts::sync::encrypted_root::{
    layout as encrypted_root_layout, project as encrypted_root_project,
};
use crate::protocol::facts::sync::key_wrap_available::layout as key_wrap_available_layout;
use crate::protocol::facts::sync::shared_fact::layout as shared_fact_layout;
use crate::protocol::intents::transport::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use crate::protocol::matchers;

use super::layout;

type KeyWrapId = FactId;

#[derive(Debug, Clone, Default)]
pub struct SyncRangeRequestProjector;

impl SyncRangeRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncRangeRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let request = layout::decode_fact(fact.body())?;
        let scope = matchers::workspace_scope(request.workspace_id);
        encrypted_root_project::require_fact_scope(fact, &scope)?;
        let range_need =
            matchers::range_fact_need(fact.id, scope.clone(), request.start, request.end);
        let mut roots = matched_range_roots(projection_context, &range_need)?;
        if roots.is_empty() {
            return Ok(ProjectionOutput::new().need(range_need));
        };

        roots.sort_by_key(|root| (root.timestamp, root.fact_id));
        let mut output = ProjectionOutput::new();
        let mut has_incomplete_root = false;
        for root in roots {
            let dep_need = matchers::exact_fact_need(fact.id, scope.clone(), root.dependency_id);
            let key_need = matchers::key_wrap_need(fact.id, scope.clone(), root.key_wrap_id);
            let dep_ready =
                has_matched_exact_fact(projection_context, &dep_need, root.dependency_id)?;
            let key_ready = has_matched_key_wrap(projection_context, &key_need, root.key_wrap_id)?;
            if dep_ready && key_ready {
                output = output.intent(send_facts_on_connection_intent(SendFactsOnConnection {
                    connection_id: request.connection_id,
                    fact_ids: vec![root.fact_id, root.dependency_id, root.key_wrap_id],
                }));
                continue;
            }

            // Incomplete roots still tell the matcher exactly which dependency
            // or key-wrap facts would make this original range request ready.
            has_incomplete_root = true;
            if !dep_ready {
                output = output.need(dep_need);
            }
            if !key_ready {
                output = output.need(key_need);
            }
        }

        if has_incomplete_root {
            output = output.need(range_need);
        }

        Ok(output)
    }
}

fn matched_range_roots(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<Vec<matchers::RangeOfferSelector>, String> {
    projection_context
        .matched_payloads_for(need)
        .map(|(offer, payload)| validate_range_match(offer, payload))
        .collect()
}

fn validate_range_match(
    offer: &ContextOffer,
    payload: &Fact,
) -> Result<matchers::RangeOfferSelector, String> {
    let selector = matchers::decode_range_offer_selector(&offer.selector)
        .ok_or_else(|| "sync range context offer selector is malformed".to_string())?;
    let root = encrypted_root_layout::decode_fact(payload.body())?;
    encrypted_root_project::validate_sync_fact_workspace(payload, root.workspace_id)?;
    let ContextOffer { payload_ref, .. } = offer;
    if offer.owner != payload.id || *payload_ref != payload.id {
        return Err("sync range context offer must point at its encrypted-root fact".to_string());
    }
    if offer.scope != matchers::workspace_scope(root.workspace_id) {
        return Err("sync range context offer scope does not match payload".to_string());
    }
    if payload.timestamp != selector.timestamp
        || root.fact_id != selector.fact_id
        || root.dependency_id != selector.dependency_id
        || root.key_wrap_id != selector.key_wrap_id
    {
        return Err("sync range context offer does not match encrypted-root payload".to_string());
    }
    Ok(selector)
}

fn has_matched_exact_fact(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
    fact_id: FactId,
) -> Result<bool, String> {
    let Some(payload) = projection_context.payload_for(need) else {
        return Ok(false);
    };
    if payload.scope != need.scope {
        return Err("sync exact-fact context scope does not match payload".to_string());
    }
    let provided = exact_fact_id_from_payload(payload, fact_id)?;
    if provided != fact_id {
        return Err("sync exact-fact context payload does not match need".to_string());
    }
    Ok(true)
}

fn has_matched_key_wrap(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
    key_wrap_id: KeyWrapId,
) -> Result<bool, String> {
    let Some(payload) = projection_context.payload_for(need) else {
        return Ok(false);
    };
    if payload.scope != need.scope {
        return Err("sync key-wrap context scope does not match payload".to_string());
    }
    let provided = key_wrap_id_from_payload(payload, key_wrap_id)?;
    if provided != key_wrap_id {
        return Err("sync key-wrap context payload does not match need".to_string());
    }
    Ok(true)
}

fn exact_fact_id_from_payload(fact: &Fact, expected: FactId) -> Result<FactId, String> {
    match fact.bytes.first().copied() {
        Some(encrypted_root_layout::TYPE_ENCRYPTED_ROOT) => {
            let root = encrypted_root_layout::decode_fact(fact.body())?;
            encrypted_root_project::validate_sync_fact_workspace(fact, root.workspace_id)?;
            Ok(root.fact_id)
        }
        Some(shared_fact_layout::TYPE_SHARED_FACT) => {
            let shared = shared_fact_layout::decode_fact(fact.body())?;
            encrypted_root_project::validate_sync_fact_workspace(fact, shared.workspace_id)?;
            Ok(shared.fact_id)
        }
        Some(key_wrap_available_layout::TYPE_KEY_WRAP_AVAILABLE) => {
            let key = key_wrap_available_layout::decode_fact(fact.body())?;
            encrypted_root_project::validate_sync_fact_workspace(fact, key.workspace_id)?;
            Ok(key.key_wrap_id)
        }
        _ if fact.id == expected => Ok(fact.id),
        _ => Err("sync exact-fact context payload does not identify requested fact".to_string()),
    }
}

fn key_wrap_id_from_payload(fact: &Fact, expected: KeyWrapId) -> Result<KeyWrapId, String> {
    match fact.bytes.first().copied() {
        Some(key_wrap_available_layout::TYPE_KEY_WRAP_AVAILABLE) => {
            let key = key_wrap_available_layout::decode_fact(fact.body())?;
            encrypted_root_project::validate_sync_fact_workspace(fact, key.workspace_id)?;
            Ok(key.key_wrap_id)
        }
        _ if fact.id == expected => Ok(fact.id),
        _ => Err("sync key-wrap context payload does not identify requested key wrap".to_string()),
    }
}
