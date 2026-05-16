//! Projector for sync range requests.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId};
use crate::core::projection::{MatchedContext, ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::sync::matchers;
use crate::event_modules::sync_encrypted_root::{
    layout as encrypted_root_layout, project as encrypted_root_project,
};
use crate::event_modules::sync_key_wrap_available::layout as key_wrap_available_layout;
use crate::event_modules::sync_shared_event::layout as shared_event_layout;

use super::layout;

type EventId = FactId;
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
        let request = layout::decode_fact(&fact.bytes)?;
        let scope = matchers::workspace_scope(request.workspace_id);
        encrypted_root_project::require_fact_scope(fact, &scope)?;
        let range_need =
            matchers::range_event_need(fact.id, scope.clone(), request.start, request.end);
        let mut roots = matched_range_roots(projection_context, &range_need)?;
        if roots.is_empty() {
            return Ok(ProjectionOutput::new().need(range_need));
        };

        roots.sort_by_key(|root| (root.timestamp, root.event_id));
        let mut output = ProjectionOutput::new();
        let mut has_incomplete_root = false;
        for root in roots {
            let dep_need = matchers::exact_event_need(fact.id, scope.clone(), root.dependency_id);
            let key_need = matchers::key_wrap_need(fact.id, scope.clone(), root.key_wrap_id);
            let dep_ready =
                has_matched_exact_event(projection_context, &dep_need, root.dependency_id)?;
            let key_ready = has_matched_key_wrap(projection_context, &key_need, root.key_wrap_id)?;
            if dep_ready && key_ready {
                output = output.intent(crate::handlers::transit::send_on_connection_intent(
                    crate::handlers::transit::TransitSendOnConnection {
                        connection_id: request.connection_id,
                        fact_ids: vec![root.event_id, root.dependency_id, root.key_wrap_id],
                    },
                ));
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
        .matched_context()
        .iter()
        .filter(|matched| matched.need == *need)
        .map(validate_range_match)
        .collect()
}

fn validate_range_match(matched: &MatchedContext) -> Result<matchers::RangeOfferSelector, String> {
    let selector = matchers::decode_range_offer_selector(&matched.offer.selector)
        .ok_or_else(|| "sync range context offer selector is malformed".to_string())?;
    let root = encrypted_root_layout::decode_fact(&matched.payload.bytes)?;
    encrypted_root_project::validate_sync_fact_workspace(&matched.payload, root.workspace_id)?;
    if matched.offer.owner != matched.payload.id || matched.offer.payload_ref != matched.payload.id
    {
        return Err("sync range context offer must point at its encrypted-root fact".to_string());
    }
    if matched.offer.scope != matchers::workspace_scope(root.workspace_id) {
        return Err("sync range context offer scope does not match payload".to_string());
    }
    if matched.payload.timestamp != selector.timestamp
        || root.event_id != selector.event_id
        || root.dependency_id != selector.dependency_id
        || root.key_wrap_id != selector.key_wrap_id
    {
        return Err("sync range context offer does not match encrypted-root payload".to_string());
    }
    Ok(selector)
}

fn has_matched_exact_event(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
    event_id: EventId,
) -> Result<bool, String> {
    let Some(payload) = projection_context.payload_for(need) else {
        return Ok(false);
    };
    if payload.scope != need.scope {
        return Err("sync exact-event context scope does not match payload".to_string());
    }
    let provided = exact_event_id_from_payload(payload, event_id)?;
    if provided != event_id {
        return Err("sync exact-event context payload does not match need".to_string());
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

fn exact_event_id_from_payload(fact: &Fact, expected: EventId) -> Result<EventId, String> {
    match fact.bytes.first().copied() {
        Some(encrypted_root_layout::TYPE_ENCRYPTED_ROOT) => {
            let root = encrypted_root_layout::decode_fact(&fact.bytes)?;
            encrypted_root_project::validate_sync_fact_workspace(fact, root.workspace_id)?;
            Ok(root.event_id)
        }
        Some(shared_event_layout::TYPE_SHARED_EVENT) => {
            let shared = shared_event_layout::decode_fact(&fact.bytes)?;
            encrypted_root_project::validate_sync_fact_workspace(fact, shared.workspace_id)?;
            Ok(shared.event_id)
        }
        Some(key_wrap_available_layout::TYPE_KEY_WRAP_AVAILABLE) => {
            let key = key_wrap_available_layout::decode_fact(&fact.bytes)?;
            encrypted_root_project::validate_sync_fact_workspace(fact, key.workspace_id)?;
            Ok(key.key_wrap_id)
        }
        _ if fact.id == expected => Ok(fact.id),
        _ => Err("sync exact-event context payload does not identify requested event".to_string()),
    }
}

fn key_wrap_id_from_payload(fact: &Fact, expected: KeyWrapId) -> Result<KeyWrapId, String> {
    match fact.bytes.first().copied() {
        Some(key_wrap_available_layout::TYPE_KEY_WRAP_AVAILABLE) => {
            let key = key_wrap_available_layout::decode_fact(&fact.bytes)?;
            encrypted_root_project::validate_sync_fact_workspace(fact, key.workspace_id)?;
            Ok(key.key_wrap_id)
        }
        _ if fact.id == expected => Ok(fact.id),
        _ => Err("sync key-wrap context payload does not identify requested key wrap".to_string()),
    }
}
