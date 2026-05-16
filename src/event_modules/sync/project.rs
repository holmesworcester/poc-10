//! Poc-10 sync context projector.
//!
//! Sync facts project availability and demand; they do not own socket IO or
//! mutate the sync index. A range request becomes either context needs or a
//! bounded send intent once the encrypted root, its dependency, and its key
//! wrap are all visible in the same workspace. The projector therefore remains
//! a deterministic bridge between context matching and handler work.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::context;
use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncContextProjector;

impl SyncContextProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncContextProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_SYNC_RANGE_REQUEST) => {
                project_sync_range_request(fact, projection_context)
            }
            Some(layout::TYPE_ENCRYPTED_ROOT) => project_encrypted_root(fact),
            Some(layout::TYPE_SHARED_EVENT) => project_shared_event(fact),
            Some(layout::TYPE_KEY_WRAP_AVAILABLE) => project_key_wrap_available(fact),
            _ => Err("unknown sync context fact type".to_string()),
        }
    }
}

fn project_sync_range_request(
    fact: &Fact,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let request = layout::decode_sync_range_request(&fact.bytes)?;
    let scope = context::workspace_scope(request.workspace_id);
    require_fact_scope(fact, &scope)?;
    let range_need = context::range_event_need(fact.id, scope.clone(), request.start, request.end);
    let roots = projection_context
        .offers()
        .iter()
        .filter(|offer| offer.role == context::range_event_role())
        .filter_map(|offer| context::decode_range_offer_selector(&offer.selector))
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Ok(ProjectionOutput::new().need(range_need));
    };

    let mut output = ProjectionOutput::new().need(range_need);
    // Pick the earliest complete root deterministically. Later complete roots
    // stay available through their offers; this projection pass emits one send
    // intent so retries and batching remain handler concerns.
    let mut ready = roots
        .iter()
        .copied()
        .filter(|root| {
            let dep_need = context::exact_event_need(fact.id, scope.clone(), root.dependency_id);
            let key_need = context::key_wrap_need(fact.id, scope.clone(), root.key_wrap_id);
            has_exact_offer(projection_context, &dep_need)
                && has_exact_offer(projection_context, &key_need)
        })
        .collect::<Vec<_>>();
    ready.sort_by_key(|root| (root.timestamp, root.event_id));
    if let Some(root) = ready.first().copied() {
        return Ok(ProjectionOutput::new().intent(
            crate::handlers::transit::send_on_connection_intent(
                crate::handlers::transit::TransitSendOnConnection {
                    connection_id: request.connection_id,
                    fact_ids: vec![root.event_id, root.dependency_id, root.key_wrap_id],
                },
            ),
        ));
    }

    // Incomplete roots are still useful: they tell the matcher which precise
    // dependency or key-wrap facts would make the original range request ready.
    for root in roots {
        let dep_need = context::exact_event_need(fact.id, scope.clone(), root.dependency_id);
        let key_need = context::key_wrap_need(fact.id, scope.clone(), root.key_wrap_id);
        if !has_exact_offer(projection_context, &dep_need) {
            output = output.need(dep_need);
        }
        if !has_exact_offer(projection_context, &key_need) {
            output = output.need(key_need);
        }
    }

    Ok(output)
}

fn project_encrypted_root(fact: &Fact) -> Result<ProjectionOutput, String> {
    let root = layout::decode_encrypted_root(&fact.bytes)?;
    let scope = context::workspace_scope(root.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(context::range_event_offer(
            fact.id,
            scope.clone(),
            fact.timestamp,
            root.event_id,
            root.dependency_id,
            root.key_wrap_id,
        ))
        .offer(context::exact_event_offer(
            fact.id,
            scope,
            root.event_id,
            fact.id,
        )))
}

fn project_shared_event(fact: &Fact) -> Result<ProjectionOutput, String> {
    let shared = layout::decode_shared_event(&fact.bytes)?;
    let scope = context::workspace_scope(shared.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(context::exact_event_offer(
        fact.id,
        scope,
        shared.event_id,
        fact.id,
    )))
}

fn project_key_wrap_available(fact: &Fact) -> Result<ProjectionOutput, String> {
    let key = layout::decode_key_wrap_available(&fact.bytes)?;
    let scope = context::workspace_scope(key.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(context::exact_event_offer(
            fact.id,
            scope.clone(),
            key.key_wrap_id,
            fact.id,
        ))
        .offer(context::key_wrap_offer(fact.id, scope, key.key_wrap_id)))
}

fn has_exact_offer(
    projection_context: &ProjectionContext,
    need: &crate::core::context::ContextNeed,
) -> bool {
    projection_context
        .offers()
        .iter()
        .any(|offer| offer.role == need.role && offer.selector == need.selector)
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}
