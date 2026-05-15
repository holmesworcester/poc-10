//! Poc-10 sync context projector.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::context;
use super::intent;
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
            Some(layout::TYPE_DEPENDENCY) => project_dependency(fact),
            Some(layout::TYPE_KEY_OFFER) => project_key_offer(fact),
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
    let Some((root_offer, root)) = projection_context
        .offers()
        .iter()
        .find(|offer| offer.role == context::range_event_role())
        .and_then(|offer| {
            context::decode_range_offer_selector(&offer.selector).map(|root| (offer, root))
        })
    else {
        return Ok(ProjectionOutput::new().need(range_need));
    };
    let dep_need = context::exact_event_need(fact.id, scope.clone(), root.dependency_id);
    let key_need = context::key_offer_need(fact.id, scope, root.key_id);
    let has_dep = projection_context
        .offers()
        .iter()
        .any(|offer| offer.role == dep_need.role && offer.selector == dep_need.selector);
    let has_key = projection_context
        .offers()
        .iter()
        .any(|offer| offer.role == key_need.role && offer.selector == key_need.selector);

    if has_dep && has_key {
        return Ok(
            ProjectionOutput::new().intent(intent::send_on_connection_intent(
                request.connection_id,
                root_offer.payload_ref,
                root.dependency_id,
                root.key_id,
            )),
        );
    }

    Ok(ProjectionOutput::new()
        .need(range_need)
        .need(dep_need)
        .need(key_need))
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
            root.dependency_id,
            root.key_id,
        ))
        .offer(context::exact_event_offer(fact.id, scope, fact.id, fact.id)))
}

fn project_dependency(fact: &Fact) -> Result<ProjectionOutput, String> {
    let dependency = layout::decode_dependency(&fact.bytes)?;
    let scope = context::workspace_scope(dependency.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(context::exact_event_offer(
        fact.id,
        scope,
        dependency.event_id,
        fact.id,
    )))
}

fn project_key_offer(fact: &Fact) -> Result<ProjectionOutput, String> {
    let key = layout::decode_key_offer(&fact.bytes)?;
    let scope = context::workspace_scope(key.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(context::key_offer(fact.id, scope, key.key_id)))
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}
