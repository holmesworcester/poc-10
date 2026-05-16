use crate::core::facts::Fact;
use crate::core::projection::ProjectionOutput;

use super::super::layout;
use super::super::matchers;
use super::validation::require_fact_scope;

pub(super) fn project_encrypted_root(fact: &Fact) -> Result<ProjectionOutput, String> {
    let root = layout::decode_encrypted_root(&fact.bytes)?;
    let scope = matchers::workspace_scope(root.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(matchers::range_event_offer(
            fact.id,
            scope.clone(),
            fact.timestamp,
            root.event_id,
            root.dependency_id,
            root.key_wrap_id,
        ))
        .offer(matchers::exact_event_offer(
            fact.id,
            scope,
            root.event_id,
            fact.id,
        )))
}

pub(super) fn project_shared_event(fact: &Fact) -> Result<ProjectionOutput, String> {
    let shared = layout::decode_shared_event(&fact.bytes)?;
    let scope = matchers::workspace_scope(shared.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(matchers::exact_event_offer(
        fact.id,
        scope,
        shared.event_id,
        fact.id,
    )))
}

pub(super) fn project_key_wrap_available(fact: &Fact) -> Result<ProjectionOutput, String> {
    let key = layout::decode_key_wrap_available(&fact.bytes)?;
    let scope = matchers::workspace_scope(key.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(matchers::exact_event_offer(
            fact.id,
            scope.clone(),
            key.key_wrap_id,
            fact.id,
        ))
        .offer(matchers::key_wrap_offer(fact.id, scope, key.key_wrap_id)))
}
