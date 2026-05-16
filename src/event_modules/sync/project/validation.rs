use crate::core::facts::{Fact, FactScope};

use super::super::fact::WorkspaceId;
use super::super::matchers;

pub(super) fn validate_sync_fact_workspace(
    fact: &Fact,
    workspace_id: WorkspaceId,
) -> Result<(), String> {
    require_fact_scope(fact, &matchers::workspace_scope(workspace_id))
}

pub(super) fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}
