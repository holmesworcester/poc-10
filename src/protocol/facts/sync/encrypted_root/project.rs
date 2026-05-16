//! Projector for sync encrypted-root offers.

use crate::core::facts::{Fact, FactScope};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::matchers;

use super::fact::WorkspaceId;
use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncEncryptedRootProjector;

impl SyncEncryptedRootProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncEncryptedRootProjector {
    fn project(
        &self,
        fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let root = layout::decode_fact(&fact.bytes)?;
        let scope = matchers::workspace_scope(root.workspace_id);
        require_fact_scope(fact, &scope)?;
        Ok(ProjectionOutput::new()
            .offer(matchers::range_fact_offer(
                fact.id,
                scope.clone(),
                fact.timestamp,
                root.fact_id,
                root.dependency_id,
                root.key_wrap_id,
            ))
            .offer(matchers::exact_fact_offer(
                fact.id,
                scope,
                root.fact_id,
                fact.id,
            )))
    }
}

pub(crate) fn validate_sync_fact_workspace(
    fact: &Fact,
    workspace_id: WorkspaceId,
) -> Result<(), String> {
    require_fact_scope(fact, &matchers::workspace_scope(workspace_id))
}

pub(crate) fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}
