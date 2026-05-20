//! Projector for sync encrypted-root offers.
//!
//! POLICY. A sync encrypted_root fact is admitted iff:
//!   1. STRUCTURAL. The body decodes and the outer fact scope matches its
//!      workspace id.
//!   2. CONTEXT. No incoming context is required; this fact advertises a root
//!      summary already produced by local encryption/sync.
//!   3. MATERIALIZE. Publish both range and exact-fact offers that point range
//!      requests at this encrypted-root payload.

use crate::core::facts::{Fact, FactScope};
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::matchers;

use super::fact::WorkspaceId;

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
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for SyncEncryptedRootProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        root: super::fact::EncryptedRootFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = matchers::workspace_scope(root.workspace_id);
        require_fact_scope(fact, &scope)?;
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(matchers::range_fact_offer(
                fact.id,
                scope.clone(),
                fact.timestamp,
                root.fact_id,
                root.dependency_id,
                root.key_wrap_id,
            ))
            .offer(matchers::exact_fact_offer(fact.id, scope, root.fact_id)))
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
