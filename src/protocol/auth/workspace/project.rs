//! Poc-10 workspace projector.
//!
//! POLICY. A workspace fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global and the workspace payload decodes.
//!   2. CONTEXT. No authority context is required; the workspace is the root
//!      identity object for later grants.
//!   3. MATERIALIZE. Write the workspace row, publish workspace context, and
//!      mark the workspace fact shareable with itself.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_staged, AuthenticatedFact, AuthenticatedProjector, ProjectionContext, ProjectionOutput,
    Projector, SemanticProjector,
};
use crate::protocol::sync::shared_fact::project::share_fact_with_sync;

#[derive(Debug, Clone, Default)]
pub struct WorkspaceProjector;

impl WorkspaceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for WorkspaceProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::decode::Codec,
            super::authenticate::WorkspaceAuthenticator,
            super::adapt::WorkspaceAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::WorkspaceFact> for WorkspaceProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        workspace: super::fact::WorkspaceFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        self.project_authenticated(AuthenticatedFact::new(fact, workspace), context)
    }
}

impl AuthenticatedProjector<super::authenticate::WorkspaceAuthenticator> for WorkspaceProjector {
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::WorkspaceFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, workspace) = authenticated.into_parts();
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("workspace fact must have global scope".to_string());
        }
        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "auth_workspace",
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::PutRow(super::workspace_row(
                    fact.id, &workspace,
                )?)),
            fact.id,
            fact,
            Vec::new(),
        ))
    }
}

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::protocol::auth::workspace::{author, encode, queries};
    use std::collections::BTreeSet;

    #[test]
    fn workspace_projector_emits_sync_share_contribution() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let projected = WorkspaceProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project workspace");

        let intent_kinds = projected
            .effects
            .intents
            .iter()
            .map(|intent| intent.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(intent_kinds, BTreeSet::from(["share_fact_with_sync"]));
    }

    #[test]
    fn workspace_row_schema_preserves_payload_bytes_and_decodes_fields() {
        let fact = super::super::fact::WorkspaceFact {
            created_at_ms: 42,
            public_key: [7; 32],
            name: super::super::fact::WorkspaceName::new("Engineering").expect("name"),
            signature: [8; crate::core::crypto::ED25519_SIGNATURE_BYTES],
        };

        let row = super::super::workspace_row([9; 32], &fact).expect("workspace row");

        assert_eq!(row.table, super::super::WORKSPACE_ROWS);
        assert_eq!(
            row.value,
            encode::encode_payload(&fact).expect("fact payload bytes")
        );
        let decoded =
            queries::decode_workspace_row(&row.key, &row.value).expect("decode workspace row");
        assert_eq!(decoded.workspace_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 42);
        assert_eq!(decoded.public_key, [7; 32]);
        assert_eq!(decoded.name, "Engineering");
    }
}
