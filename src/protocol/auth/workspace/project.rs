//! Poc-10 workspace projector.
//!
//! POLICY. A workspace fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global and the workspace payload decodes.
//!   2. CONTEXT. A retained local invite_accepted fact must select this
//!      workspace and publish accepted-workspace context.
//!   3. MATERIALIZE. Write the workspace row, publish workspace context, and
//!      mark the workspace fact shareable.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::auth::invite_accepted;
use crate::protocol::sync::shared_fact::project::share_fact_with_sync;

/// Staged read pipeline for the workspace fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::workspace::decode::Codec",
    authenticate: "auth::workspace::authenticate::WorkspaceAuthenticator",
    adapt: "auth::workspace::adapt::WorkspaceAdapter",
    project: "auth::workspace::project::WorkspaceProjector",
};

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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("workspace fact must have global scope".to_string());
        }
        // 2. Context.
        let accepted_need = invite_accepted::workspace_accepted_need(fact.id, fact.id);
        let Some(accepted_fact) =
            _context.payload_for_checked(&accepted_need, "workspace accepted")?
        else {
            return Ok(ProjectionOutput::new().need(accepted_need));
        };
        let accepted = invite_accepted::decode_fact_payload(accepted_fact.body())
            .map_err(|_| "workspace accepted context is not invite_accepted".to_string())?;
        if accepted.workspace_id != fact.id {
            return Err("workspace accepted context points to a different workspace".to_string());
        }

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(accepted_need.clone())
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
    use crate::core::context::{ContextNeed, ContextOffer};
    use crate::core::pipeline::MatchedContext;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::workspace::{author, encode, queries};
    use crate::protocol::auth::{invite, invite_accepted};
    use std::collections::BTreeSet;

    #[test]
    fn workspace_projector_waits_for_accepted_workspace_context() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let projected = WorkspaceProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project workspace without context");

        assert!(projected.effects.row_mutations.is_empty());
        assert!(projected.offers.is_empty());
        assert_eq!(projected.needs.len(), 1);
        assert_eq!(
            projected.needs[0],
            invite_accepted::workspace_accepted_need(fact.id, fact.id)
        );
    }

    #[test]
    fn workspace_projector_emits_sync_share_contribution_after_acceptance() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let accepted = accepted_fact(fact.id, fact.id, 124_000);
        let projected = WorkspaceProjector::new()
            .project(&fact, &accepted_context(fact.id, &accepted))
            .expect("project workspace");

        let intent_kinds = projected
            .effects
            .intents
            .iter()
            .map(|intent| intent.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(intent_kinds, BTreeSet::from(["share_fact_with_sync"]));
        assert!(projected
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "auth_workspace"));
    }

    #[test]
    fn workspace_projector_rejects_mismatched_accepted_payload() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let accepted = accepted_fact([8; 32], [8; 32], 124_000);
        let err = WorkspaceProjector::new()
            .project(&fact, &accepted_context(fact.id, &accepted))
            .expect_err("mismatched accepted workspace must reject");

        assert!(err.contains("different workspace"), "{err}");
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

    fn accepted_fact(
        workspace_id: crate::core::facts::FactId,
        invite_fact_id: crate::core::facts::FactId,
        created_at_ms: u64,
    ) -> Fact {
        let (_accepted, accepted_fact) = invite_accepted::author::accepted_fact(
            workspace_id,
            invite_fact_id,
            invite::fact::bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [5; 32],
            [6; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            true,
            created_at_ms + 1,
        )
        .expect("accepted fact");
        accepted_fact
    }

    fn accepted_context(
        workspace_id: crate::core::facts::FactId,
        accepted: &Fact,
    ) -> ProjectionContext {
        let need: ContextNeed =
            invite_accepted::workspace_accepted_need(workspace_id, workspace_id);
        let offer: ContextOffer =
            invite_accepted::workspace_accepted_offer(accepted.id, workspace_id);
        ProjectionContext::from_matches(vec![MatchedContext {
            need,
            offer,
            payload: accepted.clone(),
        }])
    }
}
