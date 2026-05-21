//! Poc-10 removal frontier projector.
//!
//! POLICY. A removal_frontier is admitted iff:
//!   1. STRUCTURAL. The body decodes, the outer scope matches the workspace,
//!      and the authority admin selector is non-zero.
//!   2. AUTHORITY. Projection waits for the admin grant and every referenced
//!      removal fact, all in the same workspace scope.
//!   3. MATERIALIZE. Once validated, write the frontier row, publish exact-fact
//!      context, and share the frontier fact with the workspace.

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::removal_frontier_row;

pub const WORKSPACE_SCOPE_KIND: &str = "workspace";

#[derive(Debug, Clone, Default)]
pub struct RemovalFrontierProjector;

impl RemovalFrontierProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RemovalFrontierProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for RemovalFrontierProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        frontier: super::fact::RemovalFrontierFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let expected_scope = FactScope::Scoped {
            kind: ScopeKind::new(WORKSPACE_SCOPE_KIND).map_err(|err| err.to_string())?,
            id: frontier.workspace_id,
        };
        if fact.scope != expected_scope {
            return Err("removal frontier fact scope does not match workspace_id".to_string());
        }
        if frontier.authority_admin_id == [0; 32] {
            return Err("removal frontier authority_admin_id must not be empty".to_string());
        }

        // 2. Authority and referenced removal context.
        let authority_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::admin_role(),
            frontier.authority_admin_id,
        );
        let ref_needs = frontier
            .removal_fact_ids
            .iter()
            .copied()
            .map(|ref_id| {
                crate::protocol::matchers::exact_fact_need(fact.id, expected_scope.clone(), ref_id)
            })
            .collect::<Vec<_>>();

        let mut waiting = ProjectionOutput::new().need(authority_need.clone());
        for need in &ref_needs {
            waiting = waiting.need(need.clone());
        }

        let Some(authority) = projection_context.payload_for(&authority_need) else {
            return Ok(waiting);
        };
        let ref_matches = ref_needs
            .iter()
            .map(|need| projection_context.payload_for(need))
            .collect::<Option<Vec<_>>>();
        let Some(ref_matches) = ref_matches else {
            return Ok(waiting);
        };

        validate_authority(authority, &frontier)?;
        for (expected_id, removal_ref) in frontier.removal_fact_ids.iter().zip(ref_matches) {
            if removal_ref.id != *expected_id {
                return Err("removal frontier ref context payload id mismatch".to_string());
            }
            if removal_ref.scope != expected_scope {
                return Err("removal frontier ref workspace mismatch".to_string());
            }
        }

        // 3. Materialize.
        Ok(waiting
            .offer(crate::protocol::matchers::exact_fact_offer(
                fact.id,
                expected_scope,
                fact.id,
            ))
            .row_mutation(RowMutation::PutRow(removal_frontier_row(
                fact.id, &frontier,
            )?))
            .intent(share_fact_with_workspace_intent_for_fact(
                frontier.workspace_id,
                fact,
            )))
    }
}

fn validate_authority(
    authority: &Fact,
    frontier: &super::fact::RemovalFrontierFact,
) -> Result<(), String> {
    if authority.id != frontier.authority_admin_id {
        return Err("removal frontier authority context payload id mismatch".to_string());
    }
    let admin = identity::admin::decode_fact_payload(&authority.bytes)
        .map_err(|_| "removal frontier authority context must be an admin fact".to_string())?;
    if admin.workspace_id != frontier.workspace_id {
        return Err("removal frontier authority admin workspace mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope, ScopeKind};
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::facts::identity::admin;
    use topo::protocol::facts::identity::admin::fact::AdminFact;
    use topo::protocol::intents::sync::share_fact_with_workspace;

    use topo::protocol::facts::encryption::removal_frontier::fact::RemovalFrontierFact;
    use topo::protocol::facts::encryption::removal_frontier::{layout, project, rows};
    use topo::protocol::matchers as sync_matchers;

    fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").expect("scope kind"),
            id: workspace_id,
        }
    }

    #[test]
    fn removal_frontier_projector_waits_for_authority_and_refs_then_materializes_row() {
        let admin = admin_fact([1; 32], [7; 32]);
        let ref_a = removal_ref_fact([1; 32], 3);
        let ref_b = removal_ref_fact([1; 32], 4);
        let frontier = RemovalFrontierFact {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            authority_admin_id: admin.id,
            removal_fact_ids: vec![ref_a.id, ref_b.id],
        };
        let fact = Fact::new(
            workspace_scope(frontier.workspace_id),
            frontier.created_at_ms,
            layout::encode_fact(&frontier).expect("encode frontier"),
        );
        let projector = project::RemovalFrontierProjector::new();

        let waiting = projector
            .project(&fact, &ProjectionContext::default())
            .expect("missing context waits");
        assert!(waiting.intents.is_empty());
        assert_eq!(waiting.needs.len(), 3);

        let context = ProjectionContext::from_matches(vec![
            matched(
                crate::protocol::matchers::exact_need(
                    fact.id,
                    crate::protocol::matchers::admin_role(),
                    admin.id,
                ),
                crate::protocol::matchers::exact_offer(
                    admin.id,
                    crate::protocol::matchers::admin_role(),
                ),
                admin.clone(),
            ),
            matched(
                sync_matchers::exact_fact_need(
                    fact.id,
                    workspace_scope(frontier.workspace_id),
                    ref_a.id,
                ),
                sync_matchers::exact_fact_offer(
                    ref_a.id,
                    workspace_scope(frontier.workspace_id),
                    ref_a.id,
                ),
                ref_a.clone(),
            ),
            matched(
                sync_matchers::exact_fact_need(
                    fact.id,
                    workspace_scope(frontier.workspace_id),
                    ref_b.id,
                ),
                sync_matchers::exact_fact_offer(
                    ref_b.id,
                    workspace_scope(frontier.workspace_id),
                    ref_b.id,
                ),
                ref_b.clone(),
            ),
        ]);
        let projected = projector
            .project(&fact, &context)
            .expect("matched context projects");
        assert_eq!(projected.intents.len(), 1);
        assert_eq!(projected.row_mutations.len(), 1);
        assert_eq!(projected.offers.len(), 1);
        assert_share_intent(&projected.intents, frontier.workspace_id, fact.id);

        let row = decode_single_put_row(&projected.row_mutations[0]);
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.removal_frontier_id, fact.id);
        assert_eq!(row.created_at_ms, 1234);
        assert_eq!(row.authority_admin_id, admin.id);
        assert_eq!(row.removal_fact_ids, vec![ref_a.id, ref_b.id]);
    }

    #[test]
    fn removal_frontier_projector_rejects_scope_mismatch() {
        let frontier = RemovalFrontierFact {
            workspace_id: [1; 32],
            created_at_ms: 1,
            authority_admin_id: [2; 32],
            removal_fact_ids: vec![],
        };
        let fact = Fact::new(
            workspace_scope([9; 32]),
            frontier.created_at_ms,
            layout::encode_fact(&frontier).expect("encode frontier"),
        );
        let err = project::RemovalFrontierProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("scope mismatch must fail");
        assert!(err.contains("scope"), "{err}");
    }

    fn admin_fact(workspace_id: [u8; 32], user_fact_id: [u8; 32]) -> Fact {
        Fact::new(
            FactScope::Global,
            1,
            admin::encode_fact_payload(&AdminFact {
                created_at_ms: 1,
                workspace_id,
                public_key: [9; 32],
                authority_fact_id: workspace_id,
                user_fact_id,
            })
            .expect("encode admin"),
        )
    }

    fn removal_ref_fact(workspace_id: [u8; 32], byte: u8) -> Fact {
        Fact::new(workspace_scope(workspace_id), 1, vec![byte; 32])
    }

    fn matched(
        need: topo::core::context::ContextNeed,
        offer: topo::core::context::ContextOffer,
        payload: Fact,
    ) -> MatchedContext {
        MatchedContext {
            need,
            offer,
            payload,
        }
    }

    fn decode_single_put_row(mutation: &RowMutation) -> rows::RemovalFrontierRow {
        match mutation {
            RowMutation::PutRow(row) => {
                rows::decode_removal_frontier_row(&row.key, &row.value).expect("decode row")
            }
            _ => panic!("expected opaque put row"),
        }
    }

    fn assert_share_intent(
        intents: &[topo::core::intents::Intent],
        workspace_id: [u8; 32],
        fact_id: [u8; 32],
    ) {
        let found = intents.iter().any(|intent| {
            if intent.kind.as_str() != "share_fact_with_workspace" {
                return false;
            }
            let Ok(input) = share_fact_with_workspace::decode_share_fact_with_workspace(intent)
            else {
                return false;
            };
            input.workspace_id == workspace_id && input.fact_id == fact_id
        });
        assert!(found, "missing share_fact_with_workspace intent");
    }
}
