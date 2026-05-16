//! Poc-10 removal frontier projector.
//!
//! Decodes the workspace-scoped fact body, validates fact metadata against the
//! payload, waits for validated admin/removal-ref context, and only then emits
//! the row plus a frontier context offer.

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_admin;
use crate::event_modules::identity_matchers;
use crate::event_modules::sync;

use super::layout;
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
        let frontier = layout::decode_fact(&fact.bytes)?;
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

        let authority_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::admin_role(),
            frontier.authority_admin_id,
        );
        let ref_needs = frontier
            .removal_fact_ids
            .iter()
            .copied()
            .map(|ref_id| sync::matchers::exact_event_need(fact.id, expected_scope.clone(), ref_id))
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

        Ok(waiting
            .offer(sync::matchers::exact_event_offer(
                fact.id,
                expected_scope,
                fact.id,
                fact.id,
            ))
            .intent(AtomicIntent::PutRow(removal_frontier_row(fact.id, &frontier)?).into_intent()))
    }
}

fn validate_authority(
    authority: &Fact,
    frontier: &super::fact::RemovalFrontierFact,
) -> Result<(), String> {
    if authority.id != frontier.authority_admin_id {
        return Err("removal frontier authority context payload id mismatch".to_string());
    }
    let admin = identity_admin::layout::decode_fact(&authority.bytes)
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
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::event_modules::identity_admin::fact::AdminFact;
    use topo::event_modules::identity_admin::layout as admin_layout;
    use topo::event_modules::identity_matchers;
    use topo::event_modules::removal_frontier::fact::RemovalFrontierFact;
    use topo::event_modules::removal_frontier::{layout, project, rows};
    use topo::event_modules::sync::matchers as sync_matchers;

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
                identity_matchers::exact_need(fact.id, identity_matchers::admin_role(), admin.id),
                identity_matchers::exact_offer(admin.id, identity_matchers::admin_role()),
                admin.clone(),
            ),
            matched(
                sync_matchers::exact_event_need(
                    fact.id,
                    workspace_scope(frontier.workspace_id),
                    ref_a.id,
                ),
                sync_matchers::exact_event_offer(
                    ref_a.id,
                    workspace_scope(frontier.workspace_id),
                    ref_a.id,
                    ref_a.id,
                ),
                ref_a.clone(),
            ),
            matched(
                sync_matchers::exact_event_need(
                    fact.id,
                    workspace_scope(frontier.workspace_id),
                    ref_b.id,
                ),
                sync_matchers::exact_event_offer(
                    ref_b.id,
                    workspace_scope(frontier.workspace_id),
                    ref_b.id,
                    ref_b.id,
                ),
                ref_b.clone(),
            ),
        ]);
        let projected = projector
            .project(&fact, &context)
            .expect("matched context projects");
        assert_eq!(projected.intents.len(), 1);
        assert_eq!(projected.offers.len(), 1);

        let row = decode_single_put_row(&projected.intents[0]);
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
            admin_layout::encode_fact(&AdminFact {
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

    fn decode_single_put_row(intent: &topo::core::intents::Intent) -> rows::RemovalFrontierRow {
        match AtomicIntent::from_intent(intent, &[rows::REMOVAL_FRONTIER_ROWS]).expect("row intent")
        {
            AtomicIntent::PutRow(row) => {
                rows::decode_removal_frontier_row(&row.key, &row.value).expect("decode row")
            }
            AtomicIntent::DeleteRow(_) => panic!("expected put row"),
        }
    }
}
