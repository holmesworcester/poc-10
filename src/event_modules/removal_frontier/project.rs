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

        Ok(ProjectionOutput::new()
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
