//! Poc-10 workspace projector.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;

use super::layout;
use super::rows::workspace_row;

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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("workspace fact must have global scope".to_string());
        }
        let workspace = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::workspace_offer(fact.id))
            .intent(AtomicIntent::PutRow(workspace_row(fact.id, &workspace)?).into_intent()))
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::identity_workspace::fact::WorkspaceFact;
    use topo::event_modules::identity_workspace::{layout, project, rows};

    #[test]
    fn workspace_projector_materializes_row_through_atomic_intent() {
        let workspace = WorkspaceFact {
            created_at_ms: 100,
            public_key: [3; 32],
            name: "Research".to_string(),
        };
        let fact = Fact::new(
            FactScope::Global,
            workspace.created_at_ms,
            layout::encode_fact(&workspace).expect("encode workspace"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::WorkspaceProjector::new(),
                &[],
                &store,
                &[rows::WORKSPACE_ROWS],
                10,
            )
            .expect("project workspace");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 1);
        assert!(bus.intents().is_empty());
        let rows = store
            .table_rows(rows::WORKSPACE_ROWS)
            .expect("workspace rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, fact.id);
        assert_eq!(
            rows::decode_workspace_row(&rows[0].0, &rows[0].1)
                .expect("decode row")
                .name,
            "Research"
        );

        assert!(!bus.submit_fact(fact));
        let duplicate = bus
            .drain_applying_atomic_rows(
                &project::WorkspaceProjector::new(),
                &[],
                &store,
                &[rows::WORKSPACE_ROWS],
                10,
            )
            .expect("duplicate drain");
        assert_eq!(duplicate.projections, 0);
        assert!(bus.intents().is_empty());
    }
}
