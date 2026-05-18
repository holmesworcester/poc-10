//! Integration tests for the `create_workspace` command.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::identity::workspace::commands::create_workspace;
use topo::protocol::facts::identity::workspace::layout as workspace_layout;
use topo::protocol::facts::identity::workspace::project as workspace_project;
use topo::protocol::facts::identity::workspace::rows as workspace_rows;

struct FixedClock(Cell<u64>);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

struct EmptyVault;

impl IdentityVault for EmptyVault {
    fn local_signing_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        Err("no signing capability".to_string())
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("no encryption capability".to_string())
    }
}

#[test]
fn create_workspace_emits_decodable_workspace_fact() {
    let store = Store::open_memory().expect("store");
    let clock = FixedClock(Cell::new(60_000));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let public_key = [7u8; 32];
    let output = create_workspace(&ctx, public_key, "Research").expect("create_workspace");

    assert_eq!(output.facts.len(), 1, "one workspace fact");
    assert!(output.intents.is_empty());
    assert_eq!(output.receipt.created_at_ms, 60_000);
    assert_eq!(output.receipt.workspace_fact_id, output.facts[0].id);

    let decoded = workspace_layout::decode_fact(&output.facts[0].bytes).expect("decode fact");
    assert_eq!(decoded.public_key, public_key);
    assert_eq!(decoded.name, "Research");
    assert_eq!(decoded.created_at_ms, 60_000);
}

#[test]
fn create_workspace_rejects_blank_or_oversize_name() {
    let store = Store::open_memory().expect("store");
    let clock = FixedClock(Cell::new(0));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let err = create_workspace(&ctx, [0u8; 32], "   ").expect_err("blank name must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");

    let too_long = "a".repeat(200);
    let err = create_workspace(&ctx, [0u8; 32], &too_long).expect_err("long name must reject");
    assert!(err.contains("exceeds"), "{err}");
}

#[test]
fn create_workspace_fact_projects_through_target_bus() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("open store with schema");
    let clock = FixedClock(Cell::new(120_000));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let output = create_workspace(&ctx, [9u8; 32], "Production").expect("create_workspace");
    let fact = output.facts.into_iter().next().expect("one fact");
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact.clone());
    let report = bus
        .drain_applying_atomic_rows(
            &workspace_project::WorkspaceProjector::new(),
            &[],
            &store,
            &[workspace_rows::WORKSPACE_ROWS],
            10,
        )
        .expect("drain");
    assert_eq!(report.projections, 1);
    assert_eq!(report.intents, 2);
    assert_eq!(bus.intents().len(), 1);

    let rows = store
        .table_rows(workspace_rows::WORKSPACE_ROWS)
        .expect("workspace rows");
    assert_eq!(rows.len(), 1);
    let row = workspace_rows::decode_workspace_row(&rows[0].0, &rows[0].1).expect("decode row");
    assert_eq!(row.name, "Production");
    assert_eq!(row.public_key, [9u8; 32]);
}
