//! Integration tests for the `create_workspace` command.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::core::store::Store;
use topo::protocol::facts::identity::workspace::commands::create_workspace;
use topo::protocol::facts::identity::workspace::layout as workspace_layout;

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

    assert_eq!(output.effects.facts.len(), 1, "one workspace fact");
    assert!(output.effects.intents.is_empty());
    assert_eq!(output.receipt.created_at_ms, 60_000);
    assert_eq!(output.receipt.workspace_fact_id, output.effects.facts[0].id);

    let decoded =
        workspace_layout::decode_fact(&output.effects.facts[0].bytes).expect("decode fact");
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
