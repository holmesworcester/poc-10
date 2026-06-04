//! Integration tests for the `create_workspace` command.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::workspace::commands::{
    create_workspace_with_identity, BootstrapIdentity,
};
use topo::protocol::auth::workspace::{
    authenticate as workspace_authenticate, decode as workspace_decode,
};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

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
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    let clock = FixedClock(Cell::new(60_000));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let output = create_workspace_with_identity(
        &ctx,
        "Research",
        BootstrapIdentity {
            username: "alice",
            device_name: "alice-laptop",
            ttl_minutes: Some(0),
        },
    )
    .expect("create_workspace");

    assert!(output.effects.intents.is_empty());
    assert_eq!(output.receipt.created_at_ms, 60_000);

    let workspace_fact = output
        .effects
        .facts
        .iter()
        .find(|fact| fact.id == output.receipt.workspace_fact_id)
        .expect("workspace fact emitted");
    let decoded = workspace_decode::decode_fact(&workspace_fact.bytes).expect("decode fact");
    workspace_authenticate::verify_signature(&decoded).expect("workspace signature");
    assert_eq!(decoded.name, "Research");
    assert_eq!(decoded.created_at_ms, 60_000);
}

#[test]
fn create_workspace_rejects_blank_or_oversize_name() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    let clock = FixedClock(Cell::new(0));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let identity = BootstrapIdentity {
        username: "alice",
        device_name: "alice-laptop",
        ttl_minutes: Some(0),
    };
    let err = create_workspace_with_identity(&ctx, "   ", identity.clone())
        .expect_err("blank name must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");

    let too_long = "a".repeat(200);
    let err = create_workspace_with_identity(&ctx, &too_long, identity)
        .expect_err("long name must reject");
    assert!(err.contains("exceeds"), "{err}");
}
