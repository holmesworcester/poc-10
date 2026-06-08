//! Command tests for target content deletion constructors.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::core::crypto;
use topo::core::store::Store;
use topo::protocol::auth::signature::{
    authenticate as signature_authenticate, decode as signature_decode,
};
use topo::protocol::content::file_deletion::commands::delete_file;
use topo::protocol::content::file_deletion::decode as file_deletion_layout_decode;
use topo::protocol::content::message_deletion::commands::delete_message;
use topo::protocol::content::message_deletion::decode as message_deletion_layout_decode;

struct FixedClock(Cell<u64>);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

struct TestVault;

impl IdentityVault for TestVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        let private_key = [9; 32];
        Ok(LocalSigningCapability {
            workspace_id,
            signer_id: [8; 32],
            public_key: crypto::ed25519_public_key(&private_key),
            private_key,
        })
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("no encryption capability".to_string())
    }
}

fn ctx<'a>(store: &'a Store, clock: &'a FixedClock, vault: &'a TestVault) -> CommandContext<'a> {
    CommandContext::new(store, clock, vault)
}

#[test]
fn delete_message_emits_decodable_target_fact() {
    let store = Store::open_memory().expect("store");
    let clock = FixedClock(Cell::new(100));
    let vault = TestVault;
    let ctx = ctx(&store, &clock, &vault);

    let output =
        delete_message(&ctx, [1; 32], [2; 32], [7; 32], 1, [3; 32]).expect("delete message");

    assert_eq!(output.effects.facts.len(), 2);
    assert!(output.effects.intents.is_empty());
    assert_eq!(output.receipt.created_at_ms, 100);
    assert_eq!(output.receipt.deletion_fact_id, output.effects.facts[0].id);

    let decoded = message_deletion_layout_decode::decode_fact(&output.effects.facts[0].bytes)
        .expect("decode deletion");
    let signature =
        signature_decode::decode_fact(&output.effects.facts[1].bytes).expect("decode signature");
    signature_authenticate::verify_signature(&signature).expect("verify signature evidence");
    assert_eq!(signature.target_fact_id, output.effects.facts[0].id);
    assert_eq!(decoded.workspace_id, [1; 32]);
    assert_eq!(decoded.created_at_ms, 100);
    assert_eq!(decoded.target_message_id, [2; 32]);
    assert_eq!(decoded.target_frontier_id, [7; 32]);
    assert_eq!(decoded.target_minute, 1);
    assert_eq!(decoded.author_user_id, [3; 32]);
}

#[test]
fn delete_file_emits_decodable_target_fact() {
    let store = Store::open_memory().expect("store");
    let clock = FixedClock(Cell::new(200));
    let vault = TestVault;
    let ctx = ctx(&store, &clock, &vault);

    let output = delete_file(&ctx, [4; 32], [5; 32], [6; 32]).expect("delete file");

    assert_eq!(output.effects.facts.len(), 2);
    assert!(output.effects.intents.is_empty());
    assert_eq!(output.receipt.created_at_ms, 200);
    assert_eq!(output.receipt.deletion_fact_id, output.effects.facts[0].id);

    let decoded = file_deletion_layout_decode::decode_fact(&output.effects.facts[0].bytes)
        .expect("decode deletion");
    let signature =
        signature_decode::decode_fact(&output.effects.facts[1].bytes).expect("decode signature");
    signature_authenticate::verify_signature(&signature).expect("verify signature evidence");
    assert_eq!(signature.target_fact_id, output.effects.facts[0].id);
    assert_eq!(decoded.workspace_id, [4; 32]);
    assert_eq!(decoded.created_at_ms, 200);
    assert_eq!(decoded.target_file_id, [5; 32]);
    assert_eq!(decoded.author_user_id, [6; 32]);
}

#[test]
fn deletion_commands_reject_empty_ids() {
    let store = Store::open_memory().expect("store");
    let clock = FixedClock(Cell::new(0));
    let vault = TestVault;
    let ctx = ctx(&store, &clock, &vault);

    let err =
        delete_message(&ctx, [0; 32], [2; 32], [7; 32], 1, [3; 32]).expect_err("empty workspace");
    assert!(err.contains("workspace_id"), "{err}");

    let err = delete_file(&ctx, [4; 32], [0; 32], [6; 32]).expect_err("empty target");
    assert!(err.contains("target_file_id"), "{err}");
}
