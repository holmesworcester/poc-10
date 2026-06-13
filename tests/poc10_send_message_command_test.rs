//! Integration tests for the `send_message` command.
//!
//! The tests hand-build a `CommandContext` from a vault and a fixed clock,
//! drive the command, and assert: (1) the happy path produces a message fact
//! plus signature evidence and a
//! receipt, (2) blank or empty text is rejected, (3) the produced fact is a
//! `content_message` fact whose ciphertext decrypts back to
//! the original plaintext under the workspace key.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::core::crypto;
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::content::message::commands::send_message;
use topo::protocol::content::message::encode::associated_data;
use topo::protocol::content::message::project::decode::{decode_fact, recover_text};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

struct FixedClock(Cell<u64>);

impl FixedClock {
    fn new(start: u64) -> Self {
        Self(Cell::new(start))
    }
}

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

/// A test-only vault. Production code wires the identity-owned vault here.
struct TestVault {
    signing: Option<LocalSigningCapability>,
    encryption: Option<LocalEncryptionCapability>,
}

impl IdentityVault for TestVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        let capability = self
            .signing
            .clone()
            .ok_or_else(|| "no signing capability".to_string())?;
        if capability.workspace_id != workspace_id {
            return Err("vault has no signing capability for workspace".to_string());
        }
        Ok(capability)
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        let capability = self
            .encryption
            .clone()
            .ok_or_else(|| "no encryption capability".to_string())?;
        if capability.workspace_id != workspace_id {
            return Err("vault has no encryption capability for workspace".to_string());
        }
        Ok(capability)
    }
}

fn seeded_vault(workspace_id: WorkspaceId) -> TestVault {
    // The private key bytes are deterministic test fixtures, not random
    // material. The command never sees them except through the vault.
    let signer_private: crypto::Ed25519PrivateKey = [7; 32];
    let signer_public = crypto::ed25519_public_key(&signer_private);
    let signer_id = [11; 32];

    let signing = LocalSigningCapability {
        workspace_id,
        signer_id,
        public_key: signer_public,
        private_key: signer_private,
    };
    let encryption = LocalEncryptionCapability {
        workspace_id,
        frontier_id: [22; 32],
        owner_endpoint_id: [33; 32],
        created_at_ms: 1,
        key_secret: [9; crypto::XCHACHA20_POLY1305_KEY_BYTES],
    };
    TestVault {
        signing: Some(signing),
        encryption: Some(encryption),
    }
}

fn open_store() -> Store {
    Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("open protocol memory store")
}

#[test]
fn send_message_happy_path_emits_message_and_signature_facts() {
    let store = open_store();
    let workspace_id = [1u8; 32];
    let vault = seeded_vault(workspace_id);
    let clock = FixedClock::new(60_000);
    let ctx = CommandContext::new(&store, &clock, &vault);

    let output =
        send_message(&ctx, workspace_id, "hello, target tree").expect("happy path send_message");

    assert_eq!(output.receipt.workspace_id, workspace_id);
    assert_eq!(output.receipt.created_at_ms, 60_000);
    assert_eq!(output.facts.len(), 2, "message plus signature proof");

    let message = decode_fact(&output.facts[0].bytes).expect("decode content message");
    let signature =
        topo::protocol::auth::signature::project::decode::decode_fact(&output.facts[1].bytes)
            .expect("decode signature evidence");
    topo::protocol::auth::signature::project::authenticate::prove_signature_evidence(&signature)
        .expect("verify signature evidence");
    assert_eq!(signature.target_fact_id, output.facts[0].id);
    assert_eq!(signature.signer_public_key, message.signer_public_key);
    assert_eq!(message.workspace_id, workspace_id);
    assert_eq!(message.created_at_ms, 60_000);
    assert_eq!(message.minute, 60_000 / 60_000);
}

#[test]
fn send_message_rejects_blank_or_empty_text() {
    let store = open_store();
    let workspace_id = [1u8; 32];
    let vault = seeded_vault(workspace_id);
    let clock = FixedClock::new(60_000);
    let ctx = CommandContext::new(&store, &clock, &vault);

    let err = send_message(&ctx, workspace_id, "").expect_err("empty text must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");

    let err = send_message(&ctx, workspace_id, "   \t\n").expect_err("whitespace must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");
}

#[test]
fn send_message_fact_round_trips_through_decode_content_message() {
    let store = open_store();
    let workspace_id = [42u8; 32];
    let vault = seeded_vault(workspace_id);
    let clock = FixedClock::new(120_000);
    let ctx = CommandContext::new(&store, &clock, &vault);

    let text = "round-trip me through decode_fact";
    let output = send_message(&ctx, workspace_id, text).expect("send_message");

    assert_eq!(output.facts.len(), 2, "message plus signature proof");
    let message = decode_fact(&output.facts[0].bytes).expect("decode content message");
    let signature =
        topo::protocol::auth::signature::project::decode::decode_fact(&output.facts[1].bytes)
            .expect("decode signature evidence");
    assert_eq!(signature.target_fact_id, output.facts[0].id);

    // Recover the plaintext using the same workspace key the vault handed
    // to the command. The test must not be able to read the key from any
    // back channel: it knows the key because the vault holds it.
    let encryption = vault
        .local_encryption_capability(workspace_id)
        .expect("vault encryption capability");
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &encryption.key_secret,
        &associated_data(workspace_id, message.frontier_id, message.minute),
        &message.nonce,
        &message.ciphertext,
    )
    .expect("decrypt sealed ciphertext");

    let recovered = recover_text(&plaintext).expect("recover original text");
    assert_eq!(recovered, text);
}
