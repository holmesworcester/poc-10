//! Integration tests for the `send_message` command.
//!
//! The tests hand-build a `CommandContext` from a vault and a fixed clock,
//! drive the command, and assert: (1) the happy path produces one fact and a
//! summary, (2) blank or empty text is rejected, (3) the produced fact is a
//! signed envelope whose inner payload decodes through
//! `sealed_message::layout::decode_sealed_message` and whose ciphertext
//! decrypts back to the original plaintext under the workspace key.

use std::cell::Cell;

use topo::commands::context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::commands::send_message::{associated_data, recover_text, send_message};
use topo::core::crypto;
use topo::event_modules::encryption::fact::LocalKeySecretFact;
use topo::event_modules::sealed_message::layout::decode_sealed_message;
use topo::event_modules::signed_fact::fact::LocalSignerSecretFact;
use topo::event_modules::signed_fact::layout::decode_signed_fact;

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
        if capability.fact.workspace_id != workspace_id {
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
        if capability.fact.workspace_id != workspace_id {
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
        fact: LocalSignerSecretFact {
            workspace_id,
            signer_id,
            public_key: signer_public,
            private_key: signer_private,
        },
    };
    let encryption = LocalEncryptionCapability {
        fact: LocalKeySecretFact {
            workspace_id,
            frontier_id: [22; 32],
            owner_endpoint_id: [33; 32],
            created_at_ms: 1,
            key_secret: [9; crypto::XCHACHA20_POLY1305_KEY_BYTES],
        },
    };
    TestVault {
        signing: Some(signing),
        encryption: Some(encryption),
    }
}

#[test]
fn send_message_happy_path_emits_one_sealed_message_fact() {
    let store = topo::core::store::Store::open_memory().expect("open memory store");
    let workspace_id = [1u8; 32];
    let vault = seeded_vault(workspace_id);
    let clock = FixedClock::new(60_000);
    let ctx = CommandContext::new(&store, &clock, &vault);

    let output =
        send_message(&ctx, workspace_id, "hello, target tree").expect("happy path send_message");

    assert_eq!(output.summary.workspace_id, workspace_id);
    assert_eq!(output.summary.created_at_ms, 60_000);
    assert_eq!(output.facts.len(), 1, "one fact per send_message");
    assert!(output.intents.is_empty(), "no intents in the first cut");

    // The fact id is the blake3 of the signed envelope bytes. Peel the
    // envelope to recover the inner sealed-message payload before decoding.
    let envelope = decode_signed_fact(&output.facts[0].bytes).expect("decode signed envelope");
    let sealed = decode_sealed_message(&envelope.payload).expect("decode inner sealed message");
    assert_eq!(sealed.workspace_id, workspace_id);
    assert_eq!(sealed.created_at_ms, 60_000);
    assert_eq!(sealed.minute, 60_000 / 60_000);
}

#[test]
fn send_message_rejects_blank_or_empty_text() {
    let store = topo::core::store::Store::open_memory().expect("open memory store");
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
fn send_message_fact_round_trips_through_decode_sealed_message() {
    let store = topo::core::store::Store::open_memory().expect("open memory store");
    let workspace_id = [42u8; 32];
    let vault = seeded_vault(workspace_id);
    let clock = FixedClock::new(120_000);
    let ctx = CommandContext::new(&store, &clock, &vault);

    let text = "round-trip me through decode_sealed_message";
    let output = send_message(&ctx, workspace_id, text).expect("send_message");

    let envelope = decode_signed_fact(&output.facts[0].bytes).expect("decode signed envelope");
    let sealed = decode_sealed_message(&envelope.payload).expect("decode inner sealed message");

    // Recover the plaintext using the same workspace key the vault handed
    // to the command. The test must not be able to read the key from any
    // back channel: it knows the key because the vault holds it.
    let encryption = vault
        .local_encryption_capability(workspace_id)
        .expect("vault encryption capability");
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &encryption.fact.key_secret,
        &associated_data(workspace_id, sealed.frontier_id, sealed.minute),
        &sealed.nonce,
        &sealed.ciphertext,
    )
    .expect("decrypt sealed ciphertext");

    let recovered = recover_text(&plaintext).expect("recover original text");
    assert_eq!(recovered, text);
}
