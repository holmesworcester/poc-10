//! End-to-end demo of the poc-10 target architecture.
//!
//! This binary drives a workspace + sealed-message scenario through the
//! target `EventBus`, target projectors, and target row tables only. It
//! deliberately does not touch `src/protocol/` or `src/workers/`.
//!
//! Run with: `cargo run --example poc10_demo`

use crate::commands::context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use crate::commands::send_message::{associated_data, recover_text, send_message};
use crate::core::crypto;
use crate::core::event_bus::EventBus;
use crate::core::facts::{Fact, FactScope};
use crate::core::handler_dispatch::{HandlerContext, RowIntentHandler};
use crate::core::intents::AtomicIntent;
use crate::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use crate::core::store::Store;
use crate::event_modules::encryption::fact::LocalKeySecretFact;
use crate::event_modules::identity_workspace::fact::WorkspaceFact;
use crate::event_modules::identity_workspace::{
    layout as workspace_layout, project as workspace_project, rows as workspace_rows,
};
use crate::event_modules::sealed_message::context::{
    self as message_context, workspace_scope, SecretCoverageMatcher,
};
use crate::event_modules::sealed_message::fact::{
    SealedMessageFact, SecretNodeFact, SignerPubkeyFact, NONCE_BYTES,
};
use crate::event_modules::sealed_message::layout::decode_sealed_message;
use crate::event_modules::sealed_message::rows::{
    decode_message_row, decode_sealed_message_row, message_row, MessageRow, MESSAGE_ROWS,
    SEALED_MESSAGE_ROWS,
};
use crate::event_modules::sealed_message::{layout as message_layout, project as message_project};
use crate::event_modules::signed_fact::fact::LocalSignerSecretFact;
use crate::event_modules::signed_fact::layout::decode_signed_fact;

fn header(step: usize, title: &str) {
    println!("\n=== step {step}: {title} ===");
}

struct DemoProjector;

impl Projector for DemoProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(message_layout::TYPE_SEALED_MESSAGE)
            | Some(message_layout::TYPE_SIGNER_PUBKEY)
            | Some(message_layout::TYPE_MESSAGE_DELETION)
            | Some(message_layout::TYPE_SECRET_NODE) => {
                message_project::SealedMessageProjector::new().project(fact, context)
            }
            _ => workspace_project::WorkspaceProjector::new().project(fact, context),
        }
    }
}

pub fn run() -> Result<(), String> {
    println!("poc-10 target architecture end-to-end demo");
    println!("------------------------------------------");
    println!("Driving facts through: target EventBus -> target projectors -> target row tables.");
    println!("No src/protocol/ or src/workers/ code is invoked.");

    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .map_err(|err| format!("open store: {err:?}"))?;
    let mut bus = EventBus::new();

    let workspace_id: [u8; 32] = [7; 32];
    let signer_id: [u8; 32] = [8; 32];
    let frontier_id: [u8; 32] = [9; 32];
    let minute: u64 = 42;
    let leaf_id: [u8; 32] = [0b1010_1111; 32];

    header(1, "admit workspace fact");
    let workspace = WorkspaceFact {
        created_at_ms: 100,
        public_key: [3; 32],
        name: "Research".to_string(),
    };
    let workspace_fact = Fact::new(
        FactScope::Global,
        workspace.created_at_ms,
        workspace_layout::encode_fact(&workspace).expect("encode workspace"),
    );
    println!("  workspace fact id: {}", hex(&workspace_fact.id));
    bus.submit_fact(workspace_fact.clone());

    let report = bus
        .drain_applying_atomic_rows(
            &workspace_project::WorkspaceProjector::new(),
            &[],
            &store,
            &[workspace_rows::WORKSPACE_ROWS],
            10,
        )
        .map_err(|err| format!("workspace drain: {err}"))?;
    println!(
        "  drain: projections={} intents={}",
        report.projections, report.intents
    );

    let rows = store
        .table_rows(workspace_rows::WORKSPACE_ROWS)
        .map_err(|err| format!("read workspace rows: {err:?}"))?;
    println!("  workspace_rows materialised: {}", rows.len());
    for (key, value) in &rows {
        let row = workspace_rows::decode_workspace_row(key, value)
            .map_err(|err| format!("decode workspace row: {err}"))?;
        println!(
            "    -> name={:?} public_key={}",
            row.name,
            hex(&row.public_key)
        );
    }

    header(2, "admit signer + sealed message + secret coverage");
    let signer_fact = Fact::new(
        workspace_scope(workspace_id),
        1,
        message_layout::encode_signer_pubkey(&SignerPubkeyFact {
            signer_id,
            public_key: [5; 32],
        })
        .expect("encode signer"),
    );

    let message = SealedMessageFact {
        workspace_id,
        created_at_ms: minute * 60_000,
        author_user_id: [6; 32],
        signer_id,
        frontier_id,
        local_history_node_secret_id: [10; 32],
        expires_at_minute: u64::MAX,
        disappearing_setting_id: [11; 32],
        minute,
        leaf_id,
        nonce: [12; NONCE_BYTES],
        ciphertext: b"hello, poc-10!".to_vec(),
    };
    let message_fact = Fact::new(
        workspace_scope(workspace_id),
        minute,
        message_layout::encode_sealed_message(&message).expect("encode message"),
    );
    println!("  signer fact id : {}", hex(&signer_fact.id));
    println!("  message fact id: {}", hex(&message_fact.id));

    let secret_root = Fact::new(
        workspace_scope(workspace_id),
        0,
        message_layout::encode_secret_node(&SecretNodeFact {
            workspace_id,
            frontier_id,
            start_minute: 0,
            end_minute: 99,
            prefix_bytes: 0,
            leaf_prefix: [0; 32],
        })
        .expect("encode secret root"),
    );
    let mut prefix = [0; 32];
    prefix[0] = leaf_id[0];
    let secret_internal = Fact::new(
        workspace_scope(workspace_id),
        40,
        message_layout::encode_secret_node(&SecretNodeFact {
            workspace_id,
            frontier_id,
            start_minute: 40,
            end_minute: 50,
            prefix_bytes: 1,
            leaf_prefix: prefix,
        })
        .expect("encode secret internal"),
    );

    // A leaf-depth node covers exactly this message's (frontier, minute, leaf_id) triple.
    // prefix_bytes=32 means the full 32-byte leaf_id must match, satisfying has_secret.
    let secret_leaf = Fact::new(
        workspace_scope(workspace_id),
        minute,
        message_layout::encode_secret_node(&SecretNodeFact {
            workspace_id,
            frontier_id,
            start_minute: minute,
            end_minute: minute,
            prefix_bytes: 32,
            leaf_prefix: leaf_id,
        })
        .expect("encode secret leaf"),
    );

    bus.submit_fact(signer_fact);
    bus.submit_fact(message_fact.clone());
    bus.submit_fact(secret_root);
    bus.submit_fact(secret_internal);
    bus.submit_fact(secret_leaf);

    let signer_matcher = ExactSelectorMatcher::new(message_context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(message_context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers: [&dyn ContextMatcher; 3] = [&signer_matcher, &deletion_matcher, &secret_matcher];

    let drain = bus
        .drain_applying_atomic_rows(
            &DemoProjector,
            &matchers,
            &store,
            &[SEALED_MESSAGE_ROWS, MESSAGE_ROWS],
            32,
        )
        .map_err(|err| format!("message drain: {err}"))?;
    println!(
        "  drain: projections={} intents={} wakes={}",
        drain.projections, drain.intents, drain.wakes
    );

    {
        let sealed_rows_peek = store
            .table_rows(SEALED_MESSAGE_ROWS)
            .map_err(|err| format!("read sealed rows: {err:?}"))?;
        println!("  sealed_message_rows: {}", sealed_rows_peek.len());
        for (key, value) in &sealed_rows_peek {
            let row = decode_sealed_message_row(key, value)
                .map_err(|err| format!("decode sealed row: {err}"))?;
            println!(
                "    -> message_id={} minute={} ciphertext={:?}",
                hex(&row.message_id),
                row.minute,
                String::from_utf8_lossy(&row.ciphertext)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: open the sealed message into message_rows.
    //
    // The SealedMessageProjector never emits a message_row PutRow intent
    // directly. In the production path the `unwrap_key_wrap` worker receives
    // a MaterializeKeyWraps intent, performs actual Curve25519 ECDH + XChaCha20
    // decryption using the local recipient's private key, and then emits the
    // MessageRow. The projector only handles the structural context (signer,
    // secret-coverage, deletion); it does not hold the private key material
    // needed to produce plaintext.
    //
    // With all three context pieces satisfied (signer + leaf-depth secret
    // coverage + no deletion), the message reaches the "has_signer && has_secret"
    // branch and the projector emits only a deletion_need. The actual
    // MESSAGE_ROWS put must come from the decryption handler.
    //
    // To keep this demo end-to-end without real crypto we synthesise the
    // MessageRow from the sealed_message_row we just read, mirroring exactly
    // what the decryption worker would write after a successful AEAD open.
    header(3, "open sealed message into message_rows");
    let sealed_rows = store
        .table_rows(SEALED_MESSAGE_ROWS)
        .map_err(|err| format!("read sealed rows for open: {err:?}"))?;
    println!("  sealed_message_rows available: {}", sealed_rows.len());
    for (key, value) in &sealed_rows {
        let sealed = decode_sealed_message_row(key, value)
            .map_err(|err| format!("decode sealed row: {err}"))?;
        // Synthesise the MessageRow that the decryption worker would produce.
        // In production this step requires ECDH + XChaCha20-Poly1305 to verify
        // the ciphertext; here we trust the test fixture and emit the row
        // directly as the worker would via submit_intent + dispatch_intents.
        let opened = message_row(MessageRow {
            workspace_id: sealed.workspace_id,
            message_id: sealed.message_id,
            created_at_ms: sealed.created_at_ms,
            author_user_id: sealed.author_user_id,
            signer_id: sealed.signer_id,
            minute: sealed.minute,
            leaf_id: sealed.leaf_id,
        });
        bus.submit_intent(AtomicIntent::PutRow(opened).into_intent())
            .map_err(|err| format!("submit message row intent: {err}"))?;
    }
    let row_handler = RowIntentHandler::new(&store, &[MESSAGE_ROWS]);
    let open_report = bus
        .dispatch_intents(&row_handler, &HandlerContext::new(), 32)
        .map_err(|err| format!("dispatch message row intents: {err}"))?;
    println!("  dispatch: handled={}", open_report.handled);

    let message_rows_read = store
        .table_rows(MESSAGE_ROWS)
        .map_err(|err| format!("read message rows: {err:?}"))?;
    println!("  message_rows (opened): {}", message_rows_read.len());
    for (key, value) in &message_rows_read {
        let row =
            decode_message_row(key, value).map_err(|err| format!("decode message row: {err}"))?;
        println!(
            "    -> message_id={} leaf_id={} minute={} author={}",
            hex(&row.message_id),
            hex(&row.leaf_id),
            row.minute,
            hex(&row.author_user_id),
        );
    }

    // -----------------------------------------------------------------------
    // Step 4: produce a fact through the commands lane (`send_message`)
    // using a narrow CommandContext that cannot reach workers or registries.
    // -----------------------------------------------------------------------
    header(4, "send_message through CommandContext");
    let cmd_workspace: WorkspaceId = [42; 32];
    let vault = DemoVault::seeded(cmd_workspace);
    let clock = DemoClock::starting_at(2 * 60_000);
    let cmd_ctx = CommandContext::new(&store, &clock, &vault);
    let output = send_message(&cmd_ctx, cmd_workspace, "via CommandContext")
        .map_err(|err| format!("send_message: {err}"))?;
    let fact = &output.facts[0];
    let envelope =
        decode_signed_fact(&fact.bytes).map_err(|err| format!("decode envelope: {err}"))?;
    let sealed = decode_sealed_message(&envelope.payload)
        .map_err(|err| format!("decode inner sealed message: {err}"))?;
    let recovered = {
        let cap = vault
            .local_encryption_capability(cmd_workspace)
            .map_err(|err| format!("vault enc: {err}"))?;
        let plaintext = crypto::xchacha20poly1305_decrypt(
            &cap.fact.key_secret,
            &associated_data(cmd_workspace, sealed.frontier_id, sealed.minute),
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .map_err(|err| format!("decrypt: {err:?}"))?;
        recover_text(&plaintext).map_err(|err| format!("recover: {err}"))?
    };
    println!(
        "  send_message produced {} fact(s), {} intent(s)",
        output.facts.len(),
        output.intents.len()
    );
    println!(
        "    -> message_fact_id={} created_at_ms={} minute={}",
        hex(&output.summary.message_fact_id),
        output.summary.created_at_ms,
        sealed.minute
    );
    println!("    -> recovered plaintext via workspace key: {recovered:?}");
    println!(
        "  note: signed-envelope -> sealed-message dispatch is not yet wired in the target tree."
    );
    println!("  the bus admission for this fact is intentionally skipped here so the demo never");
    println!("  appears to project an envelope through the sealed_message projector.");

    println!("\nresult: target EventBus admitted 6 fact types (workspace + signer + message +",);
    println!("secret-root + secret-internal + secret-leaf), target projectors emitted atomic");
    println!(
        "row intents for sealed_message_rows. The leaf-depth SecretNodeFact (prefix_bytes=32)"
    );
    println!(
        "satisfies has_secret in the projector, reducing the standing needs to deletion only."
    );
    println!("MESSAGE_ROWS materialises when the decryption worker calls submit_intent with a");
    println!("PutRow(message_row(...)) after AEAD-opening the ciphertext; the demo synthesises");
    println!("this intent directly (no private-key material available) and dispatches it via");
    println!("RowIntentHandler. No legacy code path was used.");
    Ok(())
}

struct DemoVault {
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
}

impl DemoVault {
    fn seeded(workspace_id: WorkspaceId) -> Self {
        let signer_private: crypto::Ed25519PrivateKey = [7; 32];
        let signer_public = crypto::ed25519_public_key(&signer_private);
        let signer_id = [11; 32];
        Self {
            signing: LocalSigningCapability {
                fact: LocalSignerSecretFact {
                    workspace_id,
                    signer_id,
                    public_key: signer_public,
                    private_key: signer_private,
                },
            },
            encryption: LocalEncryptionCapability {
                fact: LocalKeySecretFact {
                    workspace_id,
                    frontier_id: [22; 32],
                    owner_endpoint_id: [33; 32],
                    created_at_ms: 1,
                    key_secret: [9; crypto::XCHACHA20_POLY1305_KEY_BYTES],
                },
            },
        }
    }
}

impl IdentityVault for DemoVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        if self.signing.fact.workspace_id != workspace_id {
            return Err("vault has no signing capability for workspace".to_string());
        }
        Ok(self.signing.clone())
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        if self.encryption.fact.workspace_id != workspace_id {
            return Err("vault has no encryption capability for workspace".to_string());
        }
        Ok(self.encryption.clone())
    }
}

struct DemoClock(std::cell::Cell<u64>);

impl DemoClock {
    fn starting_at(start: u64) -> Self {
        Self(std::cell::Cell::new(start))
    }
}

impl CommandClock for DemoClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > 8 {
        out.push_str("..");
    }
    out
}
