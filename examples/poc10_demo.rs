//! End-to-end demo of the poc-10 target architecture.
//!
//! This binary drives a workspace + sealed-message scenario through the
//! target `EventBus`, target projectors, and target row tables only. It
//! deliberately does not touch `src/protocol/` or `src/workers/`.
//!
//! Run with: `cargo run --example poc10_demo`

use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_workspace::fact::WorkspaceFact;
use topo::event_modules::identity_workspace::{
    layout as workspace_layout, project as workspace_project, rows as workspace_rows,
};
use topo::event_modules::sealed_message::context::{
    self as message_context, workspace_scope, SecretCoverageMatcher,
};
use topo::event_modules::sealed_message::fact::{
    SealedMessageFact, SecretNodeFact, SignerPubkeyFact, NONCE_BYTES,
};
use topo::event_modules::sealed_message::rows::{
    decode_message_row, decode_sealed_message_row, MESSAGE_ROWS, SEALED_MESSAGE_ROWS,
};
use topo::event_modules::sealed_message::{layout as message_layout, project as message_project};

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

fn main() -> Result<(), String> {
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

    bus.submit_fact(signer_fact);
    bus.submit_fact(message_fact.clone());
    bus.submit_fact(secret_root);
    bus.submit_fact(secret_internal);

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

    let sealed_rows = store
        .table_rows(SEALED_MESSAGE_ROWS)
        .map_err(|err| format!("read sealed rows: {err:?}"))?;
    println!("  sealed_message_rows: {}", sealed_rows.len());
    for (key, value) in &sealed_rows {
        let row = decode_sealed_message_row(key, value)
            .map_err(|err| format!("decode sealed row: {err}"))?;
        println!(
            "    -> message_id={} minute={} ciphertext={:?}",
            hex(&row.message_id),
            row.minute,
            String::from_utf8_lossy(&row.ciphertext)
        );
    }

    let message_rows = store
        .table_rows(MESSAGE_ROWS)
        .map_err(|err| format!("read message rows: {err:?}"))?;
    println!("  message_rows (opened): {}", message_rows.len());
    for (key, value) in &message_rows {
        let row =
            decode_message_row(key, value).map_err(|err| format!("decode message row: {err}"))?;
        println!(
            "    -> message_id={} leaf_id={} minute={}",
            hex(&row.message_id),
            hex(&row.leaf_id),
            row.minute
        );
    }

    println!(
        "\nresult: target EventBus admitted {} fact types, target projectors emitted atomic",
        4
    );
    println!("row intents, target store materialised the workspace row and the sealed message");
    println!("row carrying the original ciphertext. Opening into message_rows requires a leaf-");
    println!("depth secret coverage offer; this demo only seeds an internal-node offer to keep");
    println!("the trace short. No legacy code path was used.");
    Ok(())
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
