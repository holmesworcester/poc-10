//! Integration tests for the `send_message` command.
//!
//! The tests build the projected local identity/key state a real command sees,
//! drive the command directly with `Db` plus a fixed clock, and assert: (1)
//! the happy path produces a message fact plus signature evidence and a
//! receipt, (2) blank or empty text is rejected, (3) the produced fact is a
//! `content_message` fact whose ciphertext decrypts back to the original
//! plaintext under the workspace key queried from the store.

use std::cell::Cell;

use topo::core::command::{CommandClock, WorkspaceId};
use topo::core::crypto;
use topo::core::daemon::{self, RuntimeTurnHost};
use topo::core::db::Db;
use topo::core::runtime::Runtime;
use topo::protocol::app::{MATCH_PROTOCOL, MATCH_RUNTIME};
use topo::protocol::auth::key_wrap::api::{create_key_frontier, CreateKeyFrontier};
use topo::protocol::auth::workspace::api::{create_workspace_with_identity, BootstrapIdentity};
use topo::protocol::content::message::api::{local_encryption_capability, send_message};
use topo::protocol::content::message::encode::associated_data;
use topo::protocol::content::message::project::decode::{decode_fact, recover_text};

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

fn drain_runtime_work_for_test(runtime: &mut Runtime, max_rounds: usize, limit: usize) {
    for _ in 0..max_rounds {
        runtime
            .drain_durable_projection(limit)
            .expect("drain durable projection batch");
        runtime
            .drain_incoming_projection(limit)
            .expect("drain incoming projection batch");
        runtime
            .drain_durable_intents(limit)
            .expect("drain durable intent batch");
        runtime
            .drain_local_intents(limit)
            .expect("drain local intent batch");
        if runtime.pending_projection_count() == 0 && runtime.pending_intent_count() == 0 {
            return;
        }
    }
    panic!("runtime work did not become idle within {max_rounds} rounds");
}

fn initialize_runtime_for_test(runtime: &mut Runtime) {
    let mut scheduler = daemon::RecurringScheduler::install(MATCH_RUNTIME.handlers, 0);
    daemon::runtime_turn(
        MATCH_PROTOCOL.daemon,
        runtime,
        RuntimeTurnHost::local(),
        &mut scheduler,
        4096,
    )
    .expect("initialize runtime through local turn");
}

fn open_store() -> Db {
    Db::open_memory().expect("open memory store")
}

fn runtime_with_workspace_and_key() -> (Runtime, WorkspaceId) {
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
    initialize_runtime_for_test(&mut runtime);
    let workspace_clock = FixedClock::new(1_000);
    let workspace = create_workspace_with_identity(
        runtime.db(),
        &workspace_clock,
        "Research",
        BootstrapIdentity {
            username: "alice",
            device_name: "alice-laptop",
            ttl_minutes: Some(0),
        },
    )
    .expect("workspace command");
    let workspace_id = workspace.receipt.workspace_fact_id;
    runtime
        .submit_authored_facts(workspace)
        .expect("submit workspace");
    drain_runtime_work_for_test(&mut runtime, 8, 512);
    let frontier = create_key_frontier(
        runtime.db(),
        CreateKeyFrontier {
            created_at_ms: 2_000,
            workspace_id,
        },
    )
    .expect("frontier command");
    runtime
        .submit_authored_facts(frontier)
        .expect("submit frontier");
    drain_runtime_work_for_test(&mut runtime, 8, 512);
    (runtime, workspace_id)
}

#[test]
fn send_message_happy_path_emits_message_and_signature_facts() {
    let (runtime, workspace_id) = runtime_with_workspace_and_key();
    let clock = FixedClock::new(60_000);

    let output = send_message(runtime.db(), &clock, workspace_id, "hello, target tree")
        .expect("happy path send_message");

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
    let clock = FixedClock::new(60_000);

    let err = send_message(&store, &clock, workspace_id, "").expect_err("empty text must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");

    let err =
        send_message(&store, &clock, workspace_id, "   \t\n").expect_err("whitespace must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");
}

#[test]
fn send_message_fact_round_trips_through_decode_content_message() {
    let (runtime, workspace_id) = runtime_with_workspace_and_key();
    let clock = FixedClock::new(120_000);

    let text = "round-trip me through decode_fact";
    let output = send_message(runtime.db(), &clock, workspace_id, text).expect("send_message");

    assert_eq!(output.facts.len(), 2, "message plus signature proof");
    let message = decode_fact(&output.facts[0].bytes).expect("decode content message");
    let signature =
        topo::protocol::auth::signature::project::decode::decode_fact(&output.facts[1].bytes)
            .expect("decode signature evidence");
    assert_eq!(signature.target_fact_id, output.facts[0].id);

    // Recover the plaintext using the same workspace key the command queried.
    let encryption = local_encryption_capability(runtime.db(), workspace_id)
        .expect("store encryption capability");
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
