//! Command tests for target content deletion constructors.

use std::cell::Cell;

use topo::core::command::{CommandClock, WorkspaceId};
use topo::core::db::Db;
use topo::core::runtime::Runtime;
use topo::protocol::app::MATCH_RUNTIME;
use topo::protocol::auth::signature::project::{
    authenticate as signature_authenticate, decode as signature_decode,
};
use topo::protocol::auth::workspace::api::{create_workspace_with_identity, BootstrapIdentity};
use topo::protocol::content::file_deletion::api::delete_file;
use topo::protocol::content::file_deletion::project::decode as file_deletion_layout_decode;
use topo::protocol::content::message_deletion::api::delete_message;
use topo::protocol::content::message_deletion::project::decode as message_deletion_layout_decode;

struct FixedClock(Cell<u64>);

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
        if runtime.pending_fact_count() == 0 && runtime.pending_intent_count() == 0 {
            return;
        }
    }
    panic!("runtime work did not become idle within {max_rounds} rounds");
}

fn runtime_with_workspace() -> (Runtime, WorkspaceId) {
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
    let clock = FixedClock(Cell::new(1_000));
    let workspace = create_workspace_with_identity(
        runtime.db(),
        &clock,
        "Deletion",
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
    (runtime, workspace_id)
}

#[test]
fn delete_message_emits_decodable_target_fact() {
    let (runtime, workspace_id) = runtime_with_workspace();
    let clock = FixedClock(Cell::new(100));

    let output = delete_message(
        runtime.db(),
        &clock,
        workspace_id,
        [2; 32],
        [7; 32],
        1,
        [3; 32],
    )
    .expect("delete message");

    assert_eq!(output.facts.len(), 2);
    assert_eq!(output.receipt.created_at_ms, 100);
    assert_eq!(output.receipt.deletion_fact_id, output.facts[0].id);

    let decoded = message_deletion_layout_decode::decode_fact(&output.facts[0].bytes)
        .expect("decode deletion");
    let signature =
        signature_decode::decode_fact(&output.facts[1].bytes).expect("decode signature");
    signature_authenticate::prove_signature_evidence(&signature)
        .expect("verify signature evidence");
    assert_eq!(signature.target_fact_id, output.facts[0].id);
    assert_eq!(decoded.workspace_id, workspace_id);
    assert_eq!(decoded.created_at_ms, 100);
    assert_eq!(decoded.target_message_id, [2; 32]);
    assert_eq!(decoded.target_frontier_id, [7; 32]);
    assert_eq!(decoded.target_minute, 1);
    assert_eq!(decoded.author_user_id, [3; 32]);
}

#[test]
fn delete_file_emits_decodable_target_fact() {
    let (runtime, workspace_id) = runtime_with_workspace();
    let clock = FixedClock(Cell::new(200));

    let output =
        delete_file(runtime.db(), &clock, workspace_id, [5; 32], [6; 32]).expect("delete file");

    assert_eq!(output.facts.len(), 2);
    assert_eq!(output.receipt.created_at_ms, 200);
    assert_eq!(output.receipt.deletion_fact_id, output.facts[0].id);

    let decoded =
        file_deletion_layout_decode::decode_fact(&output.facts[0].bytes).expect("decode deletion");
    let signature =
        signature_decode::decode_fact(&output.facts[1].bytes).expect("decode signature");
    signature_authenticate::prove_signature_evidence(&signature)
        .expect("verify signature evidence");
    assert_eq!(signature.target_fact_id, output.facts[0].id);
    assert_eq!(decoded.workspace_id, workspace_id);
    assert_eq!(decoded.created_at_ms, 200);
    assert_eq!(decoded.target_file_id, [5; 32]);
    assert_eq!(decoded.author_user_id, [6; 32]);
}

#[test]
fn deletion_commands_reject_empty_ids() {
    let store = Db::open_memory().expect("store");
    let clock = FixedClock(Cell::new(0));

    let err = delete_message(&store, &clock, [0; 32], [2; 32], [7; 32], 1, [3; 32])
        .expect_err("empty workspace");
    assert!(err.contains("workspace_id"), "{err}");

    let err = delete_file(&store, &clock, [4; 32], [0; 32], [6; 32]).expect_err("empty target");
    assert!(err.contains("target_file_id"), "{err}");
}
