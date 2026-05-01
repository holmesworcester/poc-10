//! # Minimal-viable daemon integration test
//!
//! Exercises the substrate end-to-end in a single process:
//!
//! 1. Boot a [`ControlLoopRuntime`] (transport bridge + dispatcher).
//! 2. Drive `create-workspace` via [`emit_local_event_with_wake`] —
//!    write a `local_event_intents` row + admit into `events_canonical`
//!    at status `ready`, wake the dispatcher, poll until applied.
//! 3. Drive `send` (Message event) the same way against the workspace
//!    just created. Poll until applied.
//! 4. Query the `messages` projection table to confirm the row landed.
//! 5. Assert `events_canonical` has both rows at status `applied`.
//!
//! This is the new substrate path: no legacy peering, no
//! `create_workspace_for_db`. The CLI subcommand handlers in
//! `src/bin/topo/main.rs` use the same helper module
//! ([`topo::local_intents`]) — this test demonstrates the flow at the
//! library-call layer so the CLI process boundary is not on the
//! critical path of the assertion.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use topo::event_modules::{MessageEvent, ParsedEvent, WorkspaceEvent};
use topo::local_intents::{emit_local_event_with_wake, wait_for_terminal};
use topo::runtime::control_loop::ControlLoopRuntime;
use topo::state::events_canonical::{self, EventScope, EventStatus};

const ENDPOINT: [u8; 32] = [0x77; 32];

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_minimal_create_workspace_and_send_message_via_local_intents() {
    let dir = tmpdir();
    let db_path = dir.path().join("daemon_minimal.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    // 1. Boot the runtime.
    let handles = ControlLoopRuntime::start(bind, ENDPOINT, &db_path)
        .await
        .expect("runtime start");
    let db = handles.runtime.db.clone();
    let wakes = handles.wakes.clone();

    // 2. Emit a Workspace event. Workspace is a self-rooting event:
    //    workspace_id == event_id (BLAKE3 of canonical bytes).
    let workspace_pubkey: [u8; 32] = [0xA1; 32];
    let ws_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: 1_000,
        workspace_id: workspace_pubkey,
        public_key: workspace_pubkey,
        name: "minimal-workspace".to_string(),
    });
    let ws_emitted = emit_local_event_with_wake(
        &db,
        &wakes,
        "create_workspace",
        &ws_event,
        None, // root: helper sets workspace_id = event_id
        EventScope::Durable,
    )
    .await
    .expect("emit workspace");

    let ws_status = wait_for_terminal(&db, &ws_emitted.event_id, Duration::from_secs(10))
        .await
        .expect("workspace event terminal");
    assert_eq!(
        ws_status,
        EventStatus::Applied,
        "workspace event must apply (got {:?})",
        ws_status
    );

    // The Workspace projector writes to the `workspaces` table keyed
    // by (workspace_id, event_id) where workspace_id == event_id.
    {
        use base64::Engine;
        let g = db.lock().await;
        let event_id_b64 =
            base64::engine::general_purpose::STANDARD.encode(ws_emitted.event_id);
        let n: i64 = g
            .query_row(
                "SELECT COUNT(*) FROM workspaces
                    WHERE workspace_id = ?1 AND event_id = ?2",
                rusqlite::params![event_id_b64, event_id_b64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "workspaces projection row missing");
    }

    // 3. Emit a Message event under that workspace. The Message
    //    projector requires only non-empty content and no `deleted` /
    //    `removed_by:*` labels — author/signer keys are not validated
    //    in the new chain (signer_user_mismatch is opt-in via
    //    ContextSnapshot).
    let author_id: [u8; 32] = [0xB2; 32];
    let msg_event = ParsedEvent::Message(MessageEvent {
        created_at_ms: 2_000,
        workspace_id: ws_emitted.event_id, // workspace_id == workspace event_id
        author_id,
        content: "hello from the new substrate".to_string(),
        signed_by: author_id,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let msg_emitted = emit_local_event_with_wake(
        &db,
        &wakes,
        "send_message",
        &msg_event,
        Some(ws_emitted.event_id),
        EventScope::Durable,
    )
    .await
    .expect("emit message");

    let msg_status = wait_for_terminal(&db, &msg_emitted.event_id, Duration::from_secs(10))
        .await
        .expect("message event terminal");
    assert_eq!(
        msg_status,
        EventStatus::Applied,
        "message event must apply (got {:?})",
        msg_status
    );

    // 4. Query the messages projection. The new chain writes
    //    `messages.message_id = base64(event_id)` keyed by
    //    `(workspace_id, message_id)`.
    {
        use base64::Engine;
        let g = db.lock().await;
        let msg_id_b64 =
            base64::engine::general_purpose::STANDARD.encode(msg_emitted.event_id);
        let content: String = g
            .query_row(
                "SELECT content FROM messages WHERE message_id = ?1",
                rusqlite::params![msg_id_b64],
                |r| r.get(0),
            )
            .expect("messages row exists");
        assert_eq!(content, "hello from the new substrate");
    }

    // 5. Assert events_canonical: both rows present at status=applied.
    {
        let g = db.lock().await;
        let ws_row = events_canonical::get(&g, &ws_emitted.event_id)
            .expect("get ws row")
            .expect("ws row exists");
        assert_eq!(ws_row.status, EventStatus::Applied);

        let msg_row = events_canonical::get(&g, &msg_emitted.event_id)
            .expect("get msg row")
            .expect("msg row exists");
        assert_eq!(msg_row.status, EventStatus::Applied);

        // The local_event_intents audit rows survive the chain — there
        // should be exactly two we wrote (plus possibly any the
        // dispatcher's drain marked `unhandled`).
        let n_intents: i64 = g
            .query_row("SELECT COUNT(*) FROM local_event_intents", [], |r| r.get(0))
            .unwrap();
        assert!(
            n_intents >= 2,
            "expected at least 2 local_event_intents rows, got {}",
            n_intents
        );
    }

    // Clean up the runtime.
    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown");
}

/// Smoke test: a runtime with no events still has events_canonical at
/// zero rows after start, and shuts down cleanly. Cheap regression
/// guard for the boot path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_minimal_runtime_starts_clean_and_empty() {
    let dir = tmpdir();
    let db_path = dir.path().join("daemon_minimal_empty.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    let handles = ControlLoopRuntime::start(bind, ENDPOINT, &db_path)
        .await
        .expect("runtime start");
    let db = handles.runtime.db.clone();

    // Allow the dispatcher to settle (idle deadline 50ms).
    tokio::time::sleep(Duration::from_millis(150)).await;

    {
        let g: tokio::sync::MutexGuard<'_, rusqlite::Connection> = db.lock().await;
        let n_events: i64 = g
            .query_row("SELECT COUNT(*) FROM events_canonical", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_events, 0);
        let n_inbound: i64 = g
            .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_inbound, 0);
    }

    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown");
    let _ = db;
}
