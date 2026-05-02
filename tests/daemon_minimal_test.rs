//! # Minimal-viable daemon integration test
//!
//! Exercises the substrate end-to-end through the public runtime API:
//!
//! 1. Boot a [`ControlLoopRuntime`] (transport bridge + dispatcher).
//! 2. Build a [`DbHandle`] over the running runtime so the test shares
//!    the dispatcher's connection + wake bus.
//! 3. Submit `Command::CreateWorkspace` via [`api::run`] and assert the
//!    outcome is `Applied`.
//! 4. Submit `Command::SendMessage` against that workspace, assert
//!    `Applied`.
//! 5. Use [`api::list_messages`] to confirm the message landed in the
//!    projection. No raw SELECT statements; no substrate-internal
//!    types.
//!
//! This test exercises the same public API surface as the real `topo`
//! binary — no substrate-internal symbols are imported.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use topo::api::{self, Command, CommandOutcome, DbHandle};
use topo::runtime::control_loop::ControlLoopRuntime;

const ENDPOINT: [u8; 32] = [0x77; 32];

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_minimal_create_workspace_and_send_message_via_api() {
    let dir = tmpdir();
    let db_path = dir.path().join("daemon_minimal.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    // 1. Boot the runtime.
    let handles = ControlLoopRuntime::start(bind, ENDPOINT, &db_path)
        .await
        .expect("runtime start");

    // 2. Build an API handle that shares the runtime's connection +
    //    wake bus so the dispatcher picks up our submitted commands
    //    without waiting on its idle deadline.
    let db = DbHandle::from_runtime(&handles);

    // 3. Create a workspace.
    let create_outcome = api::run(
        &db,
        Command::CreateWorkspace {
            name: "minimal-workspace".to_string(),
        },
        Duration::from_secs(10),
    )
    .await
    .expect("create_workspace api call");
    assert!(
        matches!(create_outcome, CommandOutcome::Applied),
        "workspace must apply (got {:?})",
        create_outcome
    );

    // The list_workspaces projection should now show exactly one
    // workspace with our chosen name.
    let workspaces = api::list_workspaces(&db).await.expect("list_workspaces");
    assert_eq!(workspaces.len(), 1, "expected exactly one workspace");
    let ws = &workspaces[0];
    assert_eq!(ws.name, "minimal-workspace");
    assert_eq!(ws.message_count, 0);

    // 4. Send a message into that workspace.
    let send_outcome = api::run(
        &db,
        Command::SendMessage {
            workspace_id: ws.id,
            content: "hello from the new substrate".to_string(),
        },
        Duration::from_secs(10),
    )
    .await
    .expect("send_message api call");
    assert!(
        matches!(send_outcome, CommandOutcome::Applied),
        "message must apply (got {:?})",
        send_outcome
    );

    // 5. The messages projection should now have exactly one row with
    //    our content.
    let messages = api::list_messages(&db, ws.id, 10)
        .await
        .expect("list_messages");
    assert_eq!(messages.len(), 1, "expected exactly one message");
    assert_eq!(messages[0].content, "hello from the new substrate");
    assert_eq!(messages[0].workspace_id, ws.id);

    // The aggregate endpoint status should reflect both events as
    // applied.
    let status = api::endpoint_status(&db).await.expect("endpoint_status");
    assert!(
        status.events_applied >= 2,
        "expected >= 2 applied events (got {})",
        status.events_applied
    );
    assert_eq!(status.events_blocked, 0);

    // Clean up the runtime.
    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown");
}

/// Smoke test: a runtime with no events still has zero events applied
/// and shuts down cleanly. Cheap regression guard for the boot path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_minimal_runtime_starts_clean_and_empty() {
    let dir = tmpdir();
    let db_path = dir.path().join("daemon_minimal_empty.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    let handles = ControlLoopRuntime::start(bind, ENDPOINT, &db_path)
        .await
        .expect("runtime start");
    let db = DbHandle::from_runtime(&handles);

    // Allow the dispatcher to settle (idle deadline 50ms).
    tokio::time::sleep(Duration::from_millis(150)).await;

    let status = api::endpoint_status(&db).await.expect("endpoint_status");
    assert_eq!(status.events_applied, 0);
    assert_eq!(status.events_blocked, 0);
    assert_eq!(status.events_pending, 0);
    assert!(status.workspaces.is_empty());

    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown");
}
