mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::{Child, Output};
use std::thread;
use std::time::Duration;

use cli_harness::*;
use topo::core::crypto;
use topo::protocol::event_modules::identity::{
    device_invite, endpoint, endpoint_shared, user, user_invite, workspace,
};
use topo::protocol::event_modules::types::EventId;
use topo::protocol::event_modules::worker::{self, CommandOutput};
use topo::protocol::Protocol;

#[test]
fn two_endpoints_sync_multiple_mutual_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_port = free_port();
    connect_pair(&alice, &bob, bob_port);

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let workspace_a = install_workspace_graph(
        &[&alice, &bob],
        11,
        "workspace-a",
        &[
            Member::new("alice-a", alice_endpoint, 21),
            Member::new("bob-a", bob_endpoint, 22),
        ],
    );
    let workspace_b = install_workspace_graph(
        &[&alice, &bob],
        12,
        "workspace-b",
        &[
            Member::new("alice-b", alice_endpoint, 23),
            Member::new("bob-b", bob_endpoint, 24),
        ],
    );
    generate(&alice, workspace_a.workspace_id, 3, 128);
    generate(&alice, workspace_b.workspace_id, 4, 129);
    sync_once(&alice, &bob, bob_port);

    assert_content_count(&bob, workspace_a.workspace_id, 3);
    assert_content_count(&bob, workspace_b.workspace_id, 4);
}

#[test]
fn two_player_sync_does_not_leak_alice_private_workspace_to_bob() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_port = free_port();
    connect_pair(&alice, &bob, bob_port);

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let shared = install_workspace_graph(
        &[&alice, &bob],
        31,
        "shared-a",
        &[
            Member::new("alice-a", alice_endpoint, 41),
            Member::new("bob-a", bob_endpoint, 42),
        ],
    );
    let alice_private = install_workspace_graph(
        &[&alice],
        32,
        "alice-b",
        &[Member::new("alice-b", alice_endpoint, 43)],
    );

    generate(&alice, shared.workspace_id, 2, 128);
    generate(&alice, alice_private.workspace_id, 5, 128);
    sync_once(&alice, &bob, bob_port);

    assert_content_count(&bob, shared.workspace_id, 2);
    assert_content_count(&bob, alice_private.workspace_id, 0);
}

#[test]
fn three_player_sync_through_alice_keeps_workspace_scopes_separate() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();
    connect_pair(&bob, &alice, alice_port);
    connect_pair(&carol, &alice, alice_port);
    connect_pair(&alice, &bob, bob_port);
    connect_pair(&alice, &carol, carol_port);

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let carol_endpoint = local_endpoint(&carol);
    let workspace_a = install_workspace_graph(
        &[&alice, &bob],
        51,
        "alice-bob-a",
        &[
            Member::new("alice-a", alice_endpoint, 61),
            Member::new("bob-a", bob_endpoint, 62),
        ],
    );
    let workspace_b = install_workspace_graph(
        &[&alice, &carol],
        52,
        "alice-carol-b",
        &[
            Member::new("alice-b", alice_endpoint, 63),
            Member::new("carol-b", carol_endpoint, 64),
        ],
    );

    generate(&bob, workspace_a.workspace_id, 3, 128);
    generate(&carol, workspace_b.workspace_id, 4, 128);

    sync_once(&bob, &alice, alice_port);
    sync_once(&carol, &alice, alice_port);
    sync_from_alice_to_bob_and_carol(&alice, &bob, bob_port, &carol, carol_port);

    assert_content_count(&alice, workspace_a.workspace_id, 3);
    assert_content_count(&alice, workspace_b.workspace_id, 4);
    assert_content_count(&bob, workspace_a.workspace_id, 3);
    assert_content_count(&bob, workspace_b.workspace_id, 0);
    assert_content_count(&carol, workspace_a.workspace_id, 0);
    assert_content_count(&carol, workspace_b.workspace_id, 4);
}

#[test]
fn daemons_sync_cli_generated_content_without_manual_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-daemon.db");
    let bob = temp_db(&tmp, "bob-daemon.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);

    let alice_invite = invite(&alice, alice_port);
    let connected = connect_with_retry(&bob, &alice_invite);
    assert!(connected.contains("connected:"), "{connected}");
    let reverse_invite = invite(&bob, bob_port);
    let reverse_connected = connect_with_retry(&alice, &reverse_invite);
    assert!(
        reverse_connected.contains("connected:"),
        "{reverse_connected}"
    );

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let workspace = install_workspace_graph(
        &[&alice, &bob],
        71,
        "daemon-shared",
        &[
            Member::new("alice-daemon", alice_endpoint, 81),
            Member::new("bob-daemon", bob_endpoint, 82),
        ],
    );
    generate(&alice, workspace.workspace_id, 3, 128);

    wait_for_content_count(&bob, workspace.workspace_id, 3);
}

#[test]
fn second_daemon_for_same_db_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-single-daemon.db");
    let first_port = free_port();
    let second_port = free_port();
    let _daemon = spawn_daemon(&alice, first_port);

    let output = topo(&[
        "--db",
        &alice,
        "start",
        "--listen",
        "127.0.0.1",
        &second_port.to_string(),
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    assert!(
        !output.status.success(),
        "second daemon unexpectedly started\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("daemon already running"),
        "unexpected second-daemon stderr:\n{}",
        stderr(&output)
    );
}

#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    endpoint_id: EventId,
    signing_public_key: [u8; 32],
    seed: u8,
}

impl Member {
    fn new(name: &'static str, endpoint: endpoint::types::EndpointKeypair, seed: u8) -> Self {
        Self {
            name,
            endpoint_id: endpoint.endpoint,
            signing_public_key: endpoint.signing_public_key,
            seed,
        }
    }
}

struct WorkspaceGraph {
    workspace_id: EventId,
}

fn install_workspace_graph(
    dbs: &[&str],
    seed: u8,
    name: &str,
    members: &[Member],
) -> WorkspaceGraph {
    let mut graph = None;
    for db in dbs {
        let installed = workspace_graph(db, seed, name, members);
        if let Some(existing) = graph {
            assert_eq!(existing, installed.workspace_id);
        }
        graph = Some(installed.workspace_id);
    }
    WorkspaceGraph {
        workspace_id: graph.expect("at least one db"),
    }
}

fn workspace_graph(db: &str, seed: u8, name: &str, members: &[Member]) -> WorkspaceGraph {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open graph store");
    let workspace_private = [seed; 32];
    let workspace_public = crypto::ed25519_public_key(&workspace_private);
    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: seed as u64,
        public_key: workspace_public,
        name: name.to_string(),
    })
    .expect("create workspace");
    let workspace_id = workspace.value.workspace_id;
    admit(&store, &protocol, workspace);

    for member in members {
        let user_private = [member.seed; 32];
        let invite_private = [member.seed.saturating_add(80); 32];
        let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
            created_at_ms: 100 + member.seed as u64,
            public_key: crypto::ed25519_public_key(&invite_private),
            workspace_id,
            authority_event_id: workspace_id,
            signer_event_id: workspace_id,
            signer_private_key: workspace_private,
        })
        .expect("create user invite");
        let user_invite_id = user_invite.value.user_invite_id;
        admit(&store, &protocol, user_invite);

        let user = user::commands::create(user::commands::CreateUser {
            created_at_ms: 200 + member.seed as u64,
            workspace_id,
            public_key: crypto::ed25519_public_key(&user_private),
            username: member.name.to_string(),
            user_invite_event_id: user_invite_id,
            user_invite_private_key: invite_private,
        })
        .expect("create user");
        let user_id = user.value.user_id;
        admit(&store, &protocol, user);

        let device_private = [member.seed.saturating_add(120); 32];
        let device_invite = device_invite::commands::create_with_private_key(
            device_invite::commands::CreateDeviceInvite {
                created_at_ms: 300 + member.seed as u64,
                workspace_id,
                user_authority_event_id: user_id,
                user_invite_event_id: Some(user_invite_id),
                signer_event_id: user_id,
                signer_private_key: user_private,
            },
            device_private,
        )
        .expect("create device invite");
        let device_invite_id = device_invite.value.device_invite_id;
        admit(&store, &protocol, device_invite);

        let shared = endpoint_shared::commands::share_endpoint(
            &store,
            endpoint_shared::commands::ShareEndpoint {
                created_at_ms: 400 + member.seed as u64,
                workspace_id,
                user_authority_event_id: user_id,
                endpoint_id: member.endpoint_id,
                signing_public_key: member.signing_public_key,
                device_name: member.name.to_string(),
                device_invite_id,
                device_invite_private_key: device_private,
            },
        )
        .expect("share endpoint");
        admit(&store, &protocol, shared);
    }

    WorkspaceGraph { workspace_id }
}

fn admit<T>(store: &topo::core::store::Store, protocol: &Protocol, output: CommandOutput<T>) {
    worker::run(store, protocol, output).expect("admit command output");
}

fn local_endpoint(db: &str) -> endpoint::types::EndpointKeypair {
    let store = Protocol::open_store(db).expect("open endpoint store");
    endpoint::commands::local_keypair(&store)
        .expect("load local endpoint")
        .expect("local endpoint exists")
}

fn start_listener(db: &str, port: u16, accept: usize) -> Child {
    let port = port.to_string();
    let accept = accept.to_string();
    spawn_topo(&[
        "--db",
        db,
        "sync",
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ])
}

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read daemon line");
    assert!(
        line.starts_with("listening: "),
        "daemon did not report listening: {line}"
    );
    RunningDaemon { child }
}

fn connect_pair(initiator_db: &str, listener_db: &str, listener_port: u16) {
    let invite = invite(listener_db, listener_port);
    let listener = start_listener(listener_db, listener_port, 1);
    let connected = connect_with_retry(initiator_db, &invite);
    assert!(connected.contains("connected:"));
    wait_success(listener, "connect listener");
}

fn invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = connect_with_invite(db, invite);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

fn connect_with_invite(db: &str, invite: &str) -> Output {
    topo(&["--db", db, "connect", invite])
}

fn sync_once(from_db: &str, listener_db: &str, listener_port: u16) {
    let (sync_out, listener) = sync_with_listener_retry(from_db, listener_db, listener_port, 1);
    assert!(sync_out.contains("routes_synced: 1"), "{sync_out}");
    wait_success(listener, "sync listener");
}

fn sync_from_alice_to_bob_and_carol(
    alice: &str,
    bob: &str,
    bob_port: u16,
    carol: &str,
    carol_port: u16,
) {
    let bob_listener = start_listener(bob, bob_port, 1);
    let carol_listener = start_listener(carol, carol_port, 1);
    thread::sleep(Duration::from_millis(100));
    let sync_out = sync_with_retry(alice);
    assert!(sync_out.contains("routes_synced: 2"), "{sync_out}");
    wait_success(bob_listener, "bob sync listener");
    wait_success(carol_listener, "carol sync listener");
}

fn sync_with_listener_retry(
    from_db: &str,
    listener_db: &str,
    listener_port: u16,
    accept: usize,
) -> (String, Child) {
    let mut last = String::new();
    for _ in 0..50 {
        let mut listener = start_listener(listener_db, listener_port, accept);
        thread::sleep(Duration::from_millis(50));
        let output = topo(&["--db", from_db, "sync"]);
        if output.status.success() {
            return (stdout(&output), listener);
        }
        last = stderr(&output);
        let _ = listener.kill();
        let _ = listener.wait();
        thread::sleep(Duration::from_millis(50));
    }
    panic!("sync never succeeded: {last}");
}

fn generate(db: &str, workspace_id: EventId, count: usize, size: usize) -> String {
    let workspace = hex_id(workspace_id);
    let count = count.to_string();
    let size = size.to_string();
    assert_success(topo(&["--db", db, "generate", &workspace, &count, &size]))
}

fn sync_with_retry(db: &str) -> String {
    let mut last = String::new();
    for _ in 0..50 {
        let output = topo(&["--db", db, "sync"]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("sync never succeeded: {last}");
}

fn assert_content_count(db: &str, workspace_id: EventId, expected: usize) {
    let workspace = hex_id(workspace_id);
    let out = assert_success(topo(&["--db", db, "content-count", &workspace]));
    assert_eq!(
        line_value(&out, "content_events"),
        expected.to_string(),
        "content-count output:\n{out}"
    );
}

fn wait_for_content_count(db: &str, workspace_id: EventId, expected: usize) {
    let workspace = hex_id(workspace_id);
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "content-count", &workspace]));
        if line_value(&out, "content_events") == expected.to_string() {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("content count did not reach {expected}; last output:\n{last}");
}

fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
