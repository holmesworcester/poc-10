//! Plan.md line 114: a daemon hosts at most one instance of any given
//! workspace. These tests exercise the guard at the mutating command
//! paths (`create_workspace_for_db`, `accept_invite`).
//!
//! All tests run against direct command APIs — no daemon, no CLI — so
//! they isolate the invariant from transport / sync orchestration.

use ed25519_dalek::SigningKey;

use topo::db::{open_connection, schema::create_tables};
use topo::event_modules::workspace::commands::{
    accept_invite, create_user_invite_raw, create_workspace_for_db,
};
use topo::event_modules::workspace::invite_link::{create_invite_link, BootstrapAddress};

fn db_path(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path()
        .join(name)
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Create a user invite from `host_db` for the active tenant and format
/// it as an invite-link string that `accept_invite` can consume. Mirrors
/// the daemon's `create_invite_for_peer` glue without needing a daemon.
fn mint_invite_link(host_db: &str) -> String {
    let conn = open_connection(host_db).expect("open host db");
    create_tables(&conn).expect("create tables");

    // Discover the local tenant peer_id (there's exactly one — the
    // workspace creator). Mirrors `open_db_load`.
    let peer_id: String = conn
        .query_row(
            "SELECT recorded_by FROM invites_accepted ORDER BY recorded_by LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("local tenant must exist");

    // Resolve admin/peer-shared metadata mirroring create_invite_for_recorded_by.
    let _ = topo::event_modules::workspace::load_local_authoring_context(&conn, &peer_id)
        .expect("load authoring");
    let workspace_id = topo::event_modules::workspace::resolve_workspace_for_peer(&conn, &peer_id)
        .expect("resolve workspace");
    let (sender_peer_eid, sender_peer_key) =
        topo::event_modules::peer_shared::load_local_peer_signer_required(&conn, &peer_id)
            .expect("load peer signer");

    // Wave 1: peer-signed identities act as admin. Resolve the User
    // event_id (the actual "authority" the chain expects) via the
    // peers_shared link, mirroring `resolve_admin_event_for_signer`.
    let admin_event_id = topo::event_modules::peer_shared::resolve_user_event_id(
        &conn,
        &peer_id,
        &sender_peer_eid,
    )
    .expect("resolve user_event_id for admin");

    let invite = create_user_invite_raw(
        &conn,
        &peer_id,
        &sender_peer_key,
        &sender_peer_eid,
        &admin_event_id,
        &workspace_id,
    )
    .expect("create user invite");

    // Use a synthetic SPKI; the test never opens a transport.
    let synthetic_spki = [0x77u8; 32];
    let bootstrap_addrs: Vec<BootstrapAddress> = vec![BootstrapAddress::Ipv4 {
        ip: std::net::Ipv4Addr::new(127, 0, 0, 1),
        port: 4433,
    }];
    create_invite_link(&invite, &bootstrap_addrs, &synthetic_spki).expect("format invite link")
}

#[test]
fn create_workspace_succeeds_when_endpoint_clean() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let db = db_path(&tmpdir, "fresh.db");

    let resp = create_workspace_for_db(&db, "fresh-space", "alice", "alice-root")
        .expect("fresh DB must accept create_workspace");

    assert!(!resp.peer_id.is_empty());
    assert!(!resp.workspace_id.is_empty());

    // Sanity: invites_accepted has exactly one row (the self-accept).
    let conn = open_connection(&db).expect("open db");
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM invites_accepted", [], |row| row.get(0))
        .expect("count invites_accepted");
    assert_eq!(
        n, 1,
        "create_workspace must emit exactly one InviteAccepted (the self-accept)"
    );
}

#[test]
fn accept_invite_to_already_hosted_workspace_fails() {
    let tmpdir = tempfile::tempdir().expect("tempdir");

    // Host DB: create the workspace.
    let host_db = db_path(&tmpdir, "host.db");
    create_workspace_for_db(&host_db, "shared-space", "alice", "alice-root")
        .expect("create workspace");

    // Mint two distinct invites from the host. Each invite carries the
    // same workspace_id but a different invite_event_id.
    let invite1 = mint_invite_link(&host_db);
    let invite2 = mint_invite_link(&host_db);
    assert_ne!(
        invite1, invite2,
        "the two invites must differ (different invite_event_ids)"
    );

    // Joiner DB: accept the first invite — establishes the local tenant
    // binding for the shared workspace.
    let joiner_db = db_path(&tmpdir, "joiner.db");
    accept_invite(&joiner_db, &invite1, "bob", "bob-laptop")
        .expect("first accept on a clean joiner DB must succeed");

    // Second accept on the SAME joiner DB targets the same workspace via
    // a different invite. Plan.md line 114 forbids this.
    let err = accept_invite(&joiner_db, &invite2, "carol", "carol-laptop")
        .expect_err("second accept of same workspace on same daemon must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("plan.md line 114") || msg.contains("daemon already hosts"),
        "uniqueness error must reference the invariant; got: {}",
        msg
    );
}

#[test]
fn accept_invite_to_different_workspace_succeeds_with_existing_workspace() {
    let tmpdir = tempfile::tempdir().expect("tempdir");

    // Two distinct host workspaces.
    let host1_db = db_path(&tmpdir, "host1.db");
    create_workspace_with_distinct_seed(&host1_db, "ws-one", "alice", "alice-root", 0x11);
    let host2_db = db_path(&tmpdir, "host2.db");
    create_workspace_with_distinct_seed(&host2_db, "ws-two", "alice2", "alice2-root", 0x22);

    let invite1 = mint_invite_link(&host1_db);
    let invite2 = mint_invite_link(&host2_db);

    // Joiner DB accepts both — distinct workspace_ids, so the invariant
    // is satisfied.
    let joiner_db = db_path(&tmpdir, "joiner.db");
    accept_invite(&joiner_db, &invite1, "bob", "bob-laptop")
        .expect("accepting workspace one must succeed");
    accept_invite(&joiner_db, &invite2, "bob2", "bob2-laptop")
        .expect("accepting workspace two on the same DB must succeed (different workspace_id)");

    // Final state: two distinct workspace bindings.
    let conn = open_connection(&joiner_db).expect("open joiner db");
    let n_workspaces: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT workspace_id) FROM invites_accepted",
            [],
            |row| row.get(0),
        )
        .expect("count distinct workspaces");
    assert_eq!(
        n_workspaces, 2,
        "joiner must end up with two distinct workspace bindings"
    );
}

/// Create a workspace deterministically distinct from another by seeding
/// the RNG path indirectly through the workspace name. We don't need
/// special seeding — the workspace_id is derived from a fresh random
/// SigningKey inside `create_workspace`, so distinct host DBs produce
/// distinct workspace_ids with overwhelming probability. The `_seed`
/// param is kept for clarity at the call site.
fn create_workspace_with_distinct_seed(
    db: &str,
    workspace_name: &str,
    username: &str,
    devicename: &str,
    _seed: u8,
) {
    create_workspace_for_db(db, workspace_name, username, devicename)
        .expect("create workspace");
    // Reference SigningKey to keep the import path warning-free across
    // edits — the test does not need the key but we want the import to
    // remain useful for future seeding extensions.
    let _ = SigningKey::from_bytes(&[_seed; 32]);
}
