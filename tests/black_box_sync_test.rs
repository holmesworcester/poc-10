mod cli_harness;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cli_harness::*;
use topo::core::cli::decode_hex_32;
use topo::core::db::Db;
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::protocol::auth::{admin, workspace as auth_workspace};
use topo::protocol::connection::frame_file_slice::encode::{
    CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES, CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
    CONNECTION_FRAME_VERSION,
};
use topo::protocol::content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES;
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

#[test]
fn two_endpoints_sync_multiple_mutual_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_a = create_workspace(&alice, "workspace-a", "alice-a", "alice-a-laptop");
    let workspace_b = create_workspace(&alice, "workspace-b", "alice-b", "alice-b-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_a,
        alice_port,
        "bob-a",
        "bob-a-phone",
    );
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_b,
        alice_port,
        "bob-b",
        "bob-b-phone",
    );
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace_a, "bob-a", 10_000);
    poll_for_workspace_member(&bob, &workspace_b, "bob-b", 10_000);
    create_local_content_key(&alice, &workspace_a);
    create_local_content_key(&alice, &workspace_b);

    generate(&alice, &workspace_a, 3, 128);
    generate(&alice, &workspace_b, 4, 129);

    wait_for_content_count(&bob, &workspace_a, 3);
    wait_for_content_count(&bob, &workspace_b, 4);
}

#[test]
fn two_player_sync_does_not_leak_alice_private_workspace_to_bob() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let shared = create_workspace(&alice, "shared-a", "alice-a", "alice-a-laptop");
    let alice_private = create_workspace(&alice, "alice-b", "alice-b", "alice-b-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(&alice, &bob, &shared, alice_port, "bob-a", "bob-a-phone");
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &shared, "bob-a", 10_000);
    create_local_content_key(&alice, &shared);

    generate(&alice, &shared, 2, 128);

    wait_for_content_count(&bob, &shared, 2);
    create_local_content_key(&alice, &alice_private);
    generate(&alice, &alice_private, 5, 128);
    thread::sleep(Duration::from_millis(1200));
    assert_content_count(&bob, &alice_private, 0);
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

    let workspace_a = create_workspace(&alice, "alice-bob-a", "alice-a", "alice-a-laptop");
    let workspace_b = create_workspace(&alice, "alice-carol-b", "alice-b", "alice-b-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let mut carol_daemon = spawn_daemon(&carol, carol_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_a,
        alice_port,
        "bob-a",
        "bob-a-phone",
    );
    accept_workspace_invite(
        &alice,
        &carol,
        &workspace_b,
        alice_port,
        "carol-b",
        "carol-b-phone",
    );
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    carol_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace_a, "bob-a", 10_000);
    poll_for_workspace_member(&carol, &workspace_b, "carol-b", 10_000);
    create_local_content_key(&bob, &workspace_a);
    create_local_content_key(&carol, &workspace_b);

    generate(&bob, &workspace_a, 3, 128);
    generate(&carol, &workspace_b, 4, 128);
    set_sync_range_until_visible(&bob, &workspace_a, "0", "18446744073709551615", 30_000);
    set_sync_range_until_visible(&carol, &workspace_b, "0", "18446744073709551615", 30_000);

    wait_for_message_fact_count(&alice, &workspace_a, 3);
    wait_for_message_fact_count(&alice, &workspace_b, 4);
    wait_for_content_count(&bob, &workspace_a, 3);
    assert_message_fact_count(&bob, &workspace_b, 0);
    assert_message_fact_count(&carol, &workspace_a, 0);
    wait_for_content_count(&carol, &workspace_b, 4);
}

#[test]
fn daemons_sync_cli_generated_content_without_manual_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-daemon.db");
    let bob = temp_db(&tmp, "bob-daemon.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let workspace = create_workspace(&alice, "daemon-shared", "alice-daemon", "alice-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace,
        alice_port,
        "bob-daemon",
        "bob-phone",
    );
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace, "bob-daemon", 10_000);
    create_local_content_key(&alice, &workspace);

    generate(&alice, &workspace, 3, 128);

    wait_for_content_count(&bob, &workspace, 3);
}

#[test]
fn cli_two_long_running_daemons_converge_messages_without_manual_sync() {
    // Asymmetric: alice runs `start` and prints an invite that points at her
    // daemon listener. Bob runs `start` and then `accept INVITE` once. After
    // accept finishes there is no manual `connect` from either side.
    // Convergence must come from the daemon's periodic outbound sync alone.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-asym.db");
    let bob = temp_db(&tmp, "bob-asym.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace = create_workspace(&alice, "asym-shared", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);

    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    // Wait for the membership graph to reach bob through the daemon's
    // periodic sync. The daemons exchange compare/have/need rounds without
    // any operator running `sync`.
    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);

    let bob_recipient_id = line_value(
        &assert_success(topo(&["--db", &bob, "key-recipient", &workspace])),
        "recipient_key_id",
    );

    let removal_frontier_id = line_value(
        &assert_success(topo(&["--db", &alice, "key-frontier", &workspace])),
        "removal_frontier_id",
    );
    let wrap = poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &bob_recipient_id,
        10_000,
    );
    assert_eq!(line_value(&wrap, "recipient_key_id"), bob_recipient_id);

    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 10_000);

    let alice_send = assert_success(topo(&["--db", &alice, "send", &workspace, "hello"]));
    assert_eq!(line_value(&alice_send, "text"), "hello");

    poll_for_message_text(&bob, &workspace, "hello", 10_000);
}

#[test]
fn cli_sync_setting_range_delivers_transitive_admin_and_message_context() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-range.db");
    let carol = temp_db(&tmp, "carol-range.db");
    let bob = temp_db(&tmp, "bob-range.db");
    let alice_port = free_port();
    let carol_port = free_port();
    let bob_port = free_port();

    let workspace = create_workspace(&alice, "range-shared", "alice", "alice-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace,
        alice_port,
        "bob-range",
        "bob-range-phone",
    );
    set_sync_range_until_visible(&alice, &workspace, "0", "18446744073709551615", 30_000);
    poll_for_workspace_member(&bob, &workspace, "bob-range", 10_000);

    let removal_frontier_id = create_local_content_key(&alice, &workspace);
    let recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace]));
    let recipient_id = line_value(&recipient, "recipient_key_id");
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &recipient_id,
        30_000,
    );
    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 30_000);

    assert_success(topo(&["--db", &bob, "stop"]));
    drop(bob_daemon);
    wait_for_daemon_lock_release(&bob);
    assert_success(topo(&["--db", &alice, "stop"]));
    drop(alice_daemon);
    wait_for_daemon_lock_release(&alice);
    alice_daemon = spawn_daemon(&alice, alice_port);

    let mut carol_daemon = spawn_daemon(&carol, carol_port);
    let carol_invite = workspace_invite_for_addr(&alice, &workspace, alice_port);
    let accepted_carol =
        accept_with_identity_retry(&carol, &carol_invite, "carol-range", "carol-range-laptop");
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace);
    set_sync_range_until_visible(&alice, &workspace, "0", "18446744073709551615", 30_000);
    poll_for_workspace_member(&carol, &workspace, "carol-range", 30_000);

    let carol_recipient = assert_success(topo(&["--db", &carol, "key-recipient", &workspace]));
    let carol_recipient_id = line_value(&carol_recipient, "recipient_key_id");
    assert_success(topo(&["--db", &alice, "stop"]));
    drop(alice_daemon);
    wait_for_daemon_lock_release(&alice);
    alice_daemon = spawn_daemon(&alice, alice_port);
    set_sync_range_until_visible(&carol, &workspace, "0", "18446744073709551615", 30_000);
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &carol_recipient_id,
        30_000,
    );
    poll_for_workspace_member(&alice, &workspace, "carol-range", 30_000);
    let carol_user_id = line_value(&accepted_carol, "user_id");
    let carol_admin = assert_success(topo(&[
        "--db",
        &alice,
        "grant-admin",
        &workspace,
        &carol_user_id,
    ]));
    assert!(!line_value(&carol_admin, "admin_id").is_empty());
    set_sync_range_until_visible(&alice, &workspace, "0", "18446744073709551615", 30_000);
    poll_for_local_admin(&carol, &workspace, 30_000);
    poll_for_key_access(&carol, &workspace, &removal_frontier_id, "yes", 30_000);

    let carol_send = assert_success(topo(&[
        "--db",
        &carol,
        "send",
        &workspace,
        "carol-range-message",
    ]));
    let message_at = line_value(&carol_send, "created_at_ms");
    assert_success(topo(&["--db", &alice, "stop"]));
    drop(alice_daemon);
    wait_for_daemon_lock_release(&alice);
    alice_daemon = spawn_daemon(&alice, alice_port);
    set_sync_range_until_visible(&carol, &workspace, &message_at, &message_at, 30_000);
    poll_for_message_text(&alice, &workspace, "carol-range-message", 10_000);

    let policy_at = message_at
        .parse::<u64>()
        .expect("message timestamp")
        .saturating_add(1)
        .to_string();
    let policy = assert_success(topo_at(
        &carol,
        &policy_at,
        &["disappearing-set", &workspace, "120"],
    ));
    assert_eq!(line_value(&policy, "ttl_minutes"), "120");
    set_sync_range_until_visible(&carol, &workspace, &policy_at, &policy_at, 30_000);
    poll_for_disappearing_value(&alice, &workspace, "current_ttl_minutes", "120", 10_000);
    alice_daemon.assert_running();
    carol_daemon.assert_running();
    assert_success(topo(&["--db", &carol, "stop"]));
    drop(carol_daemon);
    wait_for_daemon_lock_release(&carol);

    bob_daemon = spawn_daemon(&bob, bob_port);
    let policy_with =
        set_sync_range_until_visible(&alice, &workspace, &policy_at, &policy_at, 30_000);
    assert_eq!(line_value(&policy_with, "mode"), "range");
    poll_for_disappearing_value(&bob, &workspace, "current_ttl_minutes", "120", 10_000);

    let with = set_sync_range_until_visible(&alice, &workspace, &message_at, &message_at, 30_000);
    assert_eq!(line_value(&with, "mode"), "range");
    poll_for_message_text(&bob, &workspace, "carol-range-message", 10_000);
    assert_eq!(
        disappearing_value(&bob, &workspace, "current_ttl_minutes"),
        "120"
    );
    assert!(messages_text(&bob, &workspace).contains("carol-range-message"));
    bob_daemon.assert_running();
}

#[test]
fn cli_two_long_running_daemons_download_multislice_file_via_proxied_invite_path() {
    // This is the poc-10 replacement for the basic simulated download proof:
    // drive only the product CLI plus daemon networking, with the sender's bulk
    // path forced through a measured TCP proxy, then assert the receiver can
    // save the exact multi-slice bytes.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-file.db");
    let bob = temp_db(&tmp, "bob-file.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let proxy = ThrottledTcpProxy::start(
        format!("127.0.0.1:{alice_port}").parse().unwrap(),
        125_000_000,
    );

    let workspace = create_workspace(&alice, "file-shared", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, proxy.port());

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);

    let bob_recipient_id = line_value(
        &assert_success(topo(&["--db", &bob, "key-recipient", &workspace])),
        "recipient_key_id",
    );
    let removal_frontier_id = line_value(
        &assert_success(topo(&["--db", &alice, "key-frontier", &workspace])),
        "removal_frontier_id",
    );
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &bob_recipient_id,
        30_000,
    );
    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 30_000);

    set_sync_range_until_visible(&bob, &workspace, "0", "18446744073709551615", 60_000);

    // Two fixed file slices keep this as a real multislice network transfer
    // without turning the default daemon integration suite into a throughput
    // fixture.
    let payload = patterned_payload(2);
    let in_path = tmp.path().join("proxied-network-download.bin");
    std::fs::write(&in_path, &payload).expect("write source payload");

    let proxied_before = proxy.client_to_server_bytes();
    let sent = assert_success(topo(&[
        "--db",
        &bob,
        "send-file",
        &workspace,
        "proxied network download",
        "--file",
        in_path.to_str().expect("source path"),
    ]));
    assert_eq!(line_value(&sent, "blob_bytes"), payload.len().to_string());

    let listing =
        poll_for_file_complete(&alice, &workspace, "proxied-network-download.bin", 60_000);
    assert!(listing.contains("\u{2714}"), "{listing}");
    let proxied_bytes = proxy
        .client_to_server_bytes()
        .saturating_sub(proxied_before);
    assert!(
        proxy.accepted_connections() > 0,
        "proxy never accepted a connection"
    );
    assert!(
        proxied_bytes >= payload.len() as u64,
        "bulk file bytes did not cross the measured proxy: proxied_bytes={proxied_bytes} payload_bytes={}",
        payload.len()
    );

    let out_path = tmp.path().join("saved-proxied-network-download.bin");
    let saved = poll_for_saved_file(
        &alice,
        &workspace,
        "#1",
        out_path.to_str().expect("output path"),
        60_000,
    );
    assert_eq!(
        line_value(&saved, "filename"),
        "proxied-network-download.bin"
    );
    assert_eq!(
        line_value(&saved, "bytes_written"),
        payload.len().to_string()
    );
    assert_eq!(
        std::fs::read(&out_path).expect("read saved payload"),
        payload
    );
}

#[test]
#[ignore = "manual cable-bound download throughput fixture; run with --ignored when measuring daemon transfer speed"]
fn cli_cable_bound_download_perf_isolates_authoring_sync_and_save() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-download-perf.db");
    let bob = temp_db(&tmp, "bob-download-perf.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let cable_mbps = env_f64("TOPO_DOWNLOAD_PERF_MBPS").unwrap_or(25.0);
    let proxy = ThrottledTcpProxy::start(
        format!("127.0.0.1:{alice_port}").parse().unwrap(),
        bytes_per_second(cable_mbps),
    );

    let workspace = create_workspace(&alice, "download-perf", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, proxy.port());

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);

    let bob_recipient_id = line_value(
        &assert_success(topo(&["--db", &bob, "key-recipient", &workspace])),
        "recipient_key_id",
    );
    let removal_frontier_id = line_value(
        &assert_success(topo(&["--db", &alice, "key-frontier", &workspace])),
        "removal_frontier_id",
    );
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &bob_recipient_id,
        10_000,
    );
    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 10_000);
    set_sync_range_until_visible(&bob, &workspace, "0", "18446744073709551615", 60_000);

    assert_success(topo(&["--db", &alice, "stop"]));
    drop(alice_daemon);
    wait_for_daemon_lock_release(&alice);
    assert_success(topo(&["--db", &bob, "stop"]));
    drop(bob_daemon);
    wait_for_daemon_lock_release(&bob);

    let payload_mib = std::env::var("TOPO_DOWNLOAD_PERF_MIB")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("parse TOPO_DOWNLOAD_PERF_MIB")
        })
        .unwrap_or(8);
    let timeout_ms = env_u64("TOPO_DOWNLOAD_PERF_TIMEOUT_MS")
        .unwrap_or_else(|| download_timeout_ms(payload_mib, cable_mbps));

    let payload_create_started = Instant::now();
    let payload_bytes = payload_mib * 1024 * 1024;
    let payload = patterned_payload(payload_bytes.div_ceil(FILE_SLICE_PLAINTEXT_BYTES));
    let in_path = tmp.path().join("download-perf.bin");
    std::fs::write(&in_path, &payload).expect("write perf payload");
    let payload_create_elapsed = payload_create_started.elapsed();

    let authoring_started = Instant::now();
    let sent = assert_success(topo(&[
        "--db",
        &bob,
        "send-file",
        &workspace,
        "download perf",
        "--file",
        in_path.to_str().expect("source path"),
    ]));
    let authoring_elapsed = authoring_started.elapsed();
    assert_eq!(line_value(&sent, "blob_bytes"), payload.len().to_string());

    let before_sync = assert_success(topo(&["--db", &alice, "files", &workspace]));
    assert!(
        !before_sync.contains("download-perf.bin"),
        "file arrived before sync was enabled:\n{before_sync}"
    );

    let proxied_before = proxy.client_to_server_bytes();
    let sync_started = Instant::now();
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let daemons_ready_at = Instant::now();
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    let first_proxy_byte_at =
        wait_for_proxy_client_to_server_above(&proxy, proxied_before, timeout_ms);
    let first_file_slice_proxy_byte_at =
        wait_for_proxy_first_file_slice_client_to_server(&proxy, timeout_ms);
    let listing = poll_for_file_complete(&alice, &workspace, "download-perf.bin", timeout_ms);
    let completed_at = Instant::now();
    let sync_elapsed = completed_at.duration_since(sync_started);
    let ready_elapsed = completed_at.duration_since(daemons_ready_at);
    let first_proxy_byte_elapsed = completed_at.duration_since(first_proxy_byte_at);
    let ready_to_first_file_slice_elapsed =
        first_file_slice_proxy_byte_at.duration_since(daemons_ready_at);
    let first_file_slice_proxy_byte_elapsed =
        completed_at.duration_since(first_file_slice_proxy_byte_at);
    assert!(listing.contains("\u{2714}"), "{listing}");

    let proxied_bytes = proxy
        .client_to_server_bytes()
        .saturating_sub(proxied_before);
    assert!(
        proxy.accepted_connections() > 0,
        "proxy never accepted a connection"
    );
    assert!(
        proxied_bytes >= payload.len() as u64,
        "bulk file bytes did not cross the measured proxy: proxied_bytes={proxied_bytes} payload_bytes={}",
        payload.len()
    );
    let network_seconds = first_proxy_byte_elapsed.as_secs_f64().max(0.001);
    let payload_mbit_per_second = payload.len() as f64 * 8.0 / network_seconds / 1_000_000.0;
    let proxy_mbit_per_second = proxied_bytes as f64 * 8.0 / network_seconds / 1_000_000.0;

    let out_path = tmp.path().join("saved-download-perf.bin");
    let save_started = Instant::now();
    let saved = poll_for_saved_file(
        &alice,
        &workspace,
        "#1",
        out_path.to_str().expect("output path"),
        30_000,
    );
    let save_elapsed = save_started.elapsed();
    eprintln!(
        "black_box_cable_download_perf sender=bob receiver=alice path=bob_to_alice_proxy configured_mbps={:.2} payload_bytes={} proxy_client_to_server_bytes={} payload_create_ms={} send_file_authoring_ms={} sync_restart_to_complete_ms={} daemons_ready_to_complete_ms={} first_proxy_byte_to_complete_ms={} daemons_ready_to_first_file_slice_proxy_byte_ms={} first_file_slice_proxy_byte_to_complete_ms={} save_file_ms={} payload_mbit_per_s={:.2} proxy_mbit_per_s={:.2}",
        cable_mbps,
        payload.len(),
        proxied_bytes,
        payload_create_elapsed.as_millis(),
        authoring_elapsed.as_millis(),
        sync_elapsed.as_millis(),
        ready_elapsed.as_millis(),
        first_proxy_byte_elapsed.as_millis(),
        ready_to_first_file_slice_elapsed.as_millis(),
        first_file_slice_proxy_byte_elapsed.as_millis(),
        save_elapsed.as_millis(),
        payload_mbit_per_second,
        proxy_mbit_per_second
    );
    assert!(payload_mbit_per_second.is_finite() && payload_mbit_per_second > 0.0);

    assert_eq!(line_value(&saved, "filename"), "download-perf.bin");
    assert_eq!(
        line_value(&saved, "bytes_written"),
        payload.len().to_string()
    );
    assert_eq!(
        std::fs::read(&out_path).expect("read saved perf payload"),
        payload
    );
}

#[test]
fn black_box_generated_content_sync_catches_up_after_daemon_reconnect() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-sync-reconnect.db");
    let bob = temp_db(&tmp, "bob-sync-reconnect.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let message_count = 24;
    let message_text_bytes = 96;
    let timeout_ms = 20_000;

    let workspace = create_workspace(&alice, "sync-reconnect", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);
    create_local_content_key(&alice, &workspace);
    drop(alice_daemon);
    drop(bob_daemon);

    let generated = generate(&alice, &workspace, message_count, message_text_bytes);
    assert_eq!(
        line_value(&generated, "generated_facts"),
        message_count.to_string()
    );
    assert_content_count(&bob, &workspace, 0);

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    let projected = poll_for_content_count_at_least(&bob, &workspace, message_count, timeout_ms);
    assert_eq!(projected, message_count);
}

#[test]
fn cli_three_long_running_daemons_converge_messages_among_late_joiner() {
    // alice runs a daemon. bob accepts alice's daemon-served invite, then
    // carol does the same. All three converge on shared messages from alice
    // and bob without anyone running manual `sync`.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-three.db");
    let bob = temp_db(&tmp, "bob-three.db");
    let carol = temp_db(&tmp, "carol-three.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();

    let workspace = create_workspace(&alice, "three-shared", "alice", "alice-laptop");
    let invite_for_bob = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);

    let accepted_bob = accept_with_identity_retry(&bob, &invite_for_bob, "bob", "bob-phone");
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace);

    // Late joiner: carol accepts a fresh invite from alice's daemon and starts
    // her own daemon BEFORE bob/alice exchange any encrypted content. The
    // periodic outbound sync still has to fan out alice's identity facts to
    // both bob and carol, and sync their own join/identity facts back to
    // alice and to each other.
    let invite_for_carol = workspace_invite_for_addr(&alice, &workspace, alice_port);
    let _carol_daemon = spawn_daemon(&carol, carol_port);
    let accepted_carol =
        accept_with_identity_retry(&carol, &invite_for_carol, "carol", "carol-tablet");
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace);

    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);
    poll_for_workspace_member(&carol, &workspace, "carol", 10_000);

    let bob_recipient_id = line_value(
        &assert_success(topo(&["--db", &bob, "key-recipient", &workspace])),
        "recipient_key_id",
    );
    let carol_recipient_id = line_value(
        &assert_success(topo(&["--db", &carol, "key-recipient", &workspace])),
        "recipient_key_id",
    );

    let removal_frontier_id = line_value(
        &assert_success(topo(&["--db", &alice, "key-frontier", &workspace])),
        "removal_frontier_id",
    );
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &bob_recipient_id,
        10_000,
    );
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &carol_recipient_id,
        10_000,
    );
    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 10_000);
    poll_for_key_access(&carol, &workspace, &removal_frontier_id, "yes", 10_000);

    let alice_send = assert_success(topo(&["--db", &alice, "send", &workspace, "from-alice"]));
    assert_eq!(line_value(&alice_send, "text"), "from-alice");
    let bob_send = assert_success(topo(&["--db", &bob, "send", &workspace, "from-bob"]));
    assert_eq!(line_value(&bob_send, "text"), "from-bob");

    poll_for_message_text(&bob, &workspace, "from-alice", 30_000);
    poll_for_message_text(&carol, &workspace, "from-alice", 30_000);
    poll_for_message_text(&alice, &workspace, "from-bob", 30_000);
    poll_for_message_text(&carol, &workspace, "from-bob", 30_000);
}

fn workspace_invite_for_addr(db: &str, workspace_id: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--public-addr",
        &addr,
    ]));
    invite_link_from_output(&out)
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn accept_with_identity_retry(db: &str, invite: &str, username: &str, device_name: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept",
            invite,
            "--username",
            username,
            "--devicename",
            device_name,
        ]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        // Bootstrap can retry on transient TCP failures or when alice's
        // daemon has not yet committed the new user_invite fact
        // table for the just-created invite link.
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded: {last}");
}

fn poll_for_workspace_member(db: &str, workspace_id: &str, username: &str, timeout_ms: u64) {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let recipient = topo(&["--db", db, "key-recipient", workspace_id]);
        let users = topo(&["--db", db, "users", workspace_id]);
        if recipient.status.success() && users.status.success() {
            let text = stdout(&users);
            if text.contains(username) {
                return;
            }
            last = text;
        } else {
            last = format!(
                "key-recipient stderr:\n{}\nusers stderr:\n{}",
                stderr(&recipient),
                stderr(&users)
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
    let count = topo(&["--db", db, "count"]);
    let count_output = if count.status.success() {
        stdout(&count)
    } else {
        stderr(&count)
    };
    panic!(
        "user {username} did not converge into {db}; last users output:\n{last}\ncount output:\n{count_output}"
    );
}

fn wait_for_users_contains(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let users = topo(&["--db", db, "users", workspace_id]);
        if users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = stderr(&users);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("user {username} never appeared in {db}: {last}");
}

fn wait_for_identity_contains(db: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let identity = topo(&["--db", db, "identity"]);
        if identity.status.success() {
            let identity = stdout(&identity);
            if identity.contains(expected) {
                return;
            }
            last = identity;
        } else {
            last = stderr(&identity);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("identity never contained {expected}: {last}");
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let frontier = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    line_value(&frontier, "removal_frontier_id")
}

fn wait_for_keys_value(db: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "keys", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, key) == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("keys {key} never reached {expected}: {last}");
}

fn poll_for_wrap_eligibility(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    recipient_key_id: &str,
    timeout_ms: u64,
) -> String {
    // `key-wrap` is only allowed once both sides of the recipient/frontier
    // pair are visible locally. Polling its success doubles as a sync-arrival
    // probe without leaning on internal storage.
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&[
            "--db",
            db,
            "key-wrap",
            workspace_id,
            removal_frontier_id,
            recipient_key_id,
        ]);
        if out.status.success() {
            return stdout(&out);
        }
        last = stderr(&out);
        thread::sleep(Duration::from_millis(250));
    }
    panic!("key-wrap never succeeded in {db}; last error:\n{last}");
}

fn poll_for_key_access(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    expected: &str,
    timeout_ms: u64,
) {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&["--db", db, "key-access", workspace_id, removal_frontier_id]);
        if out.status.success() {
            let text = stdout(&out);
            if line_value(&text, "access") == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("key-access did not reach {expected} in {db}; last output:\n{last}");
}

fn poll_for_local_admin(db: &str, workspace_id_hex: &str, timeout_ms: u64) {
    let workspace_id = decode_hex_32(workspace_id_hex).expect("workspace id");
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        match local_admin_visible(db, workspace_id) {
            Ok(true) => return,
            Ok(false) => last = "admin row not visible".to_string(),
            Err(err) => last = err,
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("local admin did not converge in {db}; last state:\n{last}");
}

fn local_admin_visible(db: &str, workspace_id: [u8; 32]) -> Result<bool, String> {
    let store = Db::open_disk_with_schema_sources(db, &[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .map_err(|err| format!("open store: {err}"))?;
    let membership = auth_workspace::queries::local_membership(&store, workspace_id)?
        .ok_or_else(|| "local endpoint has not joined workspace".to_string())?;
    for row in admin::queries::admin_rows_in_workspace(&store, workspace_id)? {
        if row.user_fact_id == membership.user_authority_fact_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn poll_for_message_text(db: &str, workspace_id: &str, expected_text: &str, timeout_ms: u64) {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&["--db", db, "messages", workspace_id]);
        if out.status.success() {
            let text = stdout(&out);
            if text.contains(expected_text) {
                return;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("messages in {db} never contained {expected_text}; last output:\n{last}");
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

fn disappearing_value(db: &str, workspace_id: &str, key: &str) -> String {
    let status = assert_success(topo(&["--db", db, "disappearing-status", workspace_id]));
    line_value(&status, key)
}

fn poll_for_disappearing_value(
    db: &str,
    workspace_id: &str,
    key: &str,
    expected: &str,
    timeout_ms: u64,
) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while Instant::now() < deadline {
        let out = topo(&["--db", db, "disappearing-status", workspace_id]);
        if out.status.success() {
            let text = stdout(&out);
            if line_value(&text, key) == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("disappearing-status {key} did not reach {expected} in {db}; last output:\n{last}");
}

fn set_sync_range_until_visible(
    sender_db: &str,
    workspace_id: &str,
    start_ms: &str,
    end_ms: &str,
    timeout_ms: u64,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let output = topo(&[
            "--db",
            sender_db,
            "sync",
            "range",
            "--start-ms",
            start_ms,
            "--end-ms",
            end_ms,
        ]);
        if output.status.success() {
            let text = stdout(&output);
            if line_value(&text, "mode") == "range"
                && line_value(&text, "start_ms") == start_ms
                && line_value(&text, "end_ms") == end_ms
            {
                return text;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("sync range setting did not become visible in {sender_db} for {workspace_id}; last output:\n{last}");
}

fn poll_for_file_complete(
    db: &str,
    workspace_id: &str,
    expected_filename: &str,
    timeout_ms: u64,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&["--db", db, "files", workspace_id]);
        if out.status.success() {
            let text = stdout(&out);
            if text.contains(expected_filename) && text.contains("\u{2714}") {
                return text;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("files in {db} never completed {expected_filename}; last output:\n{last}");
}

fn poll_for_saved_file(
    db: &str,
    workspace_id: &str,
    selector: &str,
    out_path: &str,
    timeout_ms: u64,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&["--db", db, "save-file", workspace_id, selector, out_path]);
        if out.status.success() {
            return stdout(&out);
        }
        last = stderr(&out);
        thread::sleep(Duration::from_millis(250));
    }
    panic!("save-file in {db} never completed {selector}; last error:\n{last}");
}

#[derive(Default)]
struct ProxyCounters {
    accepted_connections: AtomicUsize,
    client_to_server_bytes: AtomicU64,
    first_file_slice_client_to_server_bytes: AtomicU64,
    server_to_client_bytes: AtomicU64,
}

struct ThrottledTcpProxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    counters: Arc<ProxyCounters>,
    accept_thread: Option<JoinHandle<()>>,
}

impl ThrottledTcpProxy {
    fn start(target: SocketAddr, bytes_per_second_per_connection: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind throttled proxy");
        listener
            .set_nonblocking(true)
            .expect("set throttled proxy nonblocking");
        let addr = listener.local_addr().expect("proxy local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(ProxyCounters::default());
        let thread_stop = Arc::clone(&stop);
        let thread_counters = Arc::clone(&counters);
        let accept_thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let (client, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(err) if thread_stop.load(Ordering::SeqCst) => {
                        eprintln!("throttled proxy stopped after accept error: {err}");
                        break;
                    }
                    Err(err) => panic!("throttled proxy accept: {err}"),
                };
                let server = match TcpStream::connect(target) {
                    Ok(server) => server,
                    Err(_) => continue,
                };
                let _ = client.set_nodelay(true);
                let _ = server.set_nodelay(true);
                thread_counters
                    .accepted_connections
                    .fetch_add(1, Ordering::Relaxed);
                spawn_proxy_pipes(
                    client,
                    server,
                    bytes_per_second_per_connection.max(1),
                    Arc::clone(&thread_counters),
                );
            }
        });
        Self {
            addr,
            stop,
            counters,
            accept_thread: Some(accept_thread),
        }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn accepted_connections(&self) -> usize {
        self.counters.accepted_connections.load(Ordering::Relaxed)
    }

    fn client_to_server_bytes(&self) -> u64 {
        self.counters.client_to_server_bytes.load(Ordering::Relaxed)
    }

    fn first_file_slice_client_to_server_bytes(&self) -> u64 {
        self.counters
            .first_file_slice_client_to_server_bytes
            .load(Ordering::Relaxed)
    }
}

impl Drop for ThrottledTcpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Copy)]
enum ProxyDirection {
    ClientToServer,
    ServerToClient,
}

fn spawn_proxy_pipes(
    client: TcpStream,
    server: TcpStream,
    bytes_per_second: u64,
    counters: Arc<ProxyCounters>,
) {
    let client_reader = client.try_clone().expect("clone proxy client reader");
    let server_writer = server.try_clone().expect("clone proxy server writer");
    let c2s_counters = Arc::clone(&counters);
    thread::spawn(move || {
        copy_throttled(
            client_reader,
            server_writer,
            bytes_per_second,
            c2s_counters,
            ProxyDirection::ClientToServer,
        );
    });
    thread::spawn(move || {
        copy_throttled(
            server,
            client,
            bytes_per_second,
            counters,
            ProxyDirection::ServerToClient,
        );
    });
}

fn copy_throttled(
    mut reader: TcpStream,
    mut writer: TcpStream,
    bytes_per_second: u64,
    counters: Arc<ProxyCounters>,
    direction: ProxyDirection,
) {
    let started = Instant::now();
    let mut copied = 0u64;
    let mut buf = [0u8; 16 * 1024];
    let mut frame_tracker = match direction {
        ProxyDirection::ClientToServer => Some(ClientToServerFrameTracker::default()),
        ProxyDirection::ServerToClient => None,
    };
    loop {
        let read = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if writer.write_all(&buf[..read]).is_err() {
            break;
        }
        copied = copied.saturating_add(read as u64);
        match direction {
            ProxyDirection::ClientToServer => {
                counters
                    .client_to_server_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
                if let Some(tracker) = frame_tracker.as_mut() {
                    if tracker.observe(&buf[..read]) {
                        let _ = counters
                            .first_file_slice_client_to_server_bytes
                            .compare_exchange(0, copied, Ordering::Relaxed, Ordering::Relaxed);
                    }
                }
            }
            ProxyDirection::ServerToClient => {
                counters
                    .server_to_client_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
            }
        }
        throttle_copy(started, copied, bytes_per_second);
    }
    let _ = writer.shutdown(Shutdown::Write);
}

#[derive(Default)]
struct ClientToServerFrameTracker {
    buffered: Vec<u8>,
}

impl ClientToServerFrameTracker {
    fn observe(&mut self, bytes: &[u8]) -> bool {
        self.buffered.extend_from_slice(bytes);
        let mut saw_file_slice = false;
        loop {
            if self.buffered.len() < 4 {
                break;
            }
            let frame_len = u32::from_be_bytes(self.buffered[..4].try_into().unwrap()) as usize;
            if frame_len > CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES {
                self.buffered.clear();
                break;
            }
            let frame_end = 4 + frame_len;
            if self.buffered.len() < frame_end {
                break;
            }
            if is_file_slice_connection_frame(&self.buffered[4..frame_end]) {
                saw_file_slice = true;
            }
            self.buffered.drain(..frame_end);
        }
        saw_file_slice
    }
}

fn is_file_slice_connection_frame(frame: &[u8]) -> bool {
    frame.len() == CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES
        && frame.get(..4) == Some(b"TRNS".as_slice())
        && frame.get(4).copied() == Some(CONNECTION_FRAME_VERSION)
        && frame.get(5).copied() == Some(CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE)
}

#[test]
fn client_to_server_frame_tracker_detects_file_slice_frames_across_chunks() {
    let mut tracker = ClientToServerFrameTracker::default();
    let small_frame = length_prefixed_test_frame(64, 0);
    let file_slice_frame = length_prefixed_test_frame(
        CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES,
        CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
    );
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&small_frame);
    bytes.extend_from_slice(&file_slice_frame);

    assert!(!tracker.observe(&bytes[..3]));
    assert!(!tracker.observe(&bytes[3..small_frame.len() + 12]));
    assert!(tracker.observe(&bytes[small_frame.len() + 12..]));
}

fn length_prefixed_test_frame(frame_len: usize, size_class: u8) -> Vec<u8> {
    let mut frame = vec![0; frame_len];
    frame[..4].copy_from_slice(b"TRNS");
    frame[4] = CONNECTION_FRAME_VERSION;
    frame[5] = size_class;

    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(&frame);
    out
}

fn throttle_copy(started: Instant, copied: u64, bytes_per_second: u64) {
    let expected = Duration::from_secs_f64(copied as f64 / bytes_per_second as f64);
    if let Some(delay) = expected.checked_sub(started.elapsed()) {
        if delay > Duration::from_millis(1) {
            thread::sleep(delay);
        }
    }
}

fn wait_for_proxy_client_to_server_above(
    proxy: &ThrottledTcpProxy,
    baseline: u64,
    timeout_ms: u64,
) -> Instant {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if proxy.client_to_server_bytes() > baseline {
            return Instant::now();
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("proxy client-to-server bytes never advanced above {baseline}");
}

fn wait_for_proxy_first_file_slice_client_to_server(
    proxy: &ThrottledTcpProxy,
    timeout_ms: u64,
) -> Instant {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if proxy.first_file_slice_client_to_server_bytes() > 0 {
            return Instant::now();
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("proxy client-to-server stream never observed a file-slice connection frame");
}

fn bytes_per_second(mbps: f64) -> u64 {
    ((mbps * 1_000_000.0) / 8.0).round().max(1.0) as u64
}

fn download_timeout_ms(payload_mib: usize, mbps: f64) -> u64 {
    let payload_bytes = payload_mib as f64 * 1024.0 * 1024.0;
    let expected_transfer_ms = payload_bytes * 8.0 / (mbps * 1_000_000.0) * 1000.0;
    (expected_transfer_ms * 8.0).round().max(120_000.0) as u64
}

fn env_f64(name: &str) -> Option<f64> {
    std::env::var(name).ok().map(|value| {
        let parsed = value
            .parse::<f64>()
            .unwrap_or_else(|_| panic!("{name} must be a positive number"));
        assert!(
            parsed.is_finite() && parsed > 0.0,
            "{name} must be a positive finite number"
        );
        parsed
    })
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer"))
        })
        .filter(|value| *value > 0)
}

fn patterned_payload(slices: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(FILE_SLICE_PLAINTEXT_BYTES * slices);
    for slice_idx in 0..slices {
        for offset in 0..FILE_SLICE_PLAINTEXT_BYTES {
            payload.push(
                (slice_idx as u8)
                    .wrapping_mul(17)
                    .wrapping_add((offset % 251) as u8),
            );
        }
    }
    payload
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

fn create_workspace(db: &str, name: &str, username: &str, device_name: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
    ]));
    let workspace_id = line_value(&out, "workspace_id");
    let _daemon = spawn_daemon(db, free_port());
    wait_for_users_contains(db, &workspace_id, username);
    wait_for_identity_contains(db, "endpoint_role=device");
    workspace_id
}

fn accept_workspace_invite(
    host_db: &str,
    joiner_db: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let invite = workspace_invite_for_addr(host_db, workspace_id, port);
    let accepted = match try_accept_with_identity_retry(joiner_db, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => panic!("workspace invite accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    poll_for_workspace_member(joiner_db, workspace_id, username, 10_000);
}

struct RunningDaemon {
    child: Child,
    label: String,
    stdout: Option<JoinHandle<String>>,
    stderr: Option<JoinHandle<String>>,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            if let Ok(text) = stderr.join() {
                if !text.trim().is_empty() {
                    eprintln!("[daemon-stderr label={}] {}", self.label, text.trim_end());
                }
            }
        }
    }
}

impl RunningDaemon {
    fn assert_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!("daemon {} exited early: {status}", self.label),
            Err(err) => panic!("poll daemon {}: {err}", self.label),
        }
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    spawn_daemon_with_sync_ms(db, port, 100)
}

fn spawn_daemon_with_sync_ms(db: &str, port: u16, sync_ms: u64) -> RunningDaemon {
    let port_str = port.to_string();
    let sync_ms = sync_ms.to_string();
    for _ in 0..20 {
        let mut child = spawn_topo(&[
            "--db",
            db,
            "start",
            "--listen",
            "127.0.0.1",
            &port_str,
            "--sync-ms",
            &sync_ms,
            "--quiet-ms",
            "100",
        ]);
        let stdout = child.stdout.take().expect("daemon stdout");
        let stderr = child.stderr.take().expect("daemon stderr");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read daemon line");
        if line.starts_with("listening: ") {
            let stdout_handle = thread::spawn(move || {
                let mut text = String::new();
                let _ = reader.read_to_string(&mut text);
                text
            });
            let stderr_handle = thread::spawn(move || {
                let mut reader = BufReader::new(stderr);
                let mut text = String::new();
                let _ = reader.read_to_string(&mut text);
                text
            });
            return RunningDaemon {
                child,
                label: format!("{db}@{port}"),
                stdout: Some(stdout_handle),
                stderr: Some(stderr_handle),
            };
        }
        let mut stderr_reader = BufReader::new(stderr);
        let mut stderr_text = String::new();
        let _ = stderr_reader.read_to_string(&mut stderr_text);
        let _ = child.wait();
        if stderr_text.contains("Address already in use") {
            thread::sleep(Duration::from_millis(250));
            continue;
        }
        panic!("daemon did not report listening: {line}\nstderr:\n{stderr_text}");
    }
    panic!("daemon did not report listening after retrying port {port}");
}

fn wait_for_daemon_lock_release(db: &str) {
    let _ = topo(&["--db", db, "stop"]);
    let lock = format!("{db}.daemon.lock");
    for _ in 0..100 {
        if !std::path::Path::new(&lock).exists() {
            thread::sleep(Duration::from_millis(250));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon lock was not released for {db}");
}

fn try_accept_with_identity_retry(
    db: &str,
    invite: &str,
    username: &str,
    device_name: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept",
            invite,
            "--username",
            username,
            "--devicename",
            device_name,
        ]);
        if output.status.success() {
            return Ok(stdout(&output));
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

fn generate(db: &str, workspace: &str, count: usize, size: usize) -> String {
    let count = count.to_string();
    let size = size.to_string();
    assert_success(topo(&["--db", db, "generate", workspace, &count, &size]))
}

fn assert_content_count(db: &str, workspace: &str, expected: usize) {
    let out = assert_success(topo(&["--db", db, "content-count", workspace]));
    assert_eq!(
        line_value(&out, "content_messages"),
        expected.to_string(),
        "content-count output:\n{out}"
    );
}

fn assert_message_fact_count(db: &str, workspace: &str, expected: usize) {
    let out = assert_success(topo(&["--db", db, "content-count", workspace]));
    assert_eq!(
        line_value(&out, "message_facts"),
        expected.to_string(),
        "content-count output:\n{out}"
    );
}

fn poll_for_content_count_at_least(
    db: &str,
    workspace: &str,
    expected: usize,
    timeout_ms: u64,
) -> usize {
    let expected = expected.to_string();
    let timeout_ms = timeout_ms.to_string();
    let out = assert_success(topo(&[
        "--db",
        db,
        "assert",
        "eventually",
        "content-count",
        workspace,
        "content_messages",
        "gte",
        &expected,
        "--timeout-ms",
        &timeout_ms,
        "--poll-ms",
        "100",
    ]));
    line_value(&out, "observed")
        .parse()
        .expect("observed content_messages usize")
}

fn wait_for_content_count(db: &str, workspace: &str, expected: usize) {
    let expected = expected.to_string();
    assert_success(topo(&[
        "--db",
        db,
        "assert",
        "eventually",
        "content-count",
        workspace,
        "content_messages",
        "eq",
        &expected,
        "--timeout-ms",
        "60000",
        "--poll-ms",
        "100",
    ]));
}

fn wait_for_message_fact_count(db: &str, workspace: &str, expected: usize) {
    let expected = expected.to_string();
    assert_success(topo(&[
        "--db",
        db,
        "assert",
        "eventually",
        "content-count",
        workspace,
        "message_facts",
        "eq",
        &expected,
        "--timeout-ms",
        "60000",
        "--poll-ms",
        "100",
    ]));
}
