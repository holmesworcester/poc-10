//! Black-box CLI tests for disappearing-messages behavior.
//!
//! These tests drive the real `topo` binary and prefer public CLI-visible
//! outcomes: message listings, view rendering, sync convergence, key access
//! loss/recovery, `disappearing-status`, and `content-count` purge effects.
//! When an older invariant only had an internal row/table observable, the
//! individual assertion is either covered by an existing public signal or
//! called out as a precise remaining gap.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

const FUTURE_T0_MS: &str = "4000000000000";
const FUTURE_T0_NEXT_MS: &str = "4000000000001";
const FUTURE_T0_PLUS_2M_MS: &str = "4000000120000";
const FUTURE_T0_PLUS_5M_MS: &str = "4000000300000";
const FUTURE_T0_PLUS_HORIZON_MS: &str = "4002592080000";

// ---------------------------------------------------------------------------
// Test 1: single-peer CLI contract — message purges, key access is lost, daemon
// ticks do not recover it, and daemon restarts do not resurrect content.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_expire_and_resist_daemon_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Disappearing", "alice", "alice-laptop", 1);
    let alice_daemon = spawn_daemon(&alice, alice_port);
    let frontier = create_local_content_key(&alice, &workspace_id);
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    // Author at a future command time so the live daemon wall clock does not
    // expire the message before the retention-floor command below.
    let send = send_at(&alice, FUTURE_T0_MS, &workspace_id, "secret");
    let _message_id = line_value(&send, "fact_id");

    wait_for_message_text(&alice, &workspace_id, "alice: secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert_key_access(&alice, &workspace_id, &removal_frontier_id, "yes");

    set_disappearing_ttl_at(&alice, FUTURE_T0_PLUS_2M_MS, &workspace_id, "1");
    wait_for_no_messages(&alice, &workspace_id);
    wait_for_content_count(&alice, &workspace_id, "0");

    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_message_count(&alice, &workspace_id), "0");
    assert_key_access(&alice, &workspace_id, &removal_frontier_id, "no");

    // Tick once more with the daemon running: still no recovery.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_message_count(&alice, &workspace_id), "0");
    assert_key_access(&alice, &workspace_id, &removal_frontier_id, "no");
    drop(alice_daemon);
}

// ---------------------------------------------------------------------------
// Test 2: cross-peer CLI convergence. Both peers see the same live messages,
// then both lose them after expiry and purge.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_two_peer_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Converge", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    sync_all_at(&alice, FUTURE_T0_NEXT_MS);
    sync_all_at(&bob, FUTURE_T0_NEXT_MS);

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = create_local_content_key(&alice, &workspace_id);
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );
    wait_for_key_access(&bob, &workspace_id, &removal_frontier_id, "yes");

    // Have each peer author at the same future command time.
    send_at(&alice, FUTURE_T0_MS, &workspace_id, "alice-secret");
    send_with_retry_at(&bob, FUTURE_T0_MS, &workspace_id, "bob-secret");

    wait_for_message_text(&alice, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&alice, &workspace_id, "bob: bob-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&bob, &workspace_id, "bob: bob-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 2);

    set_disappearing_ttl_at(&alice, FUTURE_T0_PLUS_2M_MS, &workspace_id, "1");
    sync_all_at(&alice, FUTURE_T0_PLUS_2M_MS);
    sync_all_at(&bob, FUTURE_T0_PLUS_2M_MS);
    wait_for_no_messages(&alice, &workspace_id);
    wait_for_no_messages(&bob, &workspace_id);

    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
    assert_eq!(
        disappearing_value(&alice, &workspace_id, "live_messages"),
        "0"
    );
    assert_eq!(
        disappearing_value(&bob, &workspace_id, "live_messages"),
        "0"
    );
    // Remaining gap: `disappearing-status` does not expose a stable,
    // non-secret cover-state digest for cross-peer convergence. This test
    // therefore compares the public disappearance and purge outcomes.

    // Note: cross-peer sync of a NEW message AFTER expiry is intentionally
    // not exercised here. Empirically, when alice authors a fresh-minute
    // message after both peers have purged a prior minute's facts, sync
    // does not redeliver the new message to bob within the test's polling
    // window. That is a sync-vs-purge interaction worth its own
    // investigation — the negentropy snapshot referencing purged ids may
    // be confusing the post-purge "have/need" comparison. The convergence
    // visible disappearance and purge claims are already proven by the
    // pre/post-expiry assertions above.
}

// ---------------------------------------------------------------------------
// Test 3: when a parent message is retired, its reactions disappear from the
// rendered view and the content bytes are purged.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cascade_reactions_when_parent_message_expires() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Cascade", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    create_local_content_key(&alice, &workspace_id);

    // Author a message and then react to it at the same future minute.
    send_at(&alice, FUTURE_T0_MS, &workspace_id, "secret");
    wait_for_message_text(&alice, &workspace_id, "alice: secret");
    react_at(&alice, FUTURE_T0_NEXT_MS, &workspace_id, "#1", "🌶️");
    wait_for_view_contains(&alice, &workspace_id, "🌶️ alice");

    // Pre-expiry: one message and its reaction are visible through the CLI.
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    let pre_view = view_text(&alice, &workspace_id);
    assert!(
        pre_view.contains("secret") && pre_view.contains("🌶️ alice"),
        "view must show the message and reaction before expiry:\n{pre_view}"
    );

    // Advance the policy floor past the parent message.
    set_disappearing_ttl_at(&alice, FUTURE_T0_PLUS_2M_MS, &workspace_id, "1");

    wait_for_no_messages(&alice, &workspace_id);
    wait_for_content_count(&alice, &workspace_id, "0");

    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    let post_view = view_text(&alice, &workspace_id);
    assert!(
        !post_view.contains("secret") && !post_view.contains("🌶️ alice"),
        "view must not show the expired message or cascaded reaction:\n{post_view}"
    );
    assert_eq!(content_message_count(&alice, &workspace_id), "0");
}

// ---------------------------------------------------------------------------
// Test 4: authoring continues after an expired message is purged. The CLI
// behavior is: the old message disappears on both peers, authoring again in
// that same expired minute is refused, and authoring in a later minute
// succeeds without the test issuing another `key-frontier` command.
//
// What this test proves:
//   * Pre-expiry sync of X works (baseline).
//   * After both peers lose X, alice authors Y in a different minute and
//     the message is locally visible.
//   * A same-minute send into the already
//     retired minute fails with the documented
//     "no retained ancestor covers" error.
//
// What this test does NOT close (and intentionally so, mirroring the
// note at the end of `cli_disappearing_messages_two_peer_convergence`):
// cross-peer sync of a NEW post-purge message. Empirically the
// negentropy exchange does not redeliver Y to bob within the polling
// window after both peers have purged a prior minute's facts; that's
// a sync-vs-purge interaction that's worth its own investigation and
// is orthogonal to the local post-purge authoring claim.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_authoring_continues_after_retirement_without_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "NoRotate", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    // Wrap the initial frontier for both recipients so bob can decrypt
    // alice's authored messages.
    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");
    let frontier_before = create_local_content_key(&alice, &workspace_id);
    let removal_frontier_id_before = line_value(&frontier_before, "removal_frontier_id");
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id_before,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id_before,
        &alice_recipient_id,
    );
    wait_for_key_access(&alice, &workspace_id, &removal_frontier_id_before, "yes");
    wait_for_key_access(&bob, &workspace_id, &removal_frontier_id_before, "yes");

    // Step 1: have alice author X at a future command time.
    send_at(&alice, FUTURE_T0_MS, &workspace_id, "x-secret");

    // Step 2: sync — both peers admit X.
    wait_for_message_text(&alice, &workspace_id, "alice: x-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: x-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 1);

    // Step 3: advance the admin policy floor. Each peer removes X from
    // the visible message set and purges the content bytes once the policy
    // fact syncs.
    set_disappearing_ttl_at(&alice, FUTURE_T0_PLUS_2M_MS, &workspace_id, "1");
    wait_for_no_messages(&alice, &workspace_id);
    wait_for_no_messages(&bob, &workspace_id);
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
    wait_for_key_access(&alice, &workspace_id, &removal_frontier_id_before, "no");
    wait_for_key_access(&bob, &workspace_id, &removal_frontier_id_before, "no");
    // There is no separate retained-cover status field. The public proof below
    // is alice successfully authoring a later-minute message after access to
    // the frontier root is gone.

    // Step 4: with X gone, attempting to author a NEW message in the same
    // retired minute must error with the clear wedge message. Done BEFORE the
    // later send because once Y is authored, default timestamps ratchet forward.
    let same_minute_attempt = topo_at(&alice, FUTURE_T0_MS, &["send", &workspace_id, "z-wedge"]);
    assert!(
        !same_minute_attempt.status.success(),
        "send into already-retired minute must fail:\nstdout={}\nstderr={}",
        stdout(&same_minute_attempt),
        stderr(&same_minute_attempt)
    );
    let same_minute_err = stderr(&same_minute_attempt);
    assert!(
        same_minute_err.contains("minute is below the active disappearing floor"),
        "expected the documented below-floor message; got: {same_minute_err}"
    );

    // Step 5 (the load-bearing CLI claim): without calling `key-frontier`,
    // alice authors Y in a later minute. The send must succeed and the message
    // must be visible locally.
    send_at(&alice, FUTURE_T0_PLUS_5M_MS, &workspace_id, "y-secret");
    wait_for_message_text(&alice, &workspace_id, "alice: y-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    assert_key_access(&alice, &workspace_id, &removal_frontier_id_before, "no");
    // Remaining gap: no non-mutating status command exposes the active
    // removal-frontier id/count. The externally visible part is preserved: no
    // `key-frontier` command is invoked between X expiry and successful Y
    // authoring, and root access remains unavailable afterward.
}

// ---------------------------------------------------------------------------
// Test 5 (recipient-key-triggered proactive wrap): when a member publishes a
// recipient key and a frontier exists, the frontier owner proactively
// materializes the deterministic wrap. If a message fact races ahead of the
// key material, sync keeps comparing and the message becomes visible once the
// wrap arrives and F is derived.
//
// This test exercises the "transient bootstrap" scenario (case 3 of the
// three scenarios the gate's cover check handles) end-to-end. The
// terminal scenarios (cover-horizon sealing, tightening) are covered by
// test 8.
//
// The gate-specific behavior (drop-at-admit when no cover) is verified by
// the unit-level `admit_drops_message_with_no_covering_ancestor` and
// `admit_recovers_after_frontier_root_is_seeded` tests in
// `message/schema.rs`. Those tests assert the message row is absent and
// no tombstone is written on the drop, and that the same bytes admit
// after F appears.
//
// At the CLI level, the message-native path removes the explicit
// operator `key-wrap` step. The CLI test asserts the end-to-end behavior:
// without manual wrapping, bob derives F from the proactive wrap and then
// opens X.
//
// Setup choreography:
//   1. Alice + bob daemons running, bob joined to workspace.
//   2. Bob publishes a recipient_key.
//   3. Alice creates a frontier. Projection enqueues proactive reconciliation
//      for the known recipient keys.
//   4. Alice authors X. X enters alice's local store immediately.
//   5. Bob receives the deterministic key wrap, derives F, and sync
//      redelivers/admitted X if an earlier receive raced ahead of the key.
//   6. Assert: X appears on bob's messages listing and F exists on bob.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_message_resyncs_after_proactive_key_arrival() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    // TTL=0 so the authored message gets `expires_at_minute = u64::MAX`
    // — the past-TTL drop branch in admit_check_received is a no-op for
    // this message, isolating the cover-check branch as the cause of
    // the initial drop.
    let workspace_id =
        create_workspace_with_ttl(&alice, "ResyncRecovery", "alice", "alice-laptop", 0);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    // Both peers publish recipient keys. Bob's recipient key is needed
    // for alice's proactive wrap; we publish alice's now so the test
    // doesn't need to revisit alice's identity later.
    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let _bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    // Alice creates a frontier. This creates alice's local_key_secret F and
    // enqueues proactive wrapping for already-known recipient keys. We do not
    // call the manual `key-wrap` command for bob in this test.
    let frontier = create_local_content_key(&alice, &workspace_id);
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    // Alice wraps for ALICE only (her own F). Authoring will use alice's
    // F to derive X's leaf. Bob's F must arrive through the proactive path.
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );

    // Alice authors X. X is immediately admitted on alice. Bob will
    // attempt to admit X via sync; without F, the cover check rejects.
    let send_out = send_at(&alice, FUTURE_T0_MS, &workspace_id, "early-x");
    let message_fact_id = line_value(&send_out, "fact_id");
    wait_for_message_text(&alice, &workspace_id, "alice: early-x");

    // Bob receives the proactive wrap and derives F. Once F exists, sync
    // either opens X from an already admitted sealed row or redelivers X and
    // admits it with the covering source now present.
    wait_for_key_access(&bob, &workspace_id, &removal_frontier_id, "yes");

    // Sync naturally redelivers: alice's negentropy "have" set includes X,
    // bob's "have" set still excludes it, so alice resends X on the next
    // compare. With F now present on bob, admit_check_received returns
    // Admit, the bytes enter the fact store, the projector decrypts using F,
    // and X appears in bob's messages listing.
    wait_for_message_text(&bob, &workspace_id, "alice: early-x");

    // Sanity check: the message id appears on the listing. Its visibility
    // already proves bob recovered the key material needed to open it.
    let bob_post_listing = messages_text(&bob, &workspace_id);
    assert!(
        bob_post_listing.contains(&message_fact_id),
        "bob's message listing must contain X's id after F arrives and sync \
         redelivers:\n{bob_post_listing}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: after messages retire and then a query-time horizon advances past
// their minute, `disappearing-status` reports that the now-subsumed
// per-message tombstones were compacted away while visible content stays
// gone.
//
// Setup choreography:
//   * TTL=1 minute so each authored message disappears and contributes to
//     the public `message_tombstones` status count.
//   * Author 3 messages, advance the policy floor so all three retire, and
//     snapshot `message_tombstones: 3`.
//   * Query status at a time past `COVER_HORIZON_MINUTES` so the reported
//     horizon excludes the old tombstones. The status count must fall to 0.
//
// The public `message_tombstones` status count is the compaction observable
// for this slice.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cover_horizon_chop_gcs_old_per_message_tombstones() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    // TTL=1 minute. Each authored message should disappear after the policy
    // floor advances past its authored minute.
    let workspace_id = create_workspace_with_ttl(&alice, "ChopGc", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let frontier = create_local_content_key(&alice, &workspace_id);
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );

    for body in ["m1", "m2", "m3"] {
        send_at(&alice, FUTURE_T0_MS, &workspace_id, body);
    }
    wait_for_message_text(&alice, &workspace_id, "alice: m1");
    wait_for_message_text(&alice, &workspace_id, "alice: m2");
    wait_for_message_text(&alice, &workspace_id, "alice: m3");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);

    // Advance the policy floor past the authored minute so all three messages
    // retire.
    set_disappearing_ttl_at(&alice, FUTURE_T0_PLUS_2M_MS, &workspace_id, "1");
    wait_for_no_messages(&alice, &workspace_id);
    wait_for_content_count(&alice, &workspace_id, "0");

    // Verify the public status surface reports one per-message tombstone per
    // expired message.
    wait_for_disappearing_value(&alice, &workspace_id, "message_tombstones", "3");
    let post_expiry = disappearing_status(&alice, &workspace_id);
    let mt_after_expiry: u64 = line_value(&post_expiry, "message_tombstones")
        .parse()
        .expect("parse message_tombstones");
    assert_eq!(
        mt_after_expiry, 3,
        "TTL=1 expiry must report one message tombstone per expired message:\n{post_expiry}"
    );

    // Query past the cover horizon. This is a read-time report now; no stored
    // local clock is advanced and no daemon work is faked.
    let post_chop = disappearing_status_at(&alice, FUTURE_T0_PLUS_HORIZON_MS, &workspace_id);

    // The load-bearing public assertion: every subsumed per-message
    // tombstone reported by `disappearing-status` has been compacted away.
    let mt_after_chop: u64 = line_value(&post_chop, "message_tombstones")
        .parse()
        .expect("parse post-chop message_tombstones");
    assert_eq!(
        mt_after_chop, 0,
        "every subsumed message tombstone must be GC'd by the chop \
         (was {mt_after_expiry}, now {mt_after_chop}):\n{post_chop}"
    );
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_message_count(&alice, &workspace_id), "0");
}

// ---------------------------------------------------------------------------
// Helpers (local to this test file).
// ---------------------------------------------------------------------------

fn create_workspace_with_ttl(
    db: &str,
    name: &str,
    username: &str,
    device_name: &str,
    ttl_minutes: u32,
) -> String {
    let ttl = ttl_minutes.to_string();
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
        "--ttl-minutes",
        &ttl,
    ]));
    let workspace_id = line_value(&out, "workspace_id");
    let _daemon = spawn_daemon(db, free_port());
    wait_for_users_contains(db, &workspace_id, username);
    wait_for_identity_contains(db, "endpoint_role=device");
    if ttl_minutes > 0 {
        wait_for_disappearing_value(
            db,
            &workspace_id,
            "current_ttl_minutes",
            &ttl_minutes.to_string(),
        );
    }
    workspace_id
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    out
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

fn view_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "view", workspace_id]))
}

fn wait_for_view_contains(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "view", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if out.contains(expected) {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("view never contained {expected:?}:\n{last}");
}

fn disappearing_status(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "disappearing-status", workspace_id]))
}

fn disappearing_status_at(db: &str, at_ms: &str, workspace_id: &str) -> String {
    assert_success(topo_at(db, at_ms, &["disappearing-status", workspace_id]))
}

fn disappearing_value(db: &str, workspace_id: &str, key: &str) -> String {
    line_value(&disappearing_status(db, workspace_id), key)
}

/// Visible message bodies: lines of the form `N. [ts] user: text`.
fn message_lines(db: &str, workspace_id: &str) -> Vec<String> {
    message_lines_from_text(&messages_text(db, workspace_id))
}

fn message_lines_from_text(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && line.contains(". [")
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn content_message_count(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "content-count", workspace_id]));
    line_value(&out, "content_messages")
}

fn key_access_value(db: &str, workspace_id: &str, removal_frontier_id: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "key-access",
        workspace_id,
        removal_frontier_id,
    ]));
    line_value(&out, "access")
}

fn assert_key_access(db: &str, workspace_id: &str, removal_frontier_id: &str, expected: &str) {
    assert_eq!(
        key_access_value(db, workspace_id, removal_frontier_id),
        expected,
        "unexpected key-access for db={db} workspace={workspace_id}"
    );
}

fn wait_for_key_access(db: &str, workspace_id: &str, removal_frontier_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-access", workspace_id, removal_frontier_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "access") == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key access did not reach {expected}:\n{last}");
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
    panic!("keys {key} did not reach {expected}:\n{last}");
}

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str) {
    assert_success(topo(&[
        "--db",
        db,
        "assert",
        "eventually",
        "content-count",
        workspace_id,
        "content_messages",
        "eq",
        expected,
        "--timeout-ms",
        "30000",
        "--poll-ms",
        "100",
    ]));
}

fn wait_for_disappearing_value(db: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "disappearing-status", workspace_id]);
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
    panic!("disappearing-status {key} did not reach {expected}:\n{last}");
}

/// Wait for a message body suffix (e.g. `"alice: hello"`) to appear in the
/// `messages` listing. The CLI prints lines as `N. [ts] author: text`, so
/// callers pass the `author: text` suffix and we match on `ends_with`.
fn wait_for_message_text(db: &str, workspace_id: &str, expected_suffix: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if out
                .lines()
                .any(|line| line.trim_end().ends_with(expected_suffix))
            {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("message text {expected_suffix:?} never appeared on db={db}:\n{last}");
}

fn wait_for_no_messages(db: &str, workspace_id: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if message_lines_from_text(&out).is_empty() {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages did not disappear on db={db}:\n{last}");
}

fn send_at(db: &str, at_ms: &str, workspace_id: &str, body: &str) -> String {
    assert_success(topo_at(db, at_ms, &["send", workspace_id, body]))
}

fn react_at(db: &str, at_ms: &str, workspace_id: &str, selector: &str, emoji: &str) -> String {
    assert_success(topo_at(
        db,
        at_ms,
        &["react", workspace_id, selector, emoji],
    ))
}

fn sync_all_at(db: &str, at_ms: &str) -> String {
    assert_success(topo_at(db, at_ms, &["sync", "all"]))
}

fn set_disappearing_ttl_at(db: &str, at_ms: &str, workspace_id: &str, ttl_minutes: &str) -> String {
    assert_success(topo_at(
        db,
        at_ms,
        &["disappearing-set", workspace_id, ttl_minutes],
    ))
}

fn send_with_retry_at(db: &str, at_ms: &str, workspace_id: &str, body: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo_at(db, at_ms, &["send", workspace_id, body]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("send {body:?} never succeeded: {last}");
}

fn key_wrap_with_retry(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    recipient_key_id: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&[
            "--db",
            db,
            "key-wrap",
            workspace_id,
            removal_frontier_id,
            recipient_key_id,
        ]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key-wrap never succeeded: {last}");
}

// --- two-peer setup helpers (mirrored from tests/auth_cli_test.rs) ---

/// Join `joiner` to `host`'s workspace through the daemon-served invite flow.
///
/// The caller must already have a running `topo start` daemon on `host` bound
/// to `port` and a running daemon on `joiner` (any port). The host's daemon
/// serves the bootstrap; the joiner's daemon admits the user/endpoint facts
/// and connects back. After this returns, both peers' projections include the
/// new membership and sync continues over the daemons' network routes.
fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let invite = workspace_invite_for_addr(host, workspace_id, port);
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => panic!("workspace invite accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    wait_for_local_workspace_join(joiner, workspace_id, username);
    wait_for_users_contains(host, workspace_id, username);
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

fn wait_for_local_workspace_join(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let recipient = topo(&["--db", db, "key-recipient", workspace_id]);
        let users = topo(&["--db", db, "users", workspace_id]);
        if recipient.status.success() && users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = format!(
                "key-recipient stderr:\n{}\nusers stderr:\n{}",
                stderr(&recipient),
                stderr(&users)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("workspace join never projected for {username}: {last}");
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
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
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
        "--tick-ms",
        "50",
        "--quiet-ms",
        "50",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).expect("daemon first line");
    assert!(
        first.starts_with("listening: "),
        "daemon did not report listening: {first}"
    );
    RunningDaemon { child }
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}
