//! Black-box CLI tests for disappearing-messages forward secrecy.
//!
//! Drives the real `topo` binary and asserts observable forward-secrecy
//! and convergence behavior through public CLI output. The tests
//! intentionally do not seed protocol rows or call workers directly.
//!
//! The shipped surface tested here:
//!   * `create-workspace ... --ttl-minutes <u32>` plumbs a workspace-wide
//!     TTL into authored messages (slice 1 fallback).
//!   * `disappearing-set <ws> <ttl_minutes>` admin-signed setting event
//!     supersedes the workspace-event TTL for new authoring (slice 2).
//!   * `MessageEvent` canonical bytes carry `expires_at_minute: u64`
//!     (`u64::MAX` = no expiry) and `disappearing_setting_id: EventId`
//!     referencing the policy under which the message was authored.
//!     The projector validates the stamp against the referenced
//!     policy's permitted ttl_minutes (slice 3).
//!   * `disappearing_minute_expiry` daemon-step worker retires
//!     per-message and per-reaction leaves and triggers `content_purge`
//!     cascade for reactions/files/slices (slices 1 + 4).
//!   * The message projector reads `now_unix_minute` from
//!     `EventContext` and tombstones expired-at-receive messages with a
//!     deletion label so re-arrivals can't resurrect them.
//!
//! Known gaps these tests do NOT close (covered by future work or
//! documented as out of scope in `disappearing_messages_plan.md` §6):
//!   * Latest-setting enforcement — peers can pick any admitted setting
//!     as the per-message reference, including older more-permissive
//!     ones. Honest authors always pick the latest; closing the gap
//!     needs an "epoch" mechanism (time-based, logical-order, or
//!     counter-based).
//!   * A canonical-bytes-by-event-id query (`events get <id>`) for a
//!     direct purge proof. The current strongest signal is
//!     `content-count` dropping to 0 and `keys` row counts collapsing.
//!   * Offline-expire isolation. With both daemons connected the test
//!     cannot observe whether each peer's expiry decision was reached
//!     locally or sneaked across the wire. (No expiry events sync —
//!     each peer derives retirement from canonical-bytes equality of
//!     the original messages.)
//!   * Per-tombstone-row byte-equality across peers. The tests verify
//!     tombstone-count equality and `cover_summary` equality, but the
//!     actual `LOCAL_HISTORY_NODE_TOMBSTONES` rows are not surfaced by
//!     the current `keys` CLI.
//!   * Whole-minute leaf retirement. Today the worker calls
//!     `RetireDeletedEventLeaf` per message + per reaction; the
//!     `src/workers/encryption.rs:1147` TODO ("whole-minute
//!     retirement") would consolidate to one tombstone per minute.
//!     With per-message TTLs, leaves in the same minute can have
//!     different stamped expiries, so the optimization only pays off
//!     for a fixed workspace TTL.

mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

// ---------------------------------------------------------------------------
// Test 1: single-peer FS contract — keys retired, message purged, cover
// changes, AND a daemon restart cannot resurrect the expired message.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_expire_and_resist_rederive() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Disappearing", "alice", "alice-laptop", 1);
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");

    // Pin clock to unix_minute 100 (ms = 6_000_000). TTL=1 ⇒ expires at
    // minute 101; minute 102 is safely past expiry.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let send = assert_success(topo(&["--db", &alice, "send", &workspace_id, "secret"]));
    let _message_id = line_value(&send, "event_id");

    // Pre-expiry baseline. The new binary-tree schema only materializes
    // leaves for active messages; the minute_node above them stays implicit
    // until a delete forces it to be durably named, so we don't assert a
    // count for `local_history_minute_nodes` here.
    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre, "local_history_node_tombstones"), "0");
    let pre_summary = cover_summary_value(&pre);
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert!(messages_text(&alice, &workspace_id).contains("alice: secret"));

    let alice_daemon = spawn_daemon(&alice, alice_port);

    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    // Slice 1 retires one leaf per expired message. Wait until the leaf
    // row is gone; tombstone rows are an internal mechanism and slice 1
    // does not contract on a specific count (the encryption worker only
    // writes a tombstone when the retirement also materializes siblings
    // for an in-minute survivor, which doesn't happen for the last leaf
    // in its minute).
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Post-expiry assertions.
    let post = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&post, "local_history_leaves"), "0");
    let post_summary = cover_summary_value(&post);
    assert_ne!(pre_summary, post_summary);
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");

    // Stop the daemon and confirm the on-disk state still resists recovery.
    drop(alice_daemon);
    // Re-run key-derive: zero new wrap derivations.
    let derive = assert_success(topo(&["--db", &alice, "key-derive"]));
    assert_eq!(
        line_value(&derive, "derived_key_secrets"),
        "0",
        "rederive must not produce any new key secrets after expiry"
    );

    // The load-bearing FS claim is at the minute-node layer: even with the
    // removal-frontier `local_key_secret` still on disk, the punctured
    // minute_node must not be rederivable. Drive `key-node` for the same
    // coordinates that authoring used (range_start = unix_minute 100,
    // range_width = 1, no event_id_in_minute) and assert it cannot
    // resurrect a usable secret. Two acceptable behaviors: command refuses
    // (non-zero exit), or it succeeds without admitting any new event and
    // without surfacing a fresh `local_history_node_secret_id`. Either way,
    // the on-disk state must be byte-identical to the post-expiry state.
    let rederive = topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "100",
        "1",
    ]);
    if rederive.status.success() {
        let out = stdout(&rederive);
        assert_eq!(
            line_value(&out, "local_history_node_secret_id"),
            "none",
            "rederive must not surface a new minute_node secret:\n{out}"
        );
        assert_eq!(
            line_value(&out, "admitted_events"),
            "0",
            "rederive must not admit any new local_history_node_secret event:\n{out}"
        );
    }

    let after_restart = keys_value(&alice, &workspace_id);
    assert_eq!(
        line_value(&after_restart, "local_history_leaves"),
        "0",
        "rederive must not resurrect any retired leaf:\n{after_restart}"
    );
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    assert_eq!(
        cover_summary_value(&after_restart),
        post_summary,
        "cover_summary must be byte-identical after a rederive attempt"
    );

    // Restart the daemon and tick once more: still no recovery.
    let alice_daemon_again = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120001"]));
    thread::sleep(Duration::from_millis(300));
    let after_second_restart = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&after_second_restart, "local_history_leaves"), "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    drop(alice_daemon_again);
}

// ---------------------------------------------------------------------------
// Test 2: cross-peer convergence of cover and tombstones across two
// independently-running peers.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_two_peer_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_join_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Converge", "alice", "alice-laptop", 1);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "bob-phone",
    );

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
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
    let _ = wait_for_key_derive(&bob, "1");

    // Pin both clocks to the same unix_minute and have each peer author.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "alice-secret"]));
    assert_success(topo(&["--db", &bob, "send", &workspace_id, "bob-secret"]));

    wait_for_message_text(&alice, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&alice, &workspace_id, "bob: bob-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&bob, &workspace_id, "bob: bob-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 2);

    let pre_alice = keys_value(&alice, &workspace_id);
    let pre_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        cover_summary_value(&pre_alice),
        cover_summary_value(&pre_bob),
        "cover_summary must converge across peers pre-expiry"
    );
    // Two messages in one minute ⇒ two leaves on each peer. Minute_nodes
    // stay implicit until a delete materializes them, so we don't assert
    // a count for `local_history_minute_nodes` pre-expiry.
    assert_eq!(line_value(&pre_alice, "local_history_leaves"), "2");
    assert_eq!(line_value(&pre_bob, "local_history_leaves"), "2");

    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    // Wait for both peers to reach zero leaves; per-leaf retirement may or
    // may not produce a tombstone row depending on whether siblings forced
    // materialization, so leaf count is the load-bearing signal.
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");

    let post_alice = keys_value(&alice, &workspace_id);
    let post_bob = keys_value(&bob, &workspace_id);

    assert_eq!(
        line_value(&post_alice, "local_history_leaves"),
        "0",
        "alice's leaves must be retired post-expiry:\n{post_alice}"
    );
    assert_eq!(
        line_value(&post_bob, "local_history_leaves"),
        "0",
        "bob's leaves must be retired post-expiry:\n{post_bob}"
    );

    assert_eq!(
        cover_summary_value(&post_alice),
        cover_summary_value(&post_bob),
        "cover_summary must converge across peers post-expiry"
    );
    assert_ne!(
        cover_summary_value(&pre_alice),
        cover_summary_value(&post_alice),
        "cover_summary must change after puncture"
    );
    assert_eq!(
        line_value(&post_alice, "local_history_node_tombstones"),
        line_value(&post_bob, "local_history_node_tombstones"),
        "tombstone count must match across peers post-expiry"
    );

    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");

    // Note: cross-peer sync of a NEW message AFTER expiry is intentionally
    // not exercised here. Empirically, when alice authors a fresh-minute
    // message after both peers have purged a prior minute's events, sync
    // does not redeliver the new message to bob within the test's polling
    // window. That is a sync-vs-purge interaction worth its own
    // investigation — the negentropy snapshot referencing purged ids may
    // be confusing the post-purge "have/need" comparison. The convergence
    // claims of slice 1 (cover and tombstone) are already proven by the
    // pre/post-expiry assertions above.
}

// ---------------------------------------------------------------------------
// Test 3 (slice 2): admin-signed `disappearing_messages_setting` event
// supersedes the workspace event's initial TTL. Authoring under one TTL
// stamps that TTL into the message's canonical bytes; a later admin
// `disappearing-set` does NOT retroactively rewrite already-stamped
// messages, but DOES change the TTL stamped into subsequent messages.
//
// This is the load-bearing slice-2 invariant from `disappearing_messages_plan.md`:
// "Late arrivals do not retroactively change message expiry."
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_setting_supersedes_workspace_ttl_without_rewriting_old_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    // Workspace TTL = 1 minute at creation.
    let workspace_id =
        create_workspace_with_ttl(&alice, "Setting", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin the clock and author the first message at minute 100. This is
    // stamped under the workspace event's TTL of 1, so its
    // expires_at_minute is 101.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "early"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    // Admin authors a setting event raising TTL to 5. After the setting
    // is admitted, subsequent messages are stamped with TTL=5; the
    // previously-authored "early" message's stamped expiry is unchanged.
    assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));

    // Author the second message at the same minute 100 but after the new
    // setting. It should be stamped with expires_at_minute = 100 + 5 = 105.
    // (No clock advance — the setting takes effect immediately for the
    // next authoring.)
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "late"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);

    // Spawn the daemon and advance the clock past minute 101 but before
    // minute 105: the "early" message must expire, but the "late" message
    // must remain visible. This is the key claim — the setting did not
    // retroactively rewrite "early"'s expiry to 105, and the new message
    // really did pick up the new TTL.
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6180000"])); // minute 103

    // Wait for "early" to disappear; "late" should remain.
    for _ in 0..300 {
        let lines = message_lines(&alice, &workspace_id);
        let has_early = lines.iter().any(|line| line.ends_with("alice: early"));
        let has_late = lines.iter().any(|line| line.ends_with("alice: late"));
        if !has_early && has_late {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let lines = message_lines(&alice, &workspace_id);
    assert!(
        !lines.iter().any(|line| line.ends_with("alice: early")),
        "`early` (stamped TTL=1) must have expired by minute 103:\n{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.ends_with("alice: late")),
        "`late` (stamped TTL=5) must still be visible at minute 103:\n{lines:?}"
    );

    // Advance past minute 105 and the "late" message must also expire.
    assert_success(topo(&["--db", &alice, "clock", "set", "6360000"])); // minute 106
    for _ in 0..300 {
        let lines = message_lines(&alice, &workspace_id);
        if lines.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        message_lines(&alice, &workspace_id).len(),
        0,
        "`late` (stamped TTL=5) must have expired by minute 106"
    );
}

// ---------------------------------------------------------------------------
// Test 4 (slice 4): when a parent message expires, its reactions are
// reclaimed in the same tick via the content_purge cascade. Reactions
// don't carry their own `expires_at_minute` — they inherit by being
// authored in the same minute as the parent message, and the
// disappearing-minute worker writes a `MESSAGE_TOMBSTONES` row that
// triggers content_purge to drop reaction rows + canonical bytes for
// any message that's been tombstoned.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cascade_reactions_when_parent_message_expires() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Cascade", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Author a message and then react to it, both in unix_minute 100.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "secret"]));
    assert_success(topo(&[
        "--db", &alice, "react", &workspace_id, "#1", "🌶️",
    ]));

    // Pre-expiry: one message visible, two leaves materialized (message +
    // reaction).
    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "2");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    // Advance past minute 101 (TTL=1 ⇒ expires_at_minute=101).
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));

    // Wait for both leaves to be retired — the message's by the
    // disappearing-minute worker, the reaction's by the content_purge
    // cascade triggered by the message tombstone.
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Post-expiry assertions.
    let post = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&post, "local_history_leaves"), "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    // Both message and reaction canonical bytes are reclaimed.
    wait_for_content_count(&alice, &workspace_id, "0");
}

// ---------------------------------------------------------------------------
// Test 5 (option-5 enabling property): authoring continues after retirement
// without rotation. After clock-driven expiry retires a message and the
// retire walk wipes F's row, both peers can still author fresh messages
// in a different minute under the SAME frontier — without ever admitting
// a `key-frontier` event in between. The sibling fallback in
// `closest_retained_ancestor` (commit bdaa60f) is the enabling primitive:
// the materialized time-tree siblings cover every minute except the wiped
// one, so `derive_event_leaf` keeps working under the same frontier.
//
// What this test proves:
//   * Pre-expiry sync of X works (baseline).
//   * After both peers retire X and wipe F, alice authors Y in a
//     different minute under the same (wiped) frontier and the message
//     is locally visible (i.e. derive + AEAD sealed-write + projector
//     admit all succeed).
//   * Bob, having retired X independently, also retains the time-tree
//     sibling rows under his (wiped) frontier — those rows are what he
//     would use to decrypt a Y that arrives via sync.
//   * No new `removal_frontier` event was admitted on either peer; the
//     frontier id is byte-identical before X and after Y.
//   * Bonus / legitimate wedge: a same-minute send into the already
//     retired minute fails with the documented
//     "no retained ancestor covers" error — silently re-deriving from
//     a wiped F would defeat forward secrecy.
//
// What this test does NOT close (and intentionally so, mirroring the
// note at the end of `cli_disappearing_messages_two_peer_convergence`):
// cross-peer sync of a NEW post-purge message. Empirically the
// negentropy exchange does not redeliver Y to bob within the polling
// window after both peers have purged a prior minute's events; that's
// a sync-vs-purge interaction that's worth its own investigation and
// is orthogonal to the no-rotation claim. The bob-side sibling-row
// assertion below is the strongest cross-peer signal we can get
// without surfacing inter-peer Y delivery.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_authoring_continues_after_retirement_without_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_join_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "NoRotate", "alice", "alice-laptop", 1);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "bob-phone",
    );

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);

    // Wrap the initial frontier for both recipients so bob can decrypt
    // alice's authored messages. Snapshot the frontier id NOW so we can
    // assert later that no new removal_frontier event has been admitted
    // between authoring of X and authoring of Y.
    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");
    let frontier_before = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
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
    let _ = wait_for_key_derive(&bob, "1");
    let removal_frontiers_pre =
        line_value(&keys_value(&alice, &workspace_id), "removal_frontiers");
    assert_eq!(
        removal_frontiers_pre, "1",
        "precondition: exactly one removal_frontier exists at start"
    );

    // Step 1: pin both clocks to minute 100 (ms = 6_000_000) and have alice
    // author X. TTL=1 ⇒ X expires at minute 101.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "x-secret"]));

    // Step 2: sync — both peers admit X.
    wait_for_message_text(&alice, &workspace_id, "alice: x-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: x-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 1);

    let pre_alice = keys_value(&alice, &workspace_id);
    let pre_bob = keys_value(&bob, &workspace_id);
    assert_eq!(line_value(&pre_alice, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre_bob, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre_alice, "local_key_secrets"), "1");
    assert_eq!(line_value(&pre_bob, "local_key_secrets"), "1");

    // Step 3: advance both clocks past minute 101. The
    // disappearing-minute-expiry worker on each peer retires X's leaf
    // independently, and the retire walk wipes F's row on each peer.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");

    let post_retire_alice = keys_value(&alice, &workspace_id);
    let post_retire_bob = keys_value(&bob, &workspace_id);
    // F-wipe is the load-bearing precondition for the no-rotation claim:
    // if `local_key_secrets` were still 1 the test would not be
    // exercising the sibling-fallback path.
    assert_eq!(
        line_value(&post_retire_alice, "local_key_secrets"),
        "0",
        "precondition: alice's retire walk must have wiped F's row:\n{post_retire_alice}"
    );
    assert_eq!(
        line_value(&post_retire_bob, "local_key_secrets"),
        "0",
        "precondition: bob's retire walk must have wiped F's row:\n{post_retire_bob}"
    );
    // Time-tree siblings must survive on BOTH peers — they're what
    // `derive_event_leaf` will use on alice to author Y, and they're
    // also what bob would use to derive Y's leaf if/when sync of the
    // post-purge message lands. Each peer ran its own retire walk
    // independently (no expiry events sync), so equal node-secret
    // counts are the load-bearing convergence signal here.
    let alice_node_secrets: u64 = line_value(&post_retire_alice, "local_history_node_secrets")
        .parse()
        .expect("parse alice local_history_node_secrets");
    let bob_node_secrets: u64 = line_value(&post_retire_bob, "local_history_node_secrets")
        .parse()
        .expect("parse bob local_history_node_secrets");
    assert!(
        alice_node_secrets > 0,
        "precondition: alice must retain time-tree sibling rows after retire:\n{post_retire_alice}"
    );
    assert!(
        bob_node_secrets > 0,
        "precondition: bob must retain time-tree sibling rows after retire:\n{post_retire_bob}"
    );
    assert_eq!(
        alice_node_secrets, bob_node_secrets,
        "alice and bob's surviving sibling rows must converge \
         (same retire walk, same KDF, same coords)"
    );

    // Step 4 (bonus, legitimate-wedge documentation): with X retired and F
    // wiped, attempting to author a NEW message in the same retired minute
    // M=100 must error with the clear wedge message — silently re-deriving
    // from the wiped F would defeat forward secrecy. Done BEFORE the M+5
    // send because once Y is authored, `next_timestamp` ratchets forward
    // and the same-minute attempt cannot be reproduced.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let same_minute_attempt = topo(&["--db", &alice, "send", &workspace_id, "z-wedge"]);
    assert!(
        !same_minute_attempt.status.success(),
        "send into already-retired minute must fail:\nstdout={}\nstderr={}",
        stdout(&same_minute_attempt),
        stderr(&same_minute_attempt)
    );
    let same_minute_err = stderr(&same_minute_attempt);
    assert!(
        same_minute_err.contains("no retained ancestor covers"),
        "expected the documented wedge message; got: {same_minute_err}"
    );

    // Step 5 (the load-bearing claim): without any `key-frontier` advance,
    // alice authors Y in a DIFFERENT minute M+5 (105). The send must
    // succeed — `derive_event_leaf` falls back to a covering time-tree
    // sibling row admitted during the retire walk. Y must then be
    // locally visible on alice (the messages listing decrypts the
    // sealed payload, which is the strongest local proof that the
    // sibling-derived leaf secret is usable).
    assert_success(topo(&["--db", &alice, "clock", "set", "6300000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6300000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "y-secret"]));
    wait_for_message_text(&alice, &workspace_id, "alice: y-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    // Step 6: prove no rotation happened. The frontier id must be the
    // same as before X was authored, and the count of removal_frontiers
    // must still be 1. This is the option-5 contract: forward secrecy is
    // achieved by retire-driven F-wipe + sibling fallback, not by
    // admitting a new frontier event. Read the frontier id from `keys`
    // output rather than `key-frontier` (which would itself create a
    // brand-new frontier and defeat the assertion).
    let post_y_alice = keys_value(&alice, &workspace_id);
    let post_y_bob = keys_value(&bob, &workspace_id);
    let removal_frontier_id_after = frontier_id_from_keys(&post_y_alice);
    assert_eq!(
        removal_frontier_id_after, removal_frontier_id_before,
        "no key-frontier advance should have happened — frontier id must be identical \
         before X and after Y"
    );
    assert_eq!(
        line_value(&post_y_alice, "removal_frontiers"),
        "1",
        "alice must still have exactly one removal_frontier; rotation is forbidden"
    );
    assert_eq!(
        line_value(&post_y_bob, "removal_frontiers"),
        "1",
        "bob must still have exactly one removal_frontier; rotation is forbidden"
    );
    // F is still wiped on alice — Y was authored under the sibling
    // fallback, NOT by resurrecting F. (Bob's F is also still wiped;
    // we don't re-assert because it didn't change since `post_retire_bob`
    // and would only be touched by an explicit `key-frontier` advance,
    // which is exactly what this test forbids.)
    assert_eq!(
        line_value(&post_y_alice, "local_key_secrets"),
        "0",
        "F must remain wiped on alice after authoring Y under the sibling fallback"
    );
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
    line_value(&out, "workspace_id")
}

fn keys_value(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "keys", workspace_id]))
}

fn cover_summary_value(keys_output: &str) -> String {
    line_value(keys_output, "cover_summary")
}

/// Extract the (single) frontier id from `keys` output without authoring a
/// new frontier event. The `keys` command renders one line per frontier as
/// `frontier: <hex_id> access=<yes|no>`. Tests that need to assert "no
/// rotation happened" cannot call `key-frontier` to read it because that
/// command always creates a brand-new frontier.
fn frontier_id_from_keys(keys_output: &str) -> String {
    let mut iter = keys_output.lines().filter_map(|line| {
        line.strip_prefix("frontier: ")
            .and_then(|rest| rest.split_whitespace().next())
            .map(ToOwned::to_owned)
    });
    let only = iter
        .next()
        .unwrap_or_else(|| panic!("missing `frontier:` line in keys output:\n{keys_output}"));
    assert!(
        iter.next().is_none(),
        "multiple `frontier:` lines in keys output (rotation occurred):\n{keys_output}"
    );
    only
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

/// Visible message bodies: lines of the form `N. [ts] user: text`.
fn message_lines(db: &str, workspace_id: &str) -> Vec<String> {
    messages_text(db, workspace_id)
        .lines()
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

fn content_event_count(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "content-count", workspace_id]));
    line_value(&out, "content_events")
}

fn wait_for_leaf_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "keys", workspace_id]));
        if line_value(&out, "local_history_leaves") == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("leaf count did not reach {expected}:\n{last}");
}

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "content-count", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "content_events") == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("content count did not reach {expected}:\n{last}");
}

fn wait_for_key_derive(db: &str, expected: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-derive"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "derived_key_secrets") == expected {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key derive did not reach {expected}:\n{last}");
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
    panic!(
        "message text {expected_suffix:?} never appeared on db={db}:\n{last}"
    );
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

// --- two-peer setup helpers (mirrored from tests/encryption_cli_test.rs) ---

fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let mut listener = spawn_workspace_invite_listener(host, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("workspace invite accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
}

struct ListeningInvite {
    child: Child,
    invite_rx: Receiver<Result<String, String>>,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

impl ListeningInvite {
    fn invite_link(&mut self) -> String {
        match self.invite_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => {
                assert!(
                    line.starts_with("topo://invite/"),
                    "missing invite link in first listener line: {line}"
                );
                thread::sleep(Duration::from_millis(50));
                line
            }
            Ok(Err(err)) => {
                let _ = self.child.kill();
                panic!("listener did not print invite link: {err}");
            }
            Err(err) => {
                let _ = self.child.kill();
                panic!("timed out waiting for invite link: {err}");
            }
        }
    }

    fn wait_success(mut self, label: &str) -> String {
        let status = self.child.wait().expect("wait for listener");
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        assert!(
            status.success(),
            "{label} failed\nstdout={stdout}\nstderr={stderr}"
        );
        stdout
    }

    fn fail(mut self, label: &str, err: String) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        panic!("{label}: {err}\nlistener stdout:\n{stdout}\nlistener stderr:\n{stderr}");
    }
}

fn spawn_workspace_invite_listener(
    db: &str,
    workspace_id: &str,
    port: u16,
    accept: usize,
) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
}

fn listening_invite_from_child(mut child: Child) -> ListeningInvite {
    let stdout = child.stdout.take().expect("listener stdout");
    let stderr = child.stderr.take().expect("listener stderr");
    let (invite_tx, invite_rx) = mpsc::channel();
    let stdout = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut output = String::new();
        let mut first = String::new();
        match reader.read_line(&mut first) {
            Ok(0) => {
                let _ = invite_tx.send(Err("stdout closed before first line".to_string()));
            }
            Ok(_) => {
                output.push_str(&first);
                let link = first.trim_end_matches(['\r', '\n']).to_string();
                let _ = invite_tx.send(Ok(link));
            }
            Err(err) => {
                let _ = invite_tx.send(Err(err.to_string()));
            }
        }

        let mut rest = String::new();
        if reader.read_to_string(&mut rest).is_ok() {
            output.push_str(&rest);
        }
        output
    });
    let stderr = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut output = String::new();
        let _ = reader.read_to_string(&mut output);
        output
    });
    ListeningInvite {
        child,
        invite_rx,
        stdout,
        stderr,
    }
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

fn connect_daemon_pair(left_db: &str, left_port: u16, right_db: &str, right_port: u16) {
    let left_invite = transport_invite(left_db, left_port);
    let right_invite = transport_invite(right_db, right_port);
    let right_to_left = connect_with_retry(right_db, &left_invite);
    assert!(right_to_left.contains("connected:"), "{right_to_left}");
    let left_to_right = connect_with_retry(left_db, &right_invite);
    assert!(left_to_right.contains("connected:"), "{left_to_right}");
}

fn transport_invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    invite_link_from_output(&out)
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "connect", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}
