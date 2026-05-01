//! Unit tests for the projected negentropy tree state.
//!
//! Two facts to verify:
//!
//! 1. Insert two roots → fingerprint stable (set semantics, order-
//!    independent).
//! 2. Satisfy a previously-required-but-absent dep → dep_hash flips, so the
//!    fingerprint changes correctly.

use rusqlite::Connection;

use super::query::node_fingerprint;
use super::schema;
use super::update::{on_event_present, on_root_inserted};

fn open_db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    schema::ensure_schema(&db).unwrap();
    db
}

#[test]
fn root_insert_changes_fingerprint() {
    let db = open_db();
    let ws = [1u8; 32];
    let path = vec![b"node-root".to_vec()];

    let r1 = [0xA1u8; 32];
    let r2 = [0xA2u8; 32];

    let f0 = node_fingerprint(&db, &ws, &path[0]).unwrap();
    assert_eq!(f0, [0u8; 32], "no roots yet -> all-zero fingerprint");

    on_root_inserted(&ws, &r1, &[], &path, &db).unwrap();
    let f1 = node_fingerprint(&db, &ws, &path[0]).unwrap();
    assert_ne!(f1, [0u8; 32], "first root must change fingerprint");

    on_root_inserted(&ws, &r2, &[], &path, &db).unwrap();
    let f2 = node_fingerprint(&db, &ws, &path[0]).unwrap();
    assert_ne!(f2, f1, "second root must change fingerprint");
    assert_ne!(f2, [0u8; 32]);
}

#[test]
fn root_insertion_is_order_independent() {
    let path = vec![b"node-root".to_vec()];
    let ws = [1u8; 32];
    let r1 = [0xA1u8; 32];
    let r2 = [0xA2u8; 32];

    let db_a = open_db();
    on_root_inserted(&ws, &r1, &[], &path, &db_a).unwrap();
    on_root_inserted(&ws, &r2, &[], &path, &db_a).unwrap();
    let fa = node_fingerprint(&db_a, &ws, &path[0]).unwrap();

    let db_b = open_db();
    on_root_inserted(&ws, &r2, &[], &path, &db_b).unwrap();
    on_root_inserted(&ws, &r1, &[], &path, &db_b).unwrap();
    let fb = node_fingerprint(&db_b, &ws, &path[0]).unwrap();

    assert_eq!(fa, fb, "root set is order-independent (XOR is commutative)");
}

#[test]
fn duplicate_root_insert_is_idempotent() {
    let db = open_db();
    let ws = [1u8; 32];
    let path = vec![b"n".to_vec()];
    let r1 = [0xA1u8; 32];

    on_root_inserted(&ws, &r1, &[], &path, &db).unwrap();
    let f1 = node_fingerprint(&db, &ws, &path[0]).unwrap();

    on_root_inserted(&ws, &r1, &[], &path, &db).unwrap();
    let f2 = node_fingerprint(&db, &ws, &path[0]).unwrap();
    assert_eq!(f1, f2, "duplicate insert must not double-XOR");
}

#[test]
fn satisfying_a_required_dep_changes_fingerprint() {
    let db = open_db();
    let ws = [1u8; 32];
    let path = vec![b"n".to_vec()];

    // Insert a root that requires a not-yet-present dep d.
    let r = [0xC1u8; 32];
    let d = [0xDDu8; 32];

    on_root_inserted(&ws, &r, &[d], &path, &db).unwrap();
    let f_required_absent = node_fingerprint(&db, &ws, &path[0]).unwrap();

    // d becomes present locally — dep_hash should now include d's
    // contribution and the fingerprint must change.
    on_event_present(&ws, &d, &db).unwrap();
    let f_required_present = node_fingerprint(&db, &ws, &path[0]).unwrap();

    assert_ne!(
        f_required_absent, f_required_present,
        "satisfying a required dep must change the fingerprint"
    );
}

#[test]
fn dep_already_root_at_node_does_not_double_count() {
    let db = open_db();
    let ws = [1u8; 32];
    let path = vec![b"n".to_vec()];

    // Insert root x with no deps.
    let x = [0x11u8; 32];
    on_root_inserted(&ws, &x, &[], &path, &db).unwrap();
    let f_x_alone = node_fingerprint(&db, &ws, &path[0]).unwrap();

    // Insert root y depending on x. Per the stop-rule, x is a root in this
    // node already, so we do NOT add x to dep_refcount here.
    let y = [0x22u8; 32];
    on_root_inserted(&ws, &y, &[x], &path, &db).unwrap();
    let f_xy = node_fingerprint(&db, &ws, &path[0]).unwrap();

    assert_ne!(
        f_x_alone, f_xy,
        "adding y must change the fingerprint (root membership grew)"
    );

    // Verify dep_refcount has no entry for x at this node.
    let dep_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM negentropy_dep_refcount
             WHERE workspace_id = ?1 AND node_id = ?2 AND dep_event_id = ?3",
            rusqlite::params![ws.to_vec(), path[0].clone(), x.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        dep_count, 0,
        "x is a root at this node; the stop-rule must skip dep accounting"
    );
}
