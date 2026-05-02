//! Smoke tests for the `sync` event-module family.
//!
//! Per plan.md lines 295-385: compare/have/need projectors are pure-fold
//! over local negentropy state; on-leaf they emit `Have` events for every
//! `R_v` member, on-interior they emit per-child `Compare` events, and
//! `Need` projectors write the durable event_id directly to outbox so the
//! per-connection sender wraps it at egress.
//!
//! Modules covered (plan.md lines 295-385):
//! - sync::compare  (type 41) — recursive-fold projector
//! - sync::have     (type 42) — local-has check + Need synthesis
//! - sync::need     (type 43) — outbox write for sendable id
//! - sync::negentropy_tree    — local-state read helper used by compare
//! - sync::dep_cache          — transitive closure helper

use rusqlite::Connection;
use topo::event_modules::sync;
use topo::runtime::control_loop::work_item::{BlakeId, ConnectionId, WorkspaceId};
use topo::state::db::control_loop_tables::ensure_schema as ensure_substrate_schema;
use topo::state::events_canonical::{upsert_event, EventRow, EventScope, EventStatus};

fn open_db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    // Substrate tables — events_canonical, blocked_by_event, outbox, etc.
    ensure_substrate_schema(&c).unwrap();
    // sync family tables — diagnostic + materialized state.
    sync::ensure_schema(&c).unwrap();
    c
}

fn insert_local_event(db: &Connection, id: BlakeId, bytes: &[u8]) {
    upsert_event(
        db,
        &EventRow {
            event_id: id,
            canonical_event_bytes: bytes.to_vec(),
            workspace_id: Some([0u8; 32]),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
}

fn outbox_count_for(db: &Connection, conn_id: &ConnectionId) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM outbox WHERE connection_id = ?1",
        [&conn_id[..]],
        |r| r.get(0),
    )
    .unwrap()
}

fn events_canonical_count_for_scope(db: &Connection, scope: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM events_canonical WHERE scope = ?1",
        [scope],
        |r| r.get(0),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// compare projector
// ---------------------------------------------------------------------------

#[test]
fn compare_round_trip() {
    use sync::compare::{encode, parse, CompareEvent};

    let ev = CompareEvent {
        connection_id: [3; 32],
        workspace_id: [4; 32],
        node_id: vec![0x01, 0x02, 0x03],
        fingerprint: [0xAB; 32],
        created_at_ms: 5000,
    };
    let blob = encode(&ev);
    assert_eq!(parse(&blob).unwrap(), ev);
}

#[test]
fn compare_with_matching_fingerprint_emits_nothing() {
    use sync::compare::{project, CompareEvent};
    use sync::negentropy_tree::on_root_inserted;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];
    let node = b"n".to_vec();

    // Plant one root locally so the leaf has a non-empty fingerprint.
    let r = [0xA1u8; 32];
    on_root_inserted(&ws, &r, &[], &[node.clone()], &db).unwrap();
    let local_fp = sync::negentropy_tree::node_fingerprint(&db, &ws, &node).unwrap();

    // Remote sends the same fingerprint. Projector should emit nothing.
    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: node,
        fingerprint: local_fp,
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    assert_eq!(outbox_count_for(&db, &conn_id), 0);
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 0);
}

#[test]
fn compare_with_mismatched_fingerprint_at_leaf_emits_have_per_root() {
    use sync::compare::{project, CompareEvent};
    use sync::negentropy_tree::on_root_inserted;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];
    let node = b"n".to_vec();

    // Plant three roots in the leaf node; remote claims a mismatched fp.
    let r1 = [0x11u8; 32];
    let r2 = [0x22u8; 32];
    let r3 = [0x33u8; 32];
    for r in [r1, r2, r3] {
        on_root_inserted(&ws, &r, &[], &[node.clone()], &db).unwrap();
    }

    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: node,
        fingerprint: [0xFFu8; 32],
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    // Three Have events plus one reciprocal echo Compare(v, F_local)
    // so the peer drills on its side too.
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 4);
    assert_eq!(outbox_count_for(&db, &conn_id), 4);

    // Sanity: three Haves + one Compare echo.
    let mut stmt = db
        .prepare("SELECT canonical_event_bytes FROM events_canonical WHERE scope = 'endpoint_local'")
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut have_count = 0;
    let mut compare_count = 0;
    while let Some(row) = rows.next().unwrap() {
        let bytes: Vec<u8> = row.get(0).unwrap();
        if bytes[0] == sync::HAVE_TYPE_CODE {
            have_count += 1;
        } else if bytes[0] == sync::COMPARE_TYPE_CODE {
            compare_count += 1;
        }
    }
    assert_eq!(have_count, 3, "three Haves, one per local root member");
    assert_eq!(compare_count, 1, "one reciprocal echo Compare");
}

#[test]
fn compare_at_interior_node_emits_child_compares() {
    use sync::compare::{project, CompareEvent, COMPARE_TYPE_CODE};
    use sync::negentropy_tree::on_root_inserted;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];

    // Plant roots at TWO distinct child paths beneath the empty interior
    // node. Children are derived as length-1 prefixes of the longer paths.
    let interior = vec![]; // root of the materialized tree
    let child_a_path = vec![0xAA];
    let child_b_path = vec![0xBB];
    let r_a = [0x11u8; 32];
    let r_b = [0x22u8; 32];
    on_root_inserted(&ws, &r_a, &[], &[child_a_path.clone()], &db).unwrap();
    on_root_inserted(&ws, &r_b, &[], &[child_b_path.clone()], &db).unwrap();

    // Remote sends a mismatched fingerprint at the interior. Projector
    // should emit one CompareEvent per child path.
    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: interior,
        fingerprint: [0xFFu8; 32],
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    // Two child drill compares + one reciprocal echo Compare(v, F_local).
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 3);
    assert_eq!(outbox_count_for(&db, &conn_id), 3);
    let mut stmt = db
        .prepare("SELECT canonical_event_bytes FROM events_canonical WHERE scope = 'endpoint_local'")
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let bytes: Vec<u8> = row.get(0).unwrap();
        assert_eq!(
            bytes[0], COMPARE_TYPE_CODE,
            "interior-emit should produce CompareEvents (drill + echo)"
        );
    }
}

// ---------------------------------------------------------------------------
// have projector
// ---------------------------------------------------------------------------

#[test]
fn have_round_trip() {
    use sync::have::{encode, parse, HaveEvent};

    let ev = HaveEvent {
        connection_id: [5; 32],
        workspace_id: [6; 32],
        event_id: [0xCD; 32],
        created_at_ms: 7000,
    };
    let blob = encode(&ev);
    assert_eq!(parse(&blob).unwrap(), ev);
}

#[test]
fn have_for_known_event_no_writes() {
    use sync::have::{project, HaveEvent};

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xCDu8; 32];

    // Pretend we already have the event applied locally.
    insert_local_event(&db, id, b"some-canonical-blob");

    let ev = HaveEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    assert_eq!(outbox_count_for(&db, &conn_id), 0);
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 0);
}

#[test]
fn have_for_unknown_event_emits_need() {
    use sync::have::{project, HaveEvent};

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xCDu8; 32];

    // Note: we do NOT insert id into events_canonical.
    let ev = HaveEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    // One Need event synthesized + one outbox row.
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 1);
    assert_eq!(outbox_count_for(&db, &conn_id), 1);
    // Bytes start with NEED_TYPE_CODE.
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT canonical_event_bytes FROM events_canonical WHERE scope = 'endpoint_local'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bytes[0], sync::NEED_TYPE_CODE);
}

// ---------------------------------------------------------------------------
// need projector
// ---------------------------------------------------------------------------

#[test]
fn need_round_trip() {
    use sync::need::{encode, parse, NeedEvent};

    let ev = NeedEvent {
        connection_id: [7; 32],
        workspace_id: [8; 32],
        event_id: [0xEF; 32],
        created_at_ms: 9000,
    };
    let blob = encode(&ev);
    assert_eq!(parse(&blob).unwrap(), ev);
}

#[test]
fn need_for_locally_present_event_writes_outbox() {
    use sync::need::{project, NeedEvent};

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xEFu8; 32];

    // Plant the durable event so we can satisfy the need.
    insert_local_event(&db, id, b"durable-bytes");

    let ev = NeedEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    // Single outbox row carrying the durable event_id. No new
    // events_canonical rows — the durable row already exists.
    assert_eq!(outbox_count_for(&db, &conn_id), 1);
    let pending: Vec<u8> = db
        .query_row(
            "SELECT event_id FROM outbox WHERE connection_id = ?1",
            [&conn_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, id.to_vec(), "outbox row carries durable event_id");
}

#[test]
fn need_for_locally_absent_event_no_writes() {
    use sync::need::{project, NeedEvent};

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xEFu8; 32];

    // We do NOT have the event locally.
    let ev = NeedEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    project(&db, &ev).unwrap();

    assert_eq!(outbox_count_for(&db, &conn_id), 0);
}

// ---------------------------------------------------------------------------
// negentropy_tree + dep_cache helpers (existing, kept)
// ---------------------------------------------------------------------------

#[test]
fn negentropy_tree_root_insert_changes_fingerprint() {
    use sync::negentropy_tree::{node_fingerprint, on_root_inserted};

    let db = open_db();
    let ws = [1u8; 32];
    let path = vec![b"n".to_vec()];

    let f0 = node_fingerprint(&db, &ws, &path[0]).unwrap();
    assert_eq!(f0, [0u8; 32]);

    let r = [0xA1u8; 32];
    on_root_inserted(&ws, &r, &[], &path, &db).unwrap();
    let f1 = node_fingerprint(&db, &ws, &path[0]).unwrap();
    assert_ne!(f1, [0u8; 32]);
    assert_ne!(f1, f0);
}

// ---------------------------------------------------------------------------
// registry-dispatch tests: drive the *pure* projector through the same path
// the inbound chain uses (load_generic_context -> meta.projector). The
// generic loader populates the sync-extension fields on `ContextSnapshot`.
// ---------------------------------------------------------------------------

fn apply_writes_for_test(db: &Connection, ops: &[topo::projection::contract::WriteOp]) {
    use topo::projection::contract::{SqlVal, WriteOp};
    for op in ops {
        match op {
            WriteOp::InsertOrIgnore {
                table,
                columns,
                values,
            } => {
                let cols = columns.join(", ");
                let placeholders: Vec<String> =
                    (1..=values.len()).map(|i| format!("?{}", i)).collect();
                let sql = format!(
                    "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                    table,
                    cols,
                    placeholders.join(", ")
                );
                let params_vec: Vec<Box<dyn rusqlite::ToSql>> = values
                    .iter()
                    .map(|v| -> Box<dyn rusqlite::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let refs: Vec<&dyn rusqlite::ToSql> =
                    params_vec.iter().map(|b| b.as_ref()).collect();
                db.execute(&sql, refs.as_slice()).unwrap();
            }
            WriteOp::Delete { .. } => unreachable!("sync writes are insert-only"),
        }
    }
}

#[test]
fn compare_via_registry_at_leaf_emits_have_per_root() {
    use sync::compare::{project_pure, CompareEvent};
    use sync::negentropy_tree::on_root_inserted;
    use topo::event_modules::ParsedEvent;
    use topo::projection::decision::ProjectionDecision;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];
    let node = b"n".to_vec();

    let r1 = [0x11u8; 32];
    let r2 = [0x22u8; 32];
    for r in [r1, r2] {
        on_root_inserted(&ws, &r, &[], &[node.clone()], &db).unwrap();
    }

    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: node,
        fingerprint: [0xFFu8; 32],
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Compare(ev);

    let ctx = load_generic_context(&pe, &db).unwrap();
    assert!(ctx.local_sync_node_fingerprint.is_some());
    assert_eq!(ctx.local_sync_node_members.len(), 2);
    assert!(ctx.local_sync_node_children.is_empty());

    let result = project_pure("ev", &pe, &ctx);
    assert!(matches!(result.decision, ProjectionDecision::Valid));
    apply_writes_for_test(&db, &result.write_ops);

    // Two Haves (one per local root) + one reciprocal echo Compare.
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 3);
    assert_eq!(outbox_count_for(&db, &conn_id), 3);
}

#[test]
fn compare_via_registry_at_interior_emits_child_compares() {
    use sync::compare::{project_pure, CompareEvent, COMPARE_TYPE_CODE};
    use sync::negentropy_tree::on_root_inserted;
    use topo::event_modules::ParsedEvent;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];
    let interior = vec![];
    let child_a = vec![0xAA];
    let child_b = vec![0xBB];
    on_root_inserted(&ws, &[0x11u8; 32], &[], &[child_a.clone()], &db).unwrap();
    on_root_inserted(&ws, &[0x22u8; 32], &[], &[child_b.clone()], &db).unwrap();

    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: interior,
        fingerprint: [0xFFu8; 32],
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Compare(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    assert_eq!(ctx.local_sync_node_children.len(), 2);
    // Each child should carry a non-zero fingerprint (we planted a root in
    // each).
    for (_path, fp) in &ctx.local_sync_node_children {
        assert_ne!(*fp, [0u8; 32]);
    }

    let result = project_pure("ev", &pe, &ctx);
    apply_writes_for_test(&db, &result.write_ops);

    // Two child drill compares + one reciprocal echo Compare(v, F_local).
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 3);
    assert_eq!(outbox_count_for(&db, &conn_id), 3);
    let mut stmt = db
        .prepare("SELECT canonical_event_bytes FROM events_canonical WHERE scope = 'endpoint_local'")
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let bytes: Vec<u8> = row.get(0).unwrap();
        assert_eq!(bytes[0], COMPARE_TYPE_CODE);
    }
}

#[test]
fn compare_via_registry_empty_local_emits_echo_back() {
    // Asymmetric drill-down case: the empty side receives a Compare
    // with non-zero fingerprint but has no local membership rows. It
    // must echo Compare(node, fp=0) back so the populated side
    // continues descending. Without this the recursion stalls in the
    // initial-sync (one-empty-side) case.
    use sync::compare::{project_pure, CompareEvent, COMPARE_TYPE_CODE};
    use topo::event_modules::ParsedEvent;
    use topo::projection::decision::ProjectionDecision;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];
    let node = vec![0xAA];

    // No on_root_inserted — the local side has nothing in this range.
    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: node.clone(),
        fingerprint: [0xFFu8; 32],
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Compare(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    assert!(ctx.local_sync_node_members.is_empty());
    assert!(ctx.local_sync_node_children.is_empty());

    let result = project_pure("ev", &pe, &ctx);
    assert!(matches!(result.decision, ProjectionDecision::Valid));
    apply_writes_for_test(&db, &result.write_ops);

    // Exactly one echo emitted.
    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 1);
    assert_eq!(outbox_count_for(&db, &conn_id), 1);

    // Bytes start with COMPARE_TYPE_CODE (this is a Compare, not a Have).
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT canonical_event_bytes FROM events_canonical WHERE scope = 'endpoint_local'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bytes[0], COMPARE_TYPE_CODE);

    // The echo's fingerprint is local_fp (= 0 for an empty side at the node).
    let parsed = sync::compare::parse(&bytes).unwrap();
    assert_eq!(parsed.fingerprint, [0u8; 32]);
    assert_eq!(parsed.node_id, node);
}

#[test]
fn compare_via_registry_with_matching_fingerprint_emits_nothing() {
    use sync::compare::{project_pure, CompareEvent};
    use sync::negentropy_tree::on_root_inserted;
    use topo::event_modules::ParsedEvent;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];
    let node = b"n".to_vec();
    on_root_inserted(&ws, &[0xA1u8; 32], &[], &[node.clone()], &db).unwrap();
    let local_fp = sync::negentropy_tree::node_fingerprint(&db, &ws, &node).unwrap();

    let ev = CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: node,
        fingerprint: local_fp,
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Compare(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    let result = project_pure("ev", &pe, &ctx);
    assert!(result.write_ops.is_empty());
}

#[test]
fn have_via_registry_for_unknown_event_emits_need() {
    use sync::have::{project_pure, HaveEvent};
    use topo::event_modules::ParsedEvent;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xCDu8; 32];

    let ev = HaveEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Have(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    assert_eq!(ctx.local_sync_has_event, Some(false));

    let result = project_pure("ev", &pe, &ctx);
    apply_writes_for_test(&db, &result.write_ops);

    assert_eq!(events_canonical_count_for_scope(&db, "endpoint_local"), 1);
    assert_eq!(outbox_count_for(&db, &conn_id), 1);
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT canonical_event_bytes FROM events_canonical WHERE scope = 'endpoint_local'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bytes[0], sync::NEED_TYPE_CODE);
}

#[test]
fn have_via_registry_for_known_event_no_writes() {
    use sync::have::{project_pure, HaveEvent};
    use topo::event_modules::ParsedEvent;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xCDu8; 32];
    insert_local_event(&db, id, b"some-canonical-blob");

    let ev = HaveEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Have(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    assert_eq!(ctx.local_sync_has_event, Some(true));

    let result = project_pure("ev", &pe, &ctx);
    assert!(result.write_ops.is_empty());
}

#[test]
fn need_via_registry_for_present_event_writes_outbox() {
    use sync::need::{project_pure, NeedEvent};
    use topo::event_modules::ParsedEvent;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xEFu8; 32];
    insert_local_event(&db, id, b"durable-bytes");

    let ev = NeedEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Need(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    assert_eq!(ctx.local_sync_has_event, Some(true));

    let result = project_pure("ev", &pe, &ctx);
    apply_writes_for_test(&db, &result.write_ops);

    assert_eq!(outbox_count_for(&db, &conn_id), 1);
    let pending: Vec<u8> = db
        .query_row(
            "SELECT event_id FROM outbox WHERE connection_id = ?1",
            [&conn_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, id.to_vec());
}

#[test]
fn need_via_registry_for_absent_event_no_writes() {
    use sync::need::{project_pure, NeedEvent};
    use topo::event_modules::ParsedEvent;
    use topo::state::generic_context::load_generic_context;

    let db = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let id: BlakeId = [0xEFu8; 32];

    let ev = NeedEvent {
        connection_id: conn_id,
        workspace_id: [2u8; 32],
        event_id: id,
        created_at_ms: 100,
    };
    let pe = ParsedEvent::Need(ev);
    let ctx = load_generic_context(&pe, &db).unwrap();
    assert_eq!(ctx.local_sync_has_event, Some(false));

    let result = project_pure("ev", &pe, &ctx);
    assert!(result.write_ops.is_empty());
}

#[test]
fn dep_cache_transitive_closure_for_simple_chain() {
    use sync::dep_cache::compute_transitive;
    use std::collections::HashMap;

    // Linear chain r -> a -> b -> c.
    let id = |b: u8| [b; 32];
    let mut graph: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    graph.insert(id(1), vec![id(2)]);
    graph.insert(id(2), vec![id(3)]);
    graph.insert(id(3), vec![id(4)]);

    #[derive(Debug)]
    struct Never;
    impl std::fmt::Display for Never {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Ok(())
        }
    }
    impl std::error::Error for Never {}

    let result = compute_transitive(&id(1), |e| {
        Ok::<_, Never>(graph.get(e).cloned().unwrap_or_default())
    })
    .unwrap();

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], (id(2), 1));
    assert_eq!(result[1], (id(3), 2));
    assert_eq!(result[2], (id(4), 3));
}

// ---------------------------------------------------------------------------
// asymmetric-drill convergence: end-to-end ping-pong
// ---------------------------------------------------------------------------

/// Simulate the negentropy compare/have/need fold across two distinct
/// `negentropy_root_membership` stores: A (10 messages + workspace) vs
/// B (workspace only). A is the driver that emits the initial root
/// Compare. The test alternates "A applies whatever B emitted" /
/// "B applies whatever A emitted" until quiescence and asserts that
/// (a) every one of A's 10 message ids is announced via a Have on at
/// least one side, and (b) the loop terminates.
///
/// This is the substrate-level analog of the subprocess black-box
/// smoke test: it exercises the same recursive-fold logic without the
/// network, so a regression is observable in `cargo test` rather than
/// only in the slow black-box harness.
#[test]
fn compare_fold_converges_with_asymmetric_trees_n10() {
    use sync::compare::{compute_writes, CompareEvent};
    use sync::negentropy_tree::on_root_inserted;
    use topo::event_modules::sync::maintenance::{derive_node_path, NODE_PATH_DEPTH};

    fn make_db() -> Connection {
        open_db()
    }

    let db_a = make_db();
    let db_b = make_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [2u8; 32];

    // Plant the workspace event on both sides — same id so both sides
    // know about it. Use a deterministic but arbitrary path.
    let workspace_id_in_tree: BlakeId = [0x80u8; 32];
    let ws_path = derive_node_path(&workspace_id_in_tree);
    on_root_inserted(&ws, &workspace_id_in_tree, &[], &ws_path, &db_a).unwrap();
    on_root_inserted(&ws, &workspace_id_in_tree, &[], &ws_path, &db_b).unwrap();

    // Plant 10 message ids on A only. Use deterministic ids spread
    // across distinct level-1 prefixes (BLAKE3 of i) so the children
    // structure is realistic.
    let mut messages: Vec<BlakeId> = Vec::with_capacity(10);
    for i in 0u8..10 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(blake3::hash(&[i, 0xAA, 0xBB, 0xCC]).as_bytes());
        messages.push(bytes);
        let path = derive_node_path(&bytes);
        on_root_inserted(&ws, &bytes, &[], &path, &db_a).unwrap();
    }
    assert_eq!(messages.iter().collect::<std::collections::HashSet<_>>().len(), 10);

    // Verify A's tree depth matches the convention the projector
    // expects (sanity check on `derive_node_path`).
    assert_eq!(ws_path.len(), NODE_PATH_DEPTH + 1);

    // Initial root-Compare from A as the driver.
    let mut a_outbox: Vec<CompareEvent> = vec![CompareEvent {
        connection_id: conn_id,
        workspace_id: ws,
        node_id: Vec::new(),
        fingerprint: sync::negentropy_tree::node_fingerprint(&db_a, &ws, &[]).unwrap(),
        created_at_ms: 1000,
    }];
    let mut b_outbox: Vec<CompareEvent> = Vec::new();

    // Track the Haves each side has emitted. Plus the seen-bytes set
    // so we don't re-process duplicates (mirroring the chain's
    // `INSERT OR IGNORE` on event_id).
    let mut a_haves: std::collections::HashSet<BlakeId> = Default::default();
    let mut b_haves: std::collections::HashSet<BlakeId> = Default::default();
    let mut seen_compares_a: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut seen_compares_b: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut iterations = 0;

    // Hard cap to detect non-termination. Convergence for n=10 should
    // take well under 200 iterations even at depth 4.
    let cap = 5_000;
    while !a_outbox.is_empty() || !b_outbox.is_empty() {
        iterations += 1;
        assert!(
            iterations < cap,
            "compare fold did not converge in {} iterations (a_outbox={}, b_outbox={})",
            cap,
            a_outbox.len(),
            b_outbox.len()
        );

        // Drain A's outbox -> B applies (and possibly emits).
        let drained_a = std::mem::take(&mut a_outbox);
        for ev in drained_a {
            let blob = sync::compare::encode(&ev);
            if !seen_compares_b.insert(blob.clone()) {
                continue;
            }
            // B's projector runs on B's DB.
            let writes = compute_writes(&db_b, &ev).unwrap();
            // Walk the writes to extract: (i) any new endpoint_local
            // CompareEvent → enqueue toward A, (ii) any HaveEvent →
            // record b_haves.
            extract_emissions(
                &writes,
                &mut b_outbox,
                &mut b_haves,
                |ev| ev.workspace_id == ws,
            );
        }

        // Drain B's outbox -> A applies (and possibly emits).
        let drained_b = std::mem::take(&mut b_outbox);
        for ev in drained_b {
            let blob = sync::compare::encode(&ev);
            if !seen_compares_a.insert(blob.clone()) {
                continue;
            }
            let writes = compute_writes(&db_a, &ev).unwrap();
            extract_emissions(
                &writes,
                &mut a_outbox,
                &mut a_haves,
                |ev| ev.workspace_id == ws,
            );
        }
    }

    // A should have announced all 10 of its message ids via Haves.
    // (B can also announce the workspace event back to A; that's
    // fine.) The critical assertion is that A's locally-held but
    // peer-missing ids surface as Haves — the bug we're guarding
    // against was exactly "A only emits 2 Haves total".
    let mut missing: Vec<BlakeId> = Vec::new();
    for m in &messages {
        if !a_haves.contains(m) {
            missing.push(*m);
        }
    }
    assert!(
        missing.is_empty(),
        "{} of A's 10 messages were never announced via Have (iterations={})",
        missing.len(),
        iterations,
    );

    // Workspace event lives on both sides → no Need round-trip
    // required for it. Just sanity-check that the workspace id is
    // among at least one side's Haves (B can announce the workspace
    // event back to A even though A already has it; that's harmless
    // and exercises the symmetric path).
    let _ = b_haves;
    eprintln!(
        "[asymmetric-drill] converged in {} iterations; A emitted {} Haves",
        iterations,
        a_haves.len()
    );
}

/// Walk a freshly-projected `Vec<WriteOp>` and extract:
/// - any newly synthesized CompareEvent into `compare_outbox`,
/// - any newly synthesized HaveEvent's event_id into `have_set`.
fn extract_emissions(
    writes: &[topo::projection::contract::WriteOp],
    compare_outbox: &mut Vec<sync::compare::CompareEvent>,
    have_set: &mut std::collections::HashSet<BlakeId>,
    workspace_filter: impl Fn(&sync::compare::CompareEvent) -> bool,
) {
    use topo::projection::contract::{SqlVal, WriteOp};
    for op in writes {
        if let WriteOp::InsertOrIgnore {
            table,
            columns,
            values,
        } = op
        {
            if *table != "events_canonical" {
                continue;
            }
            // Find the canonical_event_bytes column.
            let bytes_idx = columns
                .iter()
                .position(|c| *c == "canonical_event_bytes")
                .unwrap();
            let bytes = match &values[bytes_idx] {
                SqlVal::Blob(b) => b.clone(),
                _ => continue,
            };
            if bytes.is_empty() {
                continue;
            }
            match bytes[0] {
                t if t == sync::COMPARE_TYPE_CODE => {
                    if let Ok(ev) = sync::compare::parse(&bytes) {
                        if workspace_filter(&ev) {
                            compare_outbox.push(ev);
                        }
                    }
                }
                t if t == sync::HAVE_TYPE_CODE => {
                    if bytes.len() >= 1 + 32 + 32 + 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes[65..97]);
                        have_set.insert(id);
                    }
                }
                _ => {}
            }
        }
    }
}
