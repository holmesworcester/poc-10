//! Projector for `CompareEvent`.
//!
//! Implements the recursive negentropy fold per `plan.md` lines 308-316:
//!
//! ```text
//! compare.project:
//!   if remote_fingerprint == F_v:
//!     emit nothing
//!   else if v is splittable:
//!     create endpoint-local compare events for each child and queue them in outbox
//!   else:
//!     create endpoint-local have-id events for the ids in R_v and queue them in outbox
//! ```
//!
//! ### Splittable convention
//!
//! The negentropy tree shape is not centrally defined as a function of the
//! event-id space; instead, callers of the maintenance routine in
//! `negentropy_tree::update::on_root_inserted` supply an explicit
//! `node_path: &[Vec<u8>]`. Until a tree-shape helper lands, the projector
//! decides splittability by looking at *what membership rows have actually
//! been recorded*:
//!
//! - **leaf** — every `negentropy_root_membership` row whose `node_id`
//!   matches `ev.node_id` exactly is a member of `R_v`. No row with a
//!   strictly-longer `node_id` prefixed by `ev.node_id` exists.
//! - **splittable** — at least one row exists with a strictly-longer
//!   `node_id` prefixed by `ev.node_id`. The children are the distinct
//!   `node_id` values of length `ev.node_id.len() + 1` that prefix any
//!   such row.
//!
//! This convention is consistent with the recursive-walk shape implied by
//! the maintenance routine (each call passes a `node_path` from leaf to
//! root) and is sufficient for the smoke tests.
//!
//! ### Endpoint-local emission
//!
//! Children-compare and per-id-have writes go through `events_canonical`
//! (scope=`endpoint_local`) and `outbox`. The id of each emitted event is
//! `blake3(canonical_event_bytes)`, matching the inbound chain's id rule
//! (see `runtime/control_loop/inbound_step::blake3_id`).

use rusqlite::{params, Connection};

use super::event::CompareEvent;
use crate::event_modules::sync::have::{codec as have_codec, event::HaveEvent};
use crate::event_modules::sync::negentropy_tree::query::node_fingerprint;
use crate::projection::contract::{SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::{BlakeId, WorkspaceId};
use crate::state::events_canonical::{EventScope, EventStatus};

/// Diagnostic table for tests/observability plus the underlying
/// `negentropy_tree` and `dep_cache` schemas the compare path reads.
/// The pure-projector dispatch path (`registry_meta::project_pure`)
/// writes a single row into `sync_compares_seen` to record receipt; the
/// real algorithm lives in `compute_writes` and is invoked via
/// `project`. The generic-context loader queries
/// `negentropy_root_membership` + `negentropy_node_hash` directly, so
/// those tables must be ready by the time any inbound chain runs.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_compares_seen (
            connection_id BLOB NOT NULL,
            workspace_id  BLOB NOT NULL,
            node_id       BLOB NOT NULL,
            fingerprint   BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (connection_id, workspace_id, node_id, fingerprint)
        );
        ",
    )?;
    crate::event_modules::sync::negentropy_tree::ensure_schema(conn)?;
    crate::event_modules::sync::dep_cache::ensure_schema(conn)?;
    crate::event_modules::sync::round_state::ensure_schema(conn)?;
    Ok(())
}

/// Inspect membership rows beneath `node_id` (strictly-longer node_ids that
/// share `node_id` as a byte prefix) and return the distinct child paths
/// of length `node_id.len() + 1`. Empty result means `node_id` is a leaf
/// in the projected tree state.
fn children_of(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
) -> rusqlite::Result<Vec<Vec<u8>>> {
    let prefix_len = node_id.len() as i64;
    let child_len = prefix_len + 1;
    let mut stmt = db.prepare(
        "SELECT DISTINCT substr(node_id, 1, ?3) AS child
         FROM negentropy_root_membership
         WHERE workspace_id = ?1
           AND length(node_id) > ?4
           AND substr(node_id, 1, ?4) = ?2
         ORDER BY child ASC",
    )?;
    let mut rows = stmt.query(params![
        workspace_id.to_vec(),
        node_id.to_vec(),
        child_len,
        prefix_len,
    ])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let child: Vec<u8> = row.get(0)?;
        out.push(child);
    }
    Ok(out)
}

/// Read the root member event_ids that live exactly at `node_id` (`R_v`
/// for a leaf node).
fn members_at(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
) -> rusqlite::Result<Vec<BlakeId>> {
    let mut stmt = db.prepare(
        "SELECT event_id FROM negentropy_root_membership
         WHERE workspace_id = ?1 AND node_id = ?2
         ORDER BY event_id ASC",
    )?;
    let mut rows = stmt.query(params![workspace_id.to_vec(), node_id.to_vec()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let blob: Vec<u8> = row.get(0)?;
        if blob.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            out.push(id);
        }
    }
    Ok(out)
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let h = blake3::hash(bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(h.as_bytes());
    id
}

/// Build the `(events_canonical row, outbox row)` write pair for a freshly
/// synthesized endpoint-local event, given its already-encoded canonical
/// bytes. Returns the event_id so callers can chain.
fn upsert_endpoint_local_event_ops(
    canonical_bytes: Vec<u8>,
    connection_id: &BlakeId,
    workspace_id: &WorkspaceId,
    created_at_ms: i64,
) -> (BlakeId, [WriteOp; 2]) {
    let event_id = blake3_id(&canonical_bytes);
    let ec = WriteOp::InsertOrIgnore {
        table: "events_canonical",
        columns: vec![
            "event_id",
            "canonical_event_bytes",
            "workspace_id",
            "scope",
            "status",
            "created_at_ms",
        ],
        values: vec![
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Blob(canonical_bytes),
            SqlVal::Blob(workspace_id.to_vec()),
            SqlVal::Text(EventScope::EndpointLocal.as_str().to_string()),
            SqlVal::Text(EventStatus::Applied.as_str().to_string()),
            SqlVal::Int(created_at_ms),
        ],
    };
    let ob = WriteOp::InsertOrIgnore {
        table: "outbox",
        columns: vec!["connection_id", "event_id", "queued_at_ms"],
        values: vec![
            SqlVal::Blob(connection_id.to_vec()),
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Int(created_at_ms),
        ],
    };
    (event_id, [ec, ob])
}

/// Compute the recursive-fold write ops for a received compare event.
///
/// Reads the local negentropy_tree state; emits no DB writes itself —
/// only returns `Vec<WriteOp>` for the apply stage.
///
/// Mirrors `registry_meta::project_pure`: on every mismatch we emit a
/// reciprocal `Compare(v, F_local)` so the peer drills on its side too,
/// followed by per-child Compares (interior) or per-member Haves (leaf).
/// See the doc-comment on `project_pure` for the asymmetric-tree
/// rationale.
pub fn compute_writes(db: &Connection, ev: &CompareEvent) -> rusqlite::Result<Vec<WriteOp>> {
    // F_v == remote? -> emit nothing.
    let local_fp = node_fingerprint(db, &ev.workspace_id, &ev.node_id)?;
    if local_fp == ev.fingerprint {
        return Ok(Vec::new());
    }

    // Splittable? Enumerate children. If non-empty, emit per-child compare.
    let children = children_of(db, &ev.workspace_id, &ev.node_id)?;
    let now_ms = ev.created_at_ms as i64;
    let mut ops: Vec<WriteOp> = Vec::new();

    // Reciprocal echo so the peer drills on its side at the same
    // node. Byte-identical to the peer's prior emission when the
    // peer originated this Compare, so `INSERT OR IGNORE` dedupes.
    let echo = CompareEvent {
        connection_id: ev.connection_id,
        workspace_id: ev.workspace_id,
        node_id: ev.node_id.clone(),
        fingerprint: local_fp,
        created_at_ms: ev.created_at_ms,
    };
    let echo_blob = super::codec::encode(&echo);
    let (_echo_id, echo_pair) = upsert_endpoint_local_event_ops(
        echo_blob,
        &ev.connection_id,
        &ev.workspace_id,
        now_ms,
    );
    ops.extend(echo_pair);

    if !children.is_empty() {
        for child in children {
            let child_fp = node_fingerprint(db, &ev.workspace_id, &child)?;
            let child_ev = CompareEvent {
                connection_id: ev.connection_id,
                workspace_id: ev.workspace_id,
                node_id: child,
                fingerprint: child_fp,
                created_at_ms: ev.created_at_ms,
            };
            let blob = super::codec::encode(&child_ev);
            let (_id, pair) = upsert_endpoint_local_event_ops(
                blob,
                &ev.connection_id,
                &ev.workspace_id,
                now_ms,
            );
            ops.extend(pair);
        }
        return Ok(ops);
    }

    // Leaf: emit one Have(event_id) per id in R_v.
    let members = members_at(db, &ev.workspace_id, &ev.node_id)?;
    for member in members {
        let have = HaveEvent {
            connection_id: ev.connection_id,
            workspace_id: ev.workspace_id,
            event_id: member,
            created_at_ms: ev.created_at_ms,
        };
        let blob = have_codec::encode(&have);
        let (_id, pair) = upsert_endpoint_local_event_ops(
            blob,
            &ev.connection_id,
            &ev.workspace_id,
            now_ms,
        );
        ops.extend(pair);
    }
    Ok(ops)
}

/// DB-aware projector: computes the negentropy fold and applies the
/// resulting `WriteOp`s in the supplied connection. Used by the smoke
/// tests; the registry-dispatch path (`registry_meta::project_pure`)
/// produces an empty result today because pure projectors cannot read DB
/// state. See `registry_meta` for the wiring story.
pub fn project(db: &Connection, ev: &CompareEvent) -> rusqlite::Result<()> {
    ensure_schema(db)?;
    crate::state::db::control_loop_tables::ensure_schema(db).ok();
    crate::event_modules::sync::negentropy_tree::ensure_schema(db).ok();
    let ops = compute_writes(db, ev)?;
    apply_ops(db, &ops)?;
    Ok(())
}

/// Local executor mirroring `state::projection::apply::write_exec` but
/// without dragging the legacy projection-queries trait into sync code.
pub(crate) fn apply_ops(db: &Connection, ops: &[WriteOp]) -> rusqlite::Result<()> {
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
                db.execute(&sql, refs.as_slice())?;
            }
            WriteOp::Delete {
                table,
                where_clause,
            } => {
                let conds: Vec<String> = where_clause
                    .iter()
                    .enumerate()
                    .map(|(i, (col, _))| format!("{} = ?{}", col, i + 1))
                    .collect();
                let sql = format!("DELETE FROM {} WHERE {}", table, conds.join(" AND "));
                let params_vec: Vec<Box<dyn rusqlite::ToSql>> = where_clause
                    .iter()
                    .map(|(_, v)| -> Box<dyn rusqlite::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let refs: Vec<&dyn rusqlite::ToSql> =
                    params_vec.iter().map(|b| b.as_ref()).collect();
                db.execute(&sql, refs.as_slice())?;
            }
        }
    }
    Ok(())
}
