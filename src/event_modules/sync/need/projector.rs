//! Projector for `NeedEvent` (plan.md line 379).
//!
//! ```text
//! need.project:
//!   if local has event_id:
//!     write outbox(connection_id, event_id) so the per-connection sender
//!     batch-loads the canonical event bytes and ships them.
//!   else:
//!     emit nothing (we cannot satisfy the need).
//! ```
//!
//! Important detail: the outbox row carries the **durable** `event_id` that
//! the peer asked for, not a wrapper or a synthesized hint. The
//! per-connection sender will resolve `events_canonical.canonical_event_bytes`
//! and wrap with `connection.wrap` at egress time.

use rusqlite::{params, Connection};

use super::event::NeedEvent;
use crate::event_modules::sync::compare::projector::apply_ops;
use crate::projection::contract::{SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::BlakeId;

/// Diagnostic table for tests/observability.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_needs_seen (
            connection_id BLOB NOT NULL,
            workspace_id  BLOB NOT NULL,
            event_id      BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (connection_id, workspace_id, event_id)
        );
        ",
    )?;
    Ok(())
}

/// Sendable iff the row exists in `events_canonical` with a
/// non-`rejected`, non-`processing` status AND non-empty canonical bytes
/// (the `processing` claim has empty bytes per `events_canonical::admit_event_id`).
fn local_can_send(db: &Connection, event_id: &BlakeId) -> rusqlite::Result<bool> {
    let row: Option<(String, Vec<u8>)> = db
        .query_row(
            "SELECT status, canonical_event_bytes FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .ok();
    Ok(match row {
        Some((status, bytes)) => status != "rejected" && !bytes.is_empty(),
        None => false,
    })
}

/// Compute the write ops for a received Need event without applying them.
pub fn compute_writes(db: &Connection, ev: &NeedEvent) -> rusqlite::Result<Vec<WriteOp>> {
    if !local_can_send(db, &ev.event_id)? {
        return Ok(Vec::new());
    }

    // Single outbox row carrying the durable event_id. The sender resolves
    // canonical bytes and wraps at egress.
    let now_ms = ev.created_at_ms as i64;
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "outbox",
        columns: vec!["connection_id", "event_id", "queued_at_ms"],
        values: vec![
            SqlVal::Blob(ev.connection_id.to_vec()),
            SqlVal::Blob(ev.event_id.to_vec()),
            SqlVal::Int(now_ms),
        ],
    }];
    Ok(ops)
}

/// DB-aware projector: computes the can-send check and applies resulting ops.
pub fn project(db: &Connection, ev: &NeedEvent) -> rusqlite::Result<()> {
    ensure_schema(db)?;
    crate::state::db::control_loop_tables::ensure_schema(db).ok();
    let ops = compute_writes(db, ev)?;
    apply_ops(db, &ops)?;
    Ok(())
}
