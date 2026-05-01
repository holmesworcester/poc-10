//! Projector for `HaveEvent`.
//!
//! Implements (plan.md lines 376-380):
//!
//! ```text
//! have.project:
//!   if local has event_id:
//!     emit nothing (we already have it)
//!   else:
//!     emit a Need(event_id) endpoint-local event into events_canonical
//!     and queue an outbox row for it.
//! ```
//!
//! "Local has" is decided against `events_canonical` — any row with
//! `status IN ('applied', 'ready', 'blocked', 'processing')` counts as
//! "we have it"; only `rejected` and missing rows mean we should request.
//! The event id of the synthesized Need event is `blake3(canonical_event_bytes)`,
//! matching the inbound chain's id rule.

use rusqlite::{params, Connection};

use super::event::HaveEvent;
use crate::event_modules::sync::compare::projector::apply_ops;
use crate::event_modules::sync::need::{codec as need_codec, event::NeedEvent};
use crate::projection::contract::{SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::BlakeId;
use crate::state::events_canonical::{EventScope, EventStatus};

/// Diagnostic table for tests/observability.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_haves_seen (
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

/// `true` iff `event_id` is locally present in `events_canonical` in any
/// non-rejected status. A `rejected` row means we have explicitly refused
/// the bytes and should not pretend to "have" them; a missing row means
/// we have never seen them.
fn local_has_event(db: &Connection, event_id: &BlakeId) -> rusqlite::Result<bool> {
    let row: Option<String> = db
        .query_row(
            "SELECT status FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| r.get::<_, String>(0),
        )
        .ok();
    Ok(match row {
        Some(s) => s != "rejected",
        None => false,
    })
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let h = blake3::hash(bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(h.as_bytes());
    id
}

/// Compute the write ops for a received Have event without applying them.
pub fn compute_writes(db: &Connection, ev: &HaveEvent) -> rusqlite::Result<Vec<WriteOp>> {
    if local_has_event(db, &ev.event_id)? {
        return Ok(Vec::new());
    }

    // Synthesize an endpoint-local Need event and queue it for the connection.
    let need = NeedEvent {
        connection_id: ev.connection_id,
        workspace_id: ev.workspace_id,
        event_id: ev.event_id,
        created_at_ms: ev.created_at_ms,
    };
    let blob = need_codec::encode(&need);
    let need_id = blake3_id(&blob);
    let now_ms = ev.created_at_ms as i64;

    let ops = vec![
        WriteOp::InsertOrIgnore {
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
                SqlVal::Blob(need_id.to_vec()),
                SqlVal::Blob(blob),
                SqlVal::Blob(ev.workspace_id.to_vec()),
                SqlVal::Text(EventScope::EndpointLocal.as_str().to_string()),
                SqlVal::Text(EventStatus::Applied.as_str().to_string()),
                SqlVal::Int(now_ms),
            ],
        },
        WriteOp::InsertOrIgnore {
            table: "outbox",
            columns: vec!["connection_id", "event_id", "queued_at_ms"],
            values: vec![
                SqlVal::Blob(ev.connection_id.to_vec()),
                SqlVal::Blob(need_id.to_vec()),
                SqlVal::Int(now_ms),
            ],
        },
    ];
    Ok(ops)
}

/// DB-aware projector: computes the local-has check + Need synthesis and
/// applies the resulting `WriteOp`s.
pub fn project(db: &Connection, ev: &HaveEvent) -> rusqlite::Result<()> {
    ensure_schema(db)?;
    crate::state::db::control_loop_tables::ensure_schema(db).ok();
    let ops = compute_writes(db, ev)?;
    apply_ops(db, &ops)?;
    Ok(())
}
