//! Periodic sync seeding job.
//!
//! Per plan.md ("Jobs decide when to begin a root compare for a
//! connection"), the sync family registers a periodic JobTick whose
//! body — kept entirely in the event-module so the kernel stays
//! policy-free — emits one root `CompareEvent` per (connection,
//! workspace) pair.
//!
//! ### Why this exists
//!
//! Negentropy convergence requires both sides to have a recent
//! fingerprint of the other. Connection apply already emits one root
//! Compare from each end on bring-up (see
//! `event_modules::connection::post_apply::emit_root_compare`), but
//! that single shot is insufficient when:
//!
//! - the responder didn't have the workspace yet at connect time
//!   (later joined), or
//! - one side authored a new event after both sides had been quiet
//!   long enough that the other side has no signal to descend.
//!
//! The previous incarnation of the sync code papered over the gap with
//! a brute-force `Have(id)` push from the apply path. That was a
//! scaffolding hack ("real negentropy" requires both sides emit root
//! Compares; the recursion converges symmetrically). The post-apply
//! root-Compare nudge plus this periodic JobTick are the two real
//! seeds.
//!
//! ### Schedule
//!
//! [`SYNC_ROOT_COMPARE_JOB_NAME`] / [`SYNC_ROOT_COMPARE_EVERY_MS`].
//! The schedule row is written by [`ensure_schedule`] which the
//! runtime startup invokes once.
//!
//! ### Behavior
//!
//! For every `(connection_id, workspace_id)` in
//! `connection_shared_workspaces`, write an endpoint-local
//! `CompareEvent` with the local root fingerprint and queue an outbox
//! row. Idempotent on repeat invocation: identical
//! `(canonical_event_bytes -> blake3) -> event_id` collide via
//! `INSERT OR IGNORE`, and outbox rows the sender has already drained
//! are gone before this fires again, so a JobTick at steady state with
//! an unchanged fingerprint is a single insert + a delete-and-resend
//! cycle.

use rusqlite::{params, Connection};

use crate::event_modules::sync::compare::{codec as compare_codec, event::CompareEvent};
use crate::projection::contract::{SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::{BlakeId, WorkspaceId};
use crate::state::events_canonical::{EventScope, EventStatus};

/// Job name written into `job_schedules.job_name` and into
/// `JobTick.job_name`.
pub const SYNC_ROOT_COMPARE_JOB_NAME: &str = "sync_root_compare";

/// How often the round-driver tick fires. Set short — the per-tick
/// body is gated by [`super::round_state::drivers_due_for_root_compare`]
/// (quiet-detector + min-round-gap), so a tick that fires while the
/// connection is mid-round is a single SELECT returning no rows. A
/// 100ms cadence gives the driver fast-recovery on quiet (the next
/// round starts ~100ms after the last frame is observed).
pub const SYNC_ROOT_COMPARE_EVERY_MS: i64 = 100;

/// Insert (or refresh) the `job_schedules` row that drives this job.
/// Idempotent — safe to call from every daemon-startup path. The
/// `next_fire_at_ms` is set to `now_ms` so the first tick fires
/// immediately on boot.
pub fn ensure_schedule(db: &Connection, now_ms: i64) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO job_schedules
            (job_name, every_ms, next_fire_at_ms, last_fired_at_ms)
         VALUES (?1, ?2, ?3, NULL)",
        params![
            SYNC_ROOT_COMPARE_JOB_NAME,
            SYNC_ROOT_COMPARE_EVERY_MS,
            now_ms,
        ],
    )?;
    Ok(())
}

/// Run the round-driver tick body. For each connection where THIS
/// daemon is the deterministic driver (lex-smaller endpoint) AND the
/// connection has been quiet long enough to count the previous round
/// "done" AND the configured min-round-gap has elapsed, emit one fresh
/// root `CompareEvent` per shared workspace, then stamp the round-state
/// row's `last_root_compare_at_ms`. Caller owns the transaction.
///
/// Most ticks at steady state are a single SELECT returning no rows
/// (either we're not the driver, or the connection is mid-round, or
/// the previous round just finished and we're under MIN_ROUND_GAP_MS
/// from that). The expensive part — encoding the CompareEvent and
/// updating outbox — only runs on the driver's "next round is due"
/// transition.
pub fn tick(db: &Connection, now_ms: i64) -> rusqlite::Result<TickReport> {
    let mut report = TickReport::default();
    let due_drivers =
        crate::event_modules::sync::round_state::drivers_due_for_root_compare(db, now_ms)?;
    if due_drivers.is_empty() {
        return Ok(report);
    }
    let workspaces_by_connection = list_workspaces_grouped_by_connection(db)?;
    for connection_id in due_drivers {
        let Some(workspaces) = workspaces_by_connection.get(&connection_id) else {
            continue;
        };
        for workspace_id in workspaces {
            emit_one_root_compare(db, &connection_id, workspace_id, now_ms)?;
            report.compares_emitted += 1;
        }
        crate::event_modules::sync::round_state::mark_root_compare_emitted(
            db,
            &connection_id,
            now_ms,
        )?;
    }
    Ok(report)
}

/// What the tick did. Useful for tests / observability.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    pub compares_emitted: usize,
}

fn list_workspaces_grouped_by_connection(
    db: &Connection,
) -> rusqlite::Result<std::collections::HashMap<BlakeId, Vec<WorkspaceId>>> {
    let mut stmt = db.prepare(
        "SELECT connection_id, workspace_id FROM connection_shared_workspaces
         ORDER BY connection_id ASC, workspace_id ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut out: std::collections::HashMap<BlakeId, Vec<WorkspaceId>> =
        std::collections::HashMap::new();
    while let Some(r) = rows.next()? {
        let cid_blob: Vec<u8> = r.get(0)?;
        let wid_blob: Vec<u8> = r.get(1)?;
        if cid_blob.len() != 32 || wid_blob.len() != 32 {
            continue;
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&cid_blob);
        let mut wid = [0u8; 32];
        wid.copy_from_slice(&wid_blob);
        out.entry(cid).or_default().push(wid);
    }
    Ok(out)
}

fn emit_one_root_compare(
    db: &Connection,
    connection_id: &BlakeId,
    workspace_id: &WorkspaceId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    let fp = crate::event_modules::sync::negentropy_tree::query::node_fingerprint(
        db,
        workspace_id,
        &[],
    )
    .unwrap_or([0u8; 32]);
    let ev = CompareEvent {
        connection_id: *connection_id,
        workspace_id: *workspace_id,
        node_id: Vec::new(),
        fingerprint: fp,
        created_at_ms: now_ms as u64,
    };
    let bytes = compare_codec::encode(&ev);
    let event_id = blake3_id(&bytes);
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
            SqlVal::Blob(bytes),
            SqlVal::Blob(workspace_id.to_vec()),
            SqlVal::Text(EventScope::EndpointLocal.as_str().to_string()),
            SqlVal::Text(EventStatus::Applied.as_str().to_string()),
            SqlVal::Int(now_ms),
        ],
    };
    let ob = WriteOp::InsertOrIgnore {
        table: "outbox",
        columns: vec!["connection_id", "event_id", "queued_at_ms"],
        values: vec![
            SqlVal::Blob(connection_id.to_vec()),
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Int(now_ms),
        ],
    };
    apply_ops(db, &[ec, ob])?;
    Ok(())
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

fn apply_ops(db: &Connection, ops: &[WriteOp]) -> rusqlite::Result<()> {
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
                let bound: Vec<Box<dyn rusqlite::ToSql>> = values
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
                    bound.iter().map(|b| b.as_ref()).collect();
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
                let bound: Vec<Box<dyn rusqlite::ToSql>> = where_clause
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
                    bound.iter().map(|b| b.as_ref()).collect();
                db.execute(&sql, refs.as_slice())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::db::control_loop_tables::ensure_schema as ensure_loop_schema;

    fn open_db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_loop_schema(&c).unwrap();
        crate::event_modules::sync::ensure_schema(&c).unwrap();
        // Manually create connection_shared_workspaces for tests since
        // the connection projector is what owns this in production.
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
                connection_id BLOB NOT NULL,
                workspace_id  BLOB NOT NULL,
                PRIMARY KEY (connection_id, workspace_id)
            );",
        )
        .unwrap();
        c
    }

    #[test]
    fn tick_emits_zero_when_no_connections() {
        let db = open_db();
        let report = tick(&db, 0).unwrap();
        assert_eq!(report.compares_emitted, 0);
    }

    #[test]
    fn tick_emits_only_for_driver_when_round_due() {
        let db = open_db();
        let conn_id = [1u8; 32];
        let ws = [2u8; 32];
        let local = [0u8; 32];
        let remote = [9u8; 32]; // local < remote => local is driver
        db.execute(
            "INSERT INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), ws.to_vec()],
        )
        .unwrap();
        crate::event_modules::sync::round_state::upsert(&db, &conn_id, &local, &remote, 0)
            .unwrap();
        let now = crate::event_modules::sync::round_state::MIN_ROUND_GAP_MS + 1_000;
        let report = tick(&db, now).unwrap();
        assert_eq!(report.compares_emitted, 1);
        let outbox_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE connection_id = ?1",
                params![conn_id.to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(outbox_count, 1);
    }

    #[test]
    fn tick_emits_zero_when_local_is_not_driver() {
        let db = open_db();
        let conn_id = [1u8; 32];
        let ws = [2u8; 32];
        let local = [9u8; 32];
        let remote = [0u8; 32]; // local > remote => not driver
        db.execute(
            "INSERT INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), ws.to_vec()],
        )
        .unwrap();
        crate::event_modules::sync::round_state::upsert(&db, &conn_id, &local, &remote, 0)
            .unwrap();
        let now = crate::event_modules::sync::round_state::MIN_ROUND_GAP_MS + 1_000;
        let report = tick(&db, now).unwrap();
        assert_eq!(report.compares_emitted, 0);
    }

    #[test]
    fn tick_emits_zero_during_in_flight_round() {
        let db = open_db();
        let conn_id = [1u8; 32];
        let ws = [2u8; 32];
        let local = [0u8; 32];
        let remote = [9u8; 32];
        db.execute(
            "INSERT INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), ws.to_vec()],
        )
        .unwrap();
        crate::event_modules::sync::round_state::upsert(&db, &conn_id, &local, &remote, 0)
            .unwrap();
        let now = crate::event_modules::sync::round_state::MIN_ROUND_GAP_MS + 1_000;
        // Recent inbound traffic — connection is mid-round.
        crate::event_modules::sync::round_state::mark_inbound(&db, &conn_id, now - 10).unwrap();
        let report = tick(&db, now).unwrap();
        assert_eq!(report.compares_emitted, 0);
    }

    #[test]
    fn ensure_schedule_is_idempotent() {
        let db = open_db();
        ensure_schedule(&db, 0).unwrap();
        ensure_schedule(&db, 0).unwrap();
        let n: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM job_schedules WHERE job_name = ?1",
                params![SYNC_ROOT_COMPARE_JOB_NAME],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }
}
