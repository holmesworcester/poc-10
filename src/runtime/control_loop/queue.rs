//! SQLite-backed work queue with lease/retry primitives.
//!
//! Schema per `plan.md` lines 53-115 + the prompt:
//!
//! ```sql
//! CREATE TABLE work_queue (
//!     id INTEGER PRIMARY KEY AUTOINCREMENT,
//!     kind TEXT NOT NULL,
//!     payload BLOB NOT NULL,
//!     lease_owner TEXT,
//!     lease_until_ms INTEGER,
//!     retry_count INTEGER NOT NULL DEFAULT 0,
//!     last_error TEXT,
//!     enqueued_at_ms INTEGER NOT NULL,
//!     dedupe_key TEXT,
//!     UNIQUE(kind, dedupe_key)
//! );
//! ```

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::work_item::{WorkItem, WorkItemKind};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS work_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            payload BLOB NOT NULL,
            lease_owner TEXT,
            lease_until_ms INTEGER,
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            enqueued_at_ms INTEGER NOT NULL,
            dedupe_key TEXT,
            UNIQUE(kind, dedupe_key)
        );
        CREATE INDEX IF NOT EXISTS idx_work_queue_claim
            ON work_queue (kind, lease_until_ms);
        ",
    )?;
    Ok(())
}

/// One row in the queue.
#[derive(Debug, Clone)]
pub struct QueueRow {
    pub id: i64,
    pub kind: WorkItemKind,
    pub payload: Vec<u8>,
    pub lease_owner: Option<String>,
    pub lease_until_ms: Option<i64>,
    pub retry_count: i64,
    pub last_error: Option<String>,
    pub enqueued_at_ms: i64,
    pub dedupe_key: Option<String>,
}

/// A claimed work row plus its lease bookkeeping.
#[derive(Debug, Clone)]
pub struct ClaimedWork {
    pub row: QueueRow,
}

/// Insert a work item. Returns the row id, or `None` if a row with the same
/// `(kind, dedupe_key)` already existed (idempotent enqueue).
pub fn enqueue(
    conn: &Connection,
    item: &WorkItem,
    payload: &[u8],
    enqueued_at_ms: i64,
) -> SqliteResult<Option<i64>> {
    let kind = item.kind().as_str();
    let dedupe = item.dedupe_key();
    let res = conn.execute(
        "INSERT OR IGNORE INTO work_queue
            (kind, payload, lease_owner, lease_until_ms, retry_count, last_error,
             enqueued_at_ms, dedupe_key)
         VALUES (?1, ?2, NULL, NULL, 0, NULL, ?3, ?4)",
        params![kind, payload, enqueued_at_ms, dedupe],
    )?;
    if res == 0 {
        Ok(None)
    } else {
        Ok(Some(conn.last_insert_rowid()))
    }
}

/// Claim one row of the given kind whose lease has expired (or that has no
/// lease). Sets `lease_owner` and `lease_until_ms` so other claimants skip it.
pub fn claim_one(
    conn: &Connection,
    kind: WorkItemKind,
    owner: &str,
    now_ms: i64,
    lease_duration_ms: i64,
) -> SqliteResult<Option<ClaimedWork>> {
    let kind_str = kind.as_str();
    let until = now_ms + lease_duration_ms;

    // Pick the oldest unleased / lease-expired row.
    let id_opt: Option<i64> = conn
        .query_row(
            "SELECT id FROM work_queue
             WHERE kind = ?1
               AND (lease_until_ms IS NULL OR lease_until_ms <= ?2)
             ORDER BY id ASC
             LIMIT 1",
            params![kind_str, now_ms],
            |row| row.get(0),
        )
        .optional()?;

    let Some(id) = id_opt else {
        return Ok(None);
    };

    let updated = conn.execute(
        "UPDATE work_queue
         SET lease_owner = ?1, lease_until_ms = ?2
         WHERE id = ?3
           AND (lease_until_ms IS NULL OR lease_until_ms <= ?4)",
        params![owner, until, id, now_ms],
    )?;
    if updated == 0 {
        return Ok(None);
    }

    let row = load_row(conn, id)?;
    Ok(row.map(|r| ClaimedWork { row: r }))
}

/// Mark a claimed row as done — i.e. delete it. Returns `true` if a row was
/// removed.
pub fn mark_done(conn: &Connection, id: i64) -> SqliteResult<bool> {
    let n = conn.execute("DELETE FROM work_queue WHERE id = ?1", params![id])?;
    Ok(n > 0)
}

/// Mark a claimed row as failed: bump retry_count, store the error, and
/// release the lease so it gets retried.
pub fn mark_failed(conn: &Connection, id: i64, err: &str) -> SqliteResult<()> {
    conn.execute(
        "UPDATE work_queue
         SET retry_count = retry_count + 1,
             last_error  = ?1,
             lease_owner = NULL,
             lease_until_ms = NULL
         WHERE id = ?2",
        params![err, id],
    )?;
    Ok(())
}

/// Release a lease without changing retry_count or last_error. Used when a
/// worker shuts down cleanly mid-claim.
pub fn release_lease(conn: &Connection, id: i64) -> SqliteResult<()> {
    conn.execute(
        "UPDATE work_queue
         SET lease_owner = NULL, lease_until_ms = NULL
         WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

/// Re-enqueue a claimed row by clearing its lease. Identical to
/// `release_lease` but is the named primitive for "I'm intentionally giving
/// this back, please dispatch again".
pub fn requeue(conn: &Connection, id: i64) -> SqliteResult<()> {
    release_lease(conn, id)
}

fn load_row(conn: &Connection, id: i64) -> SqliteResult<Option<QueueRow>> {
    conn.query_row(
        "SELECT id, kind, payload, lease_owner, lease_until_ms, retry_count,
                last_error, enqueued_at_ms, dedupe_key
         FROM work_queue WHERE id = ?1",
        params![id],
        |row| {
            let kind_str: String = row.get(1)?;
            let kind = WorkItemKind::parse(&kind_str).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    format!("unknown WorkItemKind: {}", kind_str).into(),
                )
            })?;
            Ok(QueueRow {
                id: row.get(0)?,
                kind,
                payload: row.get(2)?,
                lease_owner: row.get(3)?,
                lease_until_ms: row.get(4)?,
                retry_count: row.get(5)?,
                last_error: row.get(6)?,
                enqueued_at_ms: row.get(7)?,
                dedupe_key: row.get(8)?,
            })
        },
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::control_loop::work_item::{InboundBytes, JobTick};

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn enqueue_dedupe_idempotent() {
        let conn = open();
        let item = WorkItem::InboundBytes(InboundBytes {
            wire_id: [9u8; 32],
            bytes: vec![1, 2, 3],
            remote_endpoint_id: None,
            source_ip: None,
            source_port: None,
            received_at_ms: 0,
        });
        let id1 = enqueue(&conn, &item, b"payload", 100).unwrap();
        let id2 = enqueue(&conn, &item, b"payload", 200).unwrap();
        assert!(id1.is_some());
        assert!(id2.is_none(), "second enqueue with same dedupe must collapse");
    }

    #[test]
    fn claim_lease_done_cycle() {
        let conn = open();
        let item = WorkItem::JobTick(JobTick {
            job_name: "ping".to_string(),
            fired_at_ms: 1000,
        });
        enqueue(&conn, &item, b"data", 1000).unwrap();
        let claim = claim_one(&conn, WorkItemKind::JobTick, "worker-1", 1100, 5000)
            .unwrap()
            .expect("claim should succeed");
        assert_eq!(claim.row.kind, WorkItemKind::JobTick);
        // Second claim under same lease window: nothing left to claim.
        let again =
            claim_one(&conn, WorkItemKind::JobTick, "worker-2", 1200, 5000).unwrap();
        assert!(again.is_none());
        assert!(mark_done(&conn, claim.row.id).unwrap());
    }

    #[test]
    fn failed_row_returns_to_queue() {
        let conn = open();
        let item = WorkItem::JobTick(JobTick {
            job_name: "p".to_string(),
            fired_at_ms: 1,
        });
        enqueue(&conn, &item, b"d", 0).unwrap();
        let claim = claim_one(&conn, WorkItemKind::JobTick, "w", 0, 1000)
            .unwrap()
            .unwrap();
        mark_failed(&conn, claim.row.id, "boom").unwrap();
        let again = claim_one(&conn, WorkItemKind::JobTick, "w", 5000, 1000)
            .unwrap()
            .unwrap();
        assert_eq!(again.row.retry_count, 1);
        assert_eq!(again.row.last_error.as_deref(), Some("boom"));
    }
}
