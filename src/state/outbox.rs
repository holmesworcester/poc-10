//! # Outbox (slim per-connection send queue)
//!
//! ## Purpose
//! Source of truth for "events that still need to be sent on connection
//! C". Slim by design (`plan.md` lines 168-185): only `(connection_id,
//! event_id, queued_at_ms)` triples. All claim/refill/retry/in-flight
//! tracking lives in the per-connection `ConnectionSender` in
//! `runtime/jobs/sender`.
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the table layout and dedupe key,
//! - read-only `pending_for_connection` queries,
//! - bulk `delete` on socket-accept,
//! - idempotent `enqueue` from projectors.
//!
//! Does NOT own:
//! - the wire bytes (the sender resolves them from
//!   `events_canonical.canonical_event_bytes`),
//! - in-flight tracking (`ConnectionSender.present`),
//! - retry / backoff (`ConnectionSender.drain_to_socket` reports
//!   `send_failed`; the OutboxWake handler schedules retries),
//! - any per-row status — there is none.
//!
//! ## Interfaces
//! - [`enqueue`] — idempotent on `(connection_id, event_id)`.
//! - [`pending_for_connection`] — read-only paging in
//!   `(queued_at_ms ASC, event_id ASC)` order.
//! - [`delete`] — bulk delete after socket-accept.
//!
//! ## State
//! ```text
//! outbox:
//!   connection_id  BLOB NOT NULL
//!   event_id       BLOB NOT NULL
//!   queued_at_ms   INTEGER NOT NULL
//!   PRIMARY KEY (connection_id, event_id)
//! ```
//! Schema lives in `state::db::control_loop_tables::ensure_schema`.
//!
//! ## Invariants
//! - **No payload column.** The triple `(connection_id, event_id,
//!   queued_at_ms)` is everything stored.
//! - **No per-row claim, lease, or retry status.** The sender's in-memory
//!   `present` set carries in-flight state.
//! - **Dedupe is `(connection_id, event_id)`**, not ciphertext-based.
//!   Re-projecting the same event for the same connection is a no-op.
//! - **Two independent workspace-membership checks**:
//!   1. the projector wrote the row only after confirming
//!      `workspace_id ∈ shared_workspaces(C)`,
//!   2. `connection.wrap` re-checks before egress.
//!   (Plus a symmetric `connection.unwrap` check on the receiving side.)
//! - Order: `pending_for_connection` returns rows in
//!   `queued_at_ms ASC, event_id ASC`. The `event_id` tiebreaker is what
//!   makes the order stable when timestamps collide.
//!
//! ## Flow
//! ```text
//!   projector --enqueue(conn, event_id, queued_at_ms)--> outbox row
//!                                                            |
//!   ConnectionSender.refill_if_needed --pending_for_connection-+
//!                                                            |
//!                          (wraps batch, sends frame to TCP)
//!                                                            |
//!   socket-accept --delete(conn, [event_ids])--> outbox rows gone
//! ```
//!
//! ## Failure / restart behavior
//! - On crash, the table survives unchanged. The sender starts empty in
//!   memory and refills from the table on the next `OutboxWake`.
//! - On send failure, the row stays put; the sender clears its `present`
//!   set so the next refill picks the row up again.
//!
//! ## Performance notes
//! - PRIMARY KEY is `(connection_id, event_id)` — both lookups and dedupe
//!   are single index probes.
//! - `pending_for_connection` uses a bounded `LIMIT` so the sender can
//!   page predictably.
//! - `delete` uses a single `IN (...)` clause for bulk acceptance.
//!
//! ## Testing hooks
//! - In-file `tests` cover idempotent enqueue, ordered pending, bulk
//!   delete, and per-connection isolation.

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::runtime::control_loop::work_item::{BlakeId, ConnectionId};

/// Insert an outbox entry, idempotent on `(connection_id, event_id)`.
/// Returns `true` if a new row was created, `false` if it already existed.
pub fn enqueue(
    conn: &Connection,
    connection_id: ConnectionId,
    event_id: BlakeId,
    queued_at_ms: i64,
) -> SqliteResult<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO outbox
            (connection_id, event_id, queued_at_ms)
         VALUES (?1, ?2, ?3)",
        params![connection_id.to_vec(), event_id.to_vec(), queued_at_ms],
    )?;
    Ok(n > 0)
}

/// Read up to `max` pending outbox rows for `connection_id` ordered by
/// `queued_at_ms` (then `event_id` as a stable tiebreaker). This is a
/// **read-only** select — no claim, lease, or status mutation. The
/// per-connection `ConnectionSender` calls this to refill its hot queue;
/// any in-flight ids it tracks separately in its own `present` set.
///
/// Returns `(event_id, queued_at_ms)` pairs.
pub fn pending_for_connection(
    conn: &Connection,
    connection_id: &ConnectionId,
    max: usize,
) -> SqliteResult<Vec<(BlakeId, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT event_id, queued_at_ms
         FROM outbox
         WHERE connection_id = ?1
         ORDER BY queued_at_ms ASC, event_id ASC
         LIMIT ?2",
    )?;
    let mut rows = stmt.query(params![connection_id.to_vec(), max as i64])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let eid_blob: Vec<u8> = row.get(0)?;
        let qts: i64 = row.get(1)?;
        let eid = blob_to_32(&eid_blob)?;
        out.push((eid, qts));
    }
    Ok(out)
}

/// Bulk delete the given `event_ids` for `connection_id` after the
/// corresponding frame is socket-accepted. Returns the number of rows
/// removed.
pub fn delete(
    conn: &Connection,
    connection_id: &ConnectionId,
    event_ids: &[BlakeId],
) -> SqliteResult<usize> {
    if event_ids.is_empty() {
        return Ok(0);
    }
    let placeholders = event_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "DELETE FROM outbox
         WHERE connection_id = ? AND event_id IN ({})",
        placeholders
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut p: Vec<Box<dyn rusqlite::ToSql>> = Vec::with_capacity(event_ids.len() + 1);
    p.push(Box::new(connection_id.to_vec()));
    for id in event_ids {
        p.push(Box::new(id.to_vec()));
    }
    let refs = p.iter().map(|b| b.as_ref()).collect::<Vec<_>>();
    let n = stmt.execute(rusqlite::params_from_iter(refs))?;
    Ok(n)
}

fn blob_to_32(b: &[u8]) -> rusqlite::Result<[u8; 32]> {
    if b.len() != 32 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            format!("expected 32 bytes, got {}", b.len()).into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::db::control_loop_tables::ensure_schema;

    fn open() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c
    }

    #[test]
    fn enqueue_is_idempotent_on_pair() {
        let c = open();
        let cid: ConnectionId = [1u8; 32];
        let eid: BlakeId = [2u8; 32];
        assert!(enqueue(&c, cid, eid, 100).unwrap());
        assert!(!enqueue(&c, cid, eid, 200).unwrap());
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn pending_for_connection_returns_in_queue_order() {
        let c = open();
        let cid: ConnectionId = [1u8; 32];
        let e_old: BlakeId = [2u8; 32];
        let e_mid: BlakeId = [3u8; 32];
        let e_new: BlakeId = [4u8; 32];
        // Insert out of time order to verify the ORDER BY actually does work.
        enqueue(&c, cid, e_new, 300).unwrap();
        enqueue(&c, cid, e_old, 100).unwrap();
        enqueue(&c, cid, e_mid, 200).unwrap();
        let got = pending_for_connection(&c, &cid, 16).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, e_old);
        assert_eq!(got[1].0, e_mid);
        assert_eq!(got[2].0, e_new);
        // Times round-trip.
        assert_eq!(got[0].1, 100);
    }

    #[test]
    fn pending_for_connection_filters_by_connection() {
        let c = open();
        let a: ConnectionId = [1u8; 32];
        let b: ConnectionId = [9u8; 32];
        let e: BlakeId = [2u8; 32];
        enqueue(&c, a, e, 0).unwrap();
        enqueue(&c, b, e, 0).unwrap();
        let only_a = pending_for_connection(&c, &a, 16).unwrap();
        assert_eq!(only_a.len(), 1);
        let only_b = pending_for_connection(&c, &b, 16).unwrap();
        assert_eq!(only_b.len(), 1);
    }

    #[test]
    fn pending_for_connection_respects_max() {
        let c = open();
        let cid: ConnectionId = [1u8; 32];
        for i in 0u8..5 {
            let mut e = [0u8; 32];
            e[0] = i;
            enqueue(&c, cid, e, i as i64).unwrap();
        }
        let got = pending_for_connection(&c, &cid, 3).unwrap();
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn delete_is_bulk_and_idempotent() {
        let c = open();
        let cid: ConnectionId = [1u8; 32];
        let e1: BlakeId = [2u8; 32];
        let e2: BlakeId = [3u8; 32];
        let e3: BlakeId = [4u8; 32];
        enqueue(&c, cid, e1, 0).unwrap();
        enqueue(&c, cid, e2, 0).unwrap();
        enqueue(&c, cid, e3, 0).unwrap();
        let n = delete(&c, &cid, &[e1, e2]).unwrap();
        assert_eq!(n, 2);
        let remaining = pending_for_connection(&c, &cid, 16).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, e3);
        // Second delete is a no-op.
        let n = delete(&c, &cid, &[e1, e2]).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn delete_only_targets_named_connection() {
        let c = open();
        let a: ConnectionId = [1u8; 32];
        let b: ConnectionId = [9u8; 32];
        let e: BlakeId = [2u8; 32];
        enqueue(&c, a, e, 0).unwrap();
        enqueue(&c, b, e, 0).unwrap();
        delete(&c, &a, &[e]).unwrap();
        assert!(pending_for_connection(&c, &a, 16).unwrap().is_empty());
        assert_eq!(pending_for_connection(&c, &b, 16).unwrap().len(), 1);
    }
}
