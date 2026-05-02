//! Per-connection negentropy round bookkeeping.
//!
//! Owns one row per `(connection_id)` recording:
//!
//!   - `local_endpoint_id`, `remote_endpoint_id` — used by [`is_driver`]
//!     to deterministically pick exactly one side as the round driver
//!     for this connection. The driver is the side with the
//!     lexicographically smaller endpoint id; this avoids both sides
//!     simultaneously starting fresh rounds.
//!   - `last_inbound_at_ms` — bumped by the inbound chain on every
//!     received frame for this connection (wire-level, before chain
//!     processing). Used as the "quiet detector" — a driver waits
//!     until `now - last_inbound >= QUIET_THRESHOLD_MS` before kicking
//!     off the next round, so an in-flight round drained naturally
//!     isn't disturbed.
//!   - `last_outbound_at_ms` — bumped by the per-connection sender
//!     actor each time it ships a frame batch. Same role as
//!     last_inbound: the driver leaves headroom for the receiver to
//!     reply before scheduling the next root.
//!   - `last_root_compare_at_ms` — the last time we (the driver) wrote
//!     a fresh root `Compare` for this connection. Combined with
//!     `MIN_ROUND_GAP_MS`, prevents back-to-back rounds at the tick
//!     cadence even if traffic is silent.
//!
//! Updated as plain `UPDATE` statements from the relevant pipeline
//! seams (apply, inbound observation, outbound send). Reads happen
//! from the periodic [`super::job::tick`] body which decides which
//! `(connection_id, workspace_id)` pairs the driver owes a fresh
//! root Compare for right now.

use rusqlite::{params, Connection};

use crate::runtime::control_loop::work_item::{BlakeId, EndpointId};

/// Threshold (ms) below which the driver suppresses the next root
/// Compare because the connection is mid-round. POC value — long
/// enough that a 2-3 round-trip drill-down on TCP loopback finishes
/// inside the window, short enough that initial-sync convergence
/// doesn't stall when traffic genuinely stops.
pub const QUIET_THRESHOLD_MS: i64 = 200;

/// Minimum gap (ms) between successive root Compares from the driver
/// on the same connection, even if the connection is "quiet" by the
/// inbound/outbound timestamp test. Prevents the driver from re-firing
/// every tick interval when one side has nothing to say.
pub const MIN_ROUND_GAP_MS: i64 = 300;

/// Idempotent table create. Called from
/// [`super::ensure_schema`].
pub fn ensure_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS connection_round_state (
            connection_id            BLOB PRIMARY KEY,
            local_endpoint_id        BLOB NOT NULL,
            remote_endpoint_id       BLOB NOT NULL,
            last_inbound_at_ms       INTEGER NOT NULL DEFAULT 0,
            last_outbound_at_ms      INTEGER NOT NULL DEFAULT 0,
            last_root_compare_at_ms  INTEGER NOT NULL DEFAULT 0
        );",
    )
}

/// Deterministic driver test. The endpoint with the smaller
/// 32-byte id (lex order) is the driver — both sides agree because
/// they observe the same canonical Connection event.
pub fn is_driver(local: &EndpointId, remote: &EndpointId) -> bool {
    local < remote
}

/// Insert (or refresh) the round-state row for this connection. Idempotent;
/// `INSERT OR REPLACE` on the connection_id PK so re-applying a Connection
/// event (or recovering from a crash partway through post_apply) can't
/// produce dangling state.
pub fn upsert(
    db: &Connection,
    connection_id: &BlakeId,
    local_endpoint_id: &EndpointId,
    remote_endpoint_id: &EndpointId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO connection_round_state
            (connection_id, local_endpoint_id, remote_endpoint_id,
             last_inbound_at_ms, last_outbound_at_ms, last_root_compare_at_ms)
         VALUES (?1, ?2, ?3, 0, 0, 0)
         ON CONFLICT(connection_id) DO UPDATE SET
            local_endpoint_id = excluded.local_endpoint_id,
            remote_endpoint_id = excluded.remote_endpoint_id",
        params![
            connection_id.to_vec(),
            local_endpoint_id.to_vec(),
            remote_endpoint_id.to_vec(),
        ],
    )?;
    let _ = now_ms;
    Ok(())
}

/// Bump last_inbound for this connection. Best-effort — silently
/// no-ops if no row exists yet (we may receive bytes during connection
/// bring-up before post_apply has written the round-state row). This
/// is called from the inbound observation path on EVERY received
/// frame, so it must be cheap.
pub fn mark_inbound(db: &Connection, connection_id: &BlakeId, now_ms: i64) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE connection_round_state
            SET last_inbound_at_ms = MAX(last_inbound_at_ms, ?2)
          WHERE connection_id = ?1",
        params![connection_id.to_vec(), now_ms],
    )?;
    Ok(())
}

/// Bump last_outbound for this connection. Called from the sender
/// actor when it ships a batch.
pub fn mark_outbound(
    db: &Connection,
    connection_id: &BlakeId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE connection_round_state
            SET last_outbound_at_ms = MAX(last_outbound_at_ms, ?2)
          WHERE connection_id = ?1",
        params![connection_id.to_vec(), now_ms],
    )?;
    Ok(())
}

/// Bump last_root_compare for this connection — called by the driver
/// after it writes a fresh root Compare event.
pub fn mark_root_compare_emitted(
    db: &Connection,
    connection_id: &BlakeId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE connection_round_state
            SET last_root_compare_at_ms = MAX(last_root_compare_at_ms, ?2)
          WHERE connection_id = ?1",
        params![connection_id.to_vec(), now_ms],
    )?;
    Ok(())
}

/// Return the connection ids where THIS daemon is the driver and a
/// fresh root Compare is due right now: (a) we haven't received any
/// data on this connection in the last QUIET_THRESHOLD_MS — incoming
/// frames signal "round still in progress, don't disturb" — and (b)
/// the last root Compare we emitted was ≥ MIN_ROUND_GAP_MS ago.
///
/// Outbound activity does NOT factor into the quiet test: the local
/// authoring loop is heavy on outbound but represents new content the
/// peer needs to learn about, so suppressing rounds on local sends
/// would starve convergence during burst-authoring.
///
/// Filters by lexicographic order of the endpoint ids — the row's
/// `local_endpoint_id < remote_endpoint_id` test resolves to the same
/// boolean on both sides because both rows describe the same canonical
/// connection from each side's vantage.
pub fn drivers_due_for_root_compare(
    db: &Connection,
    now_ms: i64,
) -> rusqlite::Result<Vec<BlakeId>> {
    let mut stmt = db.prepare(
        "SELECT connection_id FROM connection_round_state
          WHERE local_endpoint_id < remote_endpoint_id
            AND (?1 - last_inbound_at_ms)      >= ?2
            AND (?1 - last_root_compare_at_ms) >= ?3
          ORDER BY connection_id ASC",
    )?;
    let rows = stmt.query_map(
        params![now_ms, QUIET_THRESHOLD_MS, MIN_ROUND_GAP_MS],
        |r| r.get::<_, Vec<u8>>(0),
    )?;
    let mut out: Vec<BlakeId> = Vec::new();
    for row in rows {
        let blob = row?;
        if blob.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            out.push(id);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c
    }

    #[test]
    fn driver_is_lex_smaller_endpoint() {
        let lo = [0u8; 32];
        let hi = [1u8; 32];
        assert!(is_driver(&lo, &hi));
        assert!(!is_driver(&hi, &lo));
        assert!(!is_driver(&lo, &lo));
    }

    #[test]
    fn upsert_then_query_driver_due() {
        let db = open();
        let cid = [9u8; 32];
        let local = [0u8; 32];
        let remote = [1u8; 32];
        upsert(&db, &cid, &local, &remote, 0).unwrap();
        let due = drivers_due_for_root_compare(&db, MIN_ROUND_GAP_MS + 1).unwrap();
        assert_eq!(due, vec![cid], "driver with zero timestamps must be due");
    }

    #[test]
    fn non_driver_never_due() {
        let db = open();
        let cid = [9u8; 32];
        let local = [1u8; 32];
        let remote = [0u8; 32];
        upsert(&db, &cid, &local, &remote, 0).unwrap();
        let due = drivers_due_for_root_compare(&db, MIN_ROUND_GAP_MS + 1).unwrap();
        assert!(due.is_empty(), "non-driver must never appear in due list");
    }

    #[test]
    fn recent_inbound_suppresses_round() {
        let db = open();
        let cid = [9u8; 32];
        let local = [0u8; 32];
        let remote = [1u8; 32];
        upsert(&db, &cid, &local, &remote, 0).unwrap();
        let now = MIN_ROUND_GAP_MS + 1_000;
        mark_inbound(&db, &cid, now - 50).unwrap();
        let due = drivers_due_for_root_compare(&db, now).unwrap();
        assert!(due.is_empty(), "round must wait for QUIET_THRESHOLD after inbound");
        let due_later = drivers_due_for_root_compare(&db, now + QUIET_THRESHOLD_MS).unwrap();
        assert_eq!(due_later, vec![cid], "round fires once quiet window elapses");
    }

    #[test]
    fn recent_root_compare_suppresses_next() {
        let db = open();
        let cid = [9u8; 32];
        let local = [0u8; 32];
        let remote = [1u8; 32];
        upsert(&db, &cid, &local, &remote, 0).unwrap();
        let now = 10_000;
        mark_root_compare_emitted(&db, &cid, now).unwrap();
        let due = drivers_due_for_root_compare(&db, now + 50).unwrap();
        assert!(due.is_empty(), "back-to-back root Compares are throttled");
        let due_later =
            drivers_due_for_root_compare(&db, now + MIN_ROUND_GAP_MS + 1).unwrap();
        assert_eq!(
            due_later,
            vec![cid],
            "root Compare fires once MIN_ROUND_GAP elapses"
        );
    }

    #[test]
    fn upsert_is_idempotent() {
        let db = open();
        let cid = [9u8; 32];
        let local = [0u8; 32];
        let remote = [1u8; 32];
        upsert(&db, &cid, &local, &remote, 0).unwrap();
        // Bump some timestamps then re-upsert; the timestamps must
        // survive (we only refresh the role columns).
        mark_inbound(&db, &cid, 555).unwrap();
        upsert(&db, &cid, &local, &remote, 0).unwrap();
        let last_inbound: i64 = db
            .query_row(
                "SELECT last_inbound_at_ms FROM connection_round_state WHERE connection_id = ?1",
                params![cid.to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_inbound, 555, "upsert must not clobber traffic timestamps");
    }
}
