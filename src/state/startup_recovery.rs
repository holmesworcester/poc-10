//! # Startup recovery (transient-status reset)
//!
//! ## Purpose
//! Reset transient row statuses left by a crashed run so the next claim
//! re-runs them from a known state (`plan.md` line 189). Idempotent: a
//! second call on a clean DB is a no-op.
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the `processing -> ready` flip on `events_canonical`,
//! - the `processing -> pending` flip on `inbound_bytes`,
//! - the [`RecoveryReport`] returned for logs and tests.
//!
//! Does NOT own:
//! - terminal-status preservation (callers don't need to opt in: the
//!   queries name `processing` exclusively),
//! - the `outbox` table — it is in-memory by design and starts empty;
//!   sync/projectors recreate any missing send work.
//! - schema creation; this is called AFTER `ensure_schema`.
//!
//! ## Interfaces
//! - [`recover_on_startup`] — single entry point, run once at boot.
//! - [`RecoveryReport`] — structured count of rows touched.
//!
//! ## State
//! Mutates `events_canonical.status` and `inbound_bytes.status` only.
//!
//! ## Invariants
//! - `events_canonical.status = 'processing' -> 'ready'`
//! - `inbound_bytes.status = 'processing' -> 'pending'`
//! - Terminal statuses (`applied`, `rejected`, `blocked`, `ready`,
//!   `pending`, `processed`, `unwrapped_no_inner`, `invalid`) are never
//!   touched.
//! - Idempotent: second call on a clean DB returns
//!   `RecoveryReport::default()`.
//!
//! ## Flow
//! ```text
//!   Daemon boot:
//!     ensure_schema()
//!     recover_on_startup()        <-- this module
//!     register_default_handlers()
//!     start dispatcher / workers
//! ```
//!
//! ## Failure / restart behavior
//! - The reset itself is a single SQL UPDATE per table, so either both
//!   succeed or the caller sees an error and aborts boot.
//! - If recovery is skipped (boot bug), claims will still succeed for
//!   non-`processing` rows, but `processing` rows are stuck — nothing
//!   else will flip them.
//!
//! ## Performance notes
//! Two `UPDATE ... WHERE status = 'processing'` calls. Cheap on small
//! recovery sets; in the worst case bounded by the number of rows the
//! crashed dispatcher had open (≤ in-flight worker count).
//!
//! ## Testing hooks
//! - In-file `tests` cover both flips, terminal-status preservation, and
//!   idempotency on a clean DB.

use rusqlite::{Connection, Result as SqliteResult};

/// Summary of a recovery pass — useful for logs and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Number of `events_canonical` rows transitioned `processing -> ready`.
    pub events_reset_to_ready: usize,
    /// Number of `inbound_bytes` rows transitioned `processing -> pending`.
    pub inbound_bytes_reset_to_pending: usize,
}

/// Reset transient statuses left over from a crashed run. Idempotent: a
/// second call on a clean DB is a no-op.
pub fn recover_on_startup(conn: &Connection) -> SqliteResult<RecoveryReport> {
    let events_reset = conn.execute(
        "UPDATE events_canonical
            SET status = 'ready'
          WHERE status = 'processing'",
        [],
    )?;
    let inbound_reset = conn.execute(
        "UPDATE inbound_bytes
            SET status = 'pending'
          WHERE status = 'processing'",
        [],
    )?;
    Ok(RecoveryReport {
        events_reset_to_ready: events_reset,
        inbound_bytes_reset_to_pending: inbound_reset,
    })
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
    fn recovers_processing_events_to_ready() {
        let c = open();
        c.execute(
            "INSERT INTO events_canonical
                (event_id, canonical_event_bytes, scope, status, created_at_ms)
             VALUES (?1, ?2, 'durable', 'processing', 0)",
            rusqlite::params![vec![1u8; 32], Vec::<u8>::new()],
        )
        .unwrap();
        let report = recover_on_startup(&c).unwrap();
        assert_eq!(report.events_reset_to_ready, 1);
        assert_eq!(report.inbound_bytes_reset_to_pending, 0);
        let status: String = c
            .query_row(
                "SELECT status FROM events_canonical WHERE event_id = ?1",
                rusqlite::params![vec![1u8; 32]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "ready");
    }

    #[test]
    fn recovers_processing_inbound_bytes_to_pending() {
        let c = open();
        c.execute(
            "INSERT INTO inbound_bytes
                (wire_id, bytes, status, enqueued_at_ms)
             VALUES (?1, ?2, 'processing', 0)",
            rusqlite::params![vec![9u8; 32], vec![1u8, 2, 3]],
        )
        .unwrap();
        let report = recover_on_startup(&c).unwrap();
        assert_eq!(report.inbound_bytes_reset_to_pending, 1);
        let status: String = c
            .query_row(
                "SELECT status FROM inbound_bytes WHERE wire_id = ?1",
                rusqlite::params![vec![9u8; 32]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending");
    }

    #[test]
    fn does_not_touch_terminal_statuses() {
        // Pre-populate rows in every non-processing status; assert nothing
        // moves except the processing rows.
        let c = open();
        for (i, st) in ["ready", "blocked", "applied", "rejected"].iter().enumerate() {
            c.execute(
                "INSERT INTO events_canonical
                    (event_id, canonical_event_bytes, scope, status, created_at_ms)
                 VALUES (?1, ?2, 'durable', ?3, 0)",
                rusqlite::params![vec![i as u8 + 10; 32], Vec::<u8>::new(), *st],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO events_canonical
                (event_id, canonical_event_bytes, scope, status, created_at_ms)
             VALUES (?1, ?2, 'durable', 'processing', 0)",
            rusqlite::params![vec![100u8; 32], Vec::<u8>::new()],
        )
        .unwrap();
        let report = recover_on_startup(&c).unwrap();
        assert_eq!(report.events_reset_to_ready, 1, "only the processing row moved");
        for (i, expected) in ["ready", "blocked", "applied", "rejected"]
            .iter()
            .enumerate()
        {
            let status: String = c
                .query_row(
                    "SELECT status FROM events_canonical WHERE event_id = ?1",
                    rusqlite::params![vec![i as u8 + 10; 32]],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(&status, expected, "row {} must be untouched", i);
        }
    }

    #[test]
    fn idempotent_on_clean_db() {
        let c = open();
        let r1 = recover_on_startup(&c).unwrap();
        assert_eq!(r1, RecoveryReport::default());
        let r2 = recover_on_startup(&c).unwrap();
        assert_eq!(r2, RecoveryReport::default());
    }
}
