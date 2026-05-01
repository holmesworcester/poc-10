//! Boundary tables introduced by the control-loop substrate, refactored to
//! match the post-update `plan.md` (lines 129-180).
//!
//! Tests and the daemon's runtime path call `ensure_schema` here
//! directly to provision the substrate boundary tables.
//!
//! Boundary tables, per the plan:
//!
//! - `inbound_bytes` (was `incoming_wire_events`) — transport ingress dedup
//!   by `wire_id`.
//! - `inbound_observations` (was `incoming_wire_observations`) — provenance
//!   for diagnostics / dialing.
//! - `events` — canonical event store, scope ∈ {durable, local,
//!   endpoint_local}, status ∈ {processing, ready, blocked, applied,
//!   rejected}. `events.status = ready` is the unblocked-events queue.
//! - `blocked_by_event` — pair rows `(blocked_by_event_id, event_id)`
//!   recording dependency wait edges.
//! - `outbox` — `(connection_id, event_id)` pair, memory by default, dedupe
//!   by unique pair. Carries no payload.
//! - `labels` — generic `(event_id, label_type, workspace_id)` gating
//!   signal.
//! - `job_schedules` — `(job_name, every_ms, next_fire_at_ms)` time entry
//!   point. (placeholder for the JobTick scheduler)
//!
//! Storage classes (per `plan.md` line 29 — "durable | memory | temp"):
//!
//! | table                | class      |
//! | -------------------- | ---------- |
//! | `inbound_bytes`      | memory     |
//! | `inbound_observations` | memory   |
//! | `events`             | per-row    |
//! | `blocked_by_event`   | per-row    |
//! | `outbox`             | memory     |
//! | `labels`             | durable    |
//! | `job_schedules`      | durable    |
//!
//! `events.scope` carries the per-row distinction between durable, local,
//! and endpoint-local rows (see `plan.md` lines 139-149 and 374-385).
//!
//! Migration notes (refactor):
//! - `incoming_wire_events` → `inbound_bytes` (rename)
//! - `incoming_wire_observations` → `inbound_observations` (rename)
//! - `outgoing_intents` → DROPPED, replaced by `outbox`. The Phase 10 sender
//!   job is being migrated; see `state/outgoing_intents.rs` for the
//!   compatibility shim that backs the legacy API onto `outbox`.

use rusqlite::{Connection, Result as SqliteResult};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS labels (
            event_id    BLOB NOT NULL,
            label_type  TEXT NOT NULL,
            workspace_id BLOB NOT NULL,
            PRIMARY KEY (event_id, label_type)
        );
        CREATE INDEX IF NOT EXISTS idx_labels_type_ws ON labels (label_type, workspace_id);

        -- Transport ingress dedupe (was: incoming_wire_events).
        CREATE TABLE IF NOT EXISTS inbound_bytes (
            wire_id        BLOB PRIMARY KEY,
            bytes          BLOB NOT NULL,
            status         TEXT NOT NULL DEFAULT 'pending',
            enqueued_at_ms INTEGER NOT NULL
        );

        -- Provenance / diagnostics (was: incoming_wire_observations).
        CREATE TABLE IF NOT EXISTS inbound_observations (
            wire_id            BLOB NOT NULL,
            connection_id      BLOB,
            remote_endpoint_id BLOB,
            ip                 TEXT,
            port               INTEGER,
            first_seen_at_ms   INTEGER NOT NULL,
            last_seen_at_ms    INTEGER NOT NULL,
            seen_count         INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (wire_id, connection_id, remote_endpoint_id)
        );
        -- Single-round-trip UPSERT target. SQLite treats NULL as distinct
        -- in PRIMARY KEY uniqueness, so an ON CONFLICT clause referring
        -- to the table-level PK silently fails to match when
        -- connection_id or remote_endpoint_id is NULL — the case
        -- record_observation() actually hits in production. Backing the
        -- UPSERT with this expression-based unique index lets the same
        -- INSERT...ON CONFLICT statement collapse first-observation
        -- and Nth-observation into one round-trip without changing
        -- table layout.
        CREATE UNIQUE INDEX IF NOT EXISTS uq_inbound_observations_provenance
            ON inbound_observations (
                wire_id,
                COALESCE(connection_id, x''),
                COALESCE(remote_endpoint_id, x'')
            );

        -- Canonical event store (plan.md lines 139-149).
        --
        -- `workspace_id` is NULLable because admission (`admit_event_id`)
        -- runs BEFORE parse, and the chain only knows the event's
        -- workspace once parse + finalize succeed. Stage 1 of the
        -- `recorded_by` retirement (plan.md): once the row is finalized
        -- with a non-NULL workspace_id, it must NEVER be overwritten with
        -- NULL or a different workspace_id.
        CREATE TABLE IF NOT EXISTS events_canonical (
            event_id              BLOB PRIMARY KEY,
            canonical_event_bytes BLOB NOT NULL,
            workspace_id          BLOB,             -- NULL while in 'processing'
            scope                 TEXT NOT NULL,    -- durable | local | endpoint_local
            status                TEXT NOT NULL,    -- processing | ready | blocked | applied | rejected
            created_at_ms         INTEGER NOT NULL,
            expires_at_ms         INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_events_canonical_status
            ON events_canonical (status, created_at_ms);
        -- Fast `(workspace_id, event_id)` lookup. Per plan.md line 62:
        -- NewRows are indexed by (event_id, workspace_id).
        CREATE INDEX IF NOT EXISTS idx_events_canonical_workspace
            ON events_canonical (workspace_id, event_id);
        -- Index for the ready-event worker query and per-workspace status
        -- scans.
        CREATE INDEX IF NOT EXISTS idx_events_canonical_workspace_status
            ON events_canonical (workspace_id, status);

        -- Dependency wait edges (plan.md lines 151-159).
        CREATE TABLE IF NOT EXISTS blocked_by_event (
            blocked_by_event_id BLOB NOT NULL,  -- missing dep
            event_id            BLOB NOT NULL,  -- blocked event
            PRIMARY KEY (blocked_by_event_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_blocked_by_event_reverse
            ON blocked_by_event (event_id, blocked_by_event_id);

        -- Outbox (plan.md lines 168-176): connection_id + event_id +
        -- queued_at_ms only. No status, lease, attempts, or error columns.
        -- The table is memory by default and has no per-row claim, lease,
        -- or retry status — refilling, batching, and retry are owned by the
        -- per-connection `ConnectionSender` (plan.md lines 178-185).
        CREATE TABLE IF NOT EXISTS outbox (
            connection_id   BLOB NOT NULL,
            event_id        BLOB NOT NULL,
            queued_at_ms    INTEGER NOT NULL,
            PRIMARY KEY (connection_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_outbox_pending
            ON outbox (connection_id, queued_at_ms);

        -- Job schedules: time enters the system here (plan.md line 136).
        CREATE TABLE IF NOT EXISTS job_schedules (
            job_name        TEXT PRIMARY KEY,
            every_ms        INTEGER NOT NULL,
            next_fire_at_ms INTEGER NOT NULL,
            last_fired_at_ms INTEGER
        );

        -- Local event intents: locally-created events the dispatcher
        -- should turn into canonical events. Boundary table for the
        -- single-writer ingress of CLI/RPC-originated commands. The
        -- dispatcher's `LocalEvents` queue kind drains pending rows
        -- and dispatches them to a registered handler that writes the
        -- canonical event + outbox.
        --
        -- During the daemon cutover phase the RPC handlers still write
        -- to the DB directly (legacy create_*_for_db paths). This
        -- table is the destination shape; the migration of each RPC
        -- handler is staged in subsequent phases.
        CREATE TABLE IF NOT EXISTS local_event_intents (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            command_kind   TEXT NOT NULL,
            payload        BLOB NOT NULL,
            enqueued_at_ms INTEGER NOT NULL,
            status         TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE INDEX IF NOT EXISTS idx_local_event_intents_pending
            ON local_event_intents (status, enqueued_at_ms)
            WHERE status = 'pending';
        ",
    )?;

    // Forward-compatible schema migration: older databases were created
    // before `events_canonical.workspace_id` existed. Detect the column
    // and add it if missing. Defensive: ignore errors that indicate the
    // column was already added by a concurrent migration.
    let has_workspace_id: bool = {
        let mut stmt = conn.prepare("PRAGMA table_info(events_canonical)")?;
        let mut found = false;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(1)?;
            if name == "workspace_id" {
                found = true;
                break;
            }
        }
        found
    };
    if !has_workspace_id {
        conn.execute(
            "ALTER TABLE events_canonical ADD COLUMN workspace_id BLOB",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_canonical_workspace
                ON events_canonical (workspace_id, event_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_canonical_workspace_status
                ON events_canonical (workspace_id, status)",
            [],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_creates_all_tables() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name IN
                 ('labels','inbound_bytes','inbound_observations',
                  'events_canonical','blocked_by_event','outbox','job_schedules')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 7);
    }

    #[test]
    fn outbox_pair_uniqueness() {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c.execute(
            "INSERT INTO outbox (connection_id, event_id, queued_at_ms)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![vec![1u8; 32], vec![2u8; 32], 0_i64],
        )
        .unwrap();
        let res = c.execute(
            "INSERT INTO outbox (connection_id, event_id, queued_at_ms)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![vec![1u8; 32], vec![2u8; 32], 1_i64],
        );
        assert!(res.is_err(), "duplicate (connection_id,event_id) must be rejected");
    }

    #[test]
    fn outbox_has_only_three_columns() {
        // Slim schema invariant from plan.md lines 168-174: outbox carries
        // only (connection_id, event_id, queued_at_ms). If a future
        // refactor adds status/lease/attempts back, this test fails fast.
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        let cols: Vec<String> = {
            let mut stmt = c.prepare("PRAGMA table_info(outbox)").unwrap();
            let it = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap();
            it.collect::<Result<Vec<_>, _>>().unwrap()
        };
        cols.iter().for_each(|c| {
            assert!(
                matches!(c.as_str(), "connection_id" | "event_id" | "queued_at_ms"),
                "unexpected outbox column: {}",
                c
            );
        });
        assert_eq!(cols.len(), 3, "outbox must be exactly 3 columns, got {:?}", cols);
    }

    #[test]
    fn blocked_by_event_pair_uniqueness() {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c.execute(
            "INSERT INTO blocked_by_event (blocked_by_event_id, event_id)
             VALUES (?1, ?2)",
            rusqlite::params![vec![1u8; 32], vec![2u8; 32]],
        )
        .unwrap();
        let res = c.execute(
            "INSERT INTO blocked_by_event (blocked_by_event_id, event_id)
             VALUES (?1, ?2)",
            rusqlite::params![vec![1u8; 32], vec![2u8; 32]],
        );
        assert!(res.is_err());
    }
}
