//! # Canonical events table
//!
//! ## Purpose
//! Single-row-per-event storage of canonical event bytes + admission
//! lifecycle. This is the boundary table between "bytes received off the
//! wire" and "state apply" — every event the daemon has seen, blocked, or
//! applied has exactly one row here (`plan.md` lines 139-149).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the row schema (`event_id`, `canonical_event_bytes`, `scope`,
//!   `status`, `created_at_ms`, `expires_at_ms`),
//! - the [`EventScope`] / [`EventStatus`] enums + their stable string
//!   serialization,
//! - the admission helper [`admit_event_id`],
//! - the `blocked_by_event` edge table semantics:
//!   [`add_blockers`] / [`unblock_dependents`].
//!
//! Does NOT own:
//! - parsing or projection of the canonical bytes — that's `event_modules`,
//! - the `outbox` send queue — see [`crate::state::outbox`],
//! - any wire/frame layout — that's `event_modules::connection::wrap`.
//!
//! ## Interfaces
//! - [`admit_event_id`] — claim or recognise an event id (Phase-1 chain
//!   step 3a-b).
//! - [`finalize_admitted`] — write the canonical bytes after parse, set
//!   `scope` and `status`.
//! - [`upsert_event`] — one-shot insert for fully-known rows (synthesized
//!   endpoint-local events; tests).
//! - [`set_status`] — terminal/lifecycle transitions.
//! - [`get`] — load one row.
//! - [`add_blockers`] — write `blocked_by_event` edges and flip status to
//!   `blocked`.
//! - [`unblock_dependents`] — same-tx unblocking when a dep is applied.
//!
//! ## State
//! ```text
//! events_canonical:
//!   event_id              BLOB PRIMARY KEY    -- BLAKE3 of canonical bytes
//!   canonical_event_bytes BLOB                -- empty during 'processing'
//!   workspace_id          BLOB NULL           -- set after parse; NULL during 'processing'
//!   scope                 TEXT                -- durable | local | endpoint_local
//!   status                TEXT                -- processing | ready | blocked | applied | rejected
//!   created_at_ms         INTEGER
//!   expires_at_ms         INTEGER NULL
//!
//! blocked_by_event:
//!   blocked_by_event_id   BLOB    -- the missing dep
//!   event_id              BLOB    -- the waiting event
//!   PRIMARY KEY (blocked_by_event_id, event_id)
//! ```
//!
//! `workspace_id` is NULL while a row is in `processing` because admission
//! (`admit_event_id`) runs BEFORE parse and the workspace is only known
//! after parsing the canonical bytes. `finalize_admitted` populates it on
//! the first transition out of `processing`. After finalize, the column
//! is never overwritten with NULL or a different workspace_id (plan.md
//! line 62: NewRows are indexed by `(event_id, workspace_id)`; both
//! components must be stable post-finalize).
//!
//! The physical table is named `events_canonical` so it doesn't collide
//! with the legacy `events` table in `state/db/store.rs`. TODO(plan.md):
//! rename to `events` at cutover.
//!
//! ## Invariants
//! - `event_id = BLAKE3(canonical_event_bytes)` once `finalize_admitted`
//!   has run. While the row is in `processing` status, the bytes are
//!   empty and the id is the chain's claim.
//! - Lifecycle transitions:
//!   `processing -> ready | blocked | applied | rejected`,
//!   `blocked    -> ready`,
//!   `ready      -> applied | blocked | rejected`. `applied` and
//!   `rejected` are terminal.
//! - `blocked_by_event` is a many-to-many: one event can have multiple
//!   blockers, one dep can have multiple dependents. A row is `ready` iff
//!   it is `blocked` AND no `blocked_by_event(event_id = self)` row
//!   exists.
//! - `unblock_dependents` flips `blocked -> ready` only; it does NOT
//!   recurse-project. The `events.status = 'ready'` set IS the queue
//!   (see `WorkItem::ReadyEvent`).
//! - Stable string serialization for `scope` / `status`: do not rename
//!   without a migration.
//!
//! ## Flow
//! ```text
//!   admit_event_id        :: missing -> processing (NewlyClaimed)
//!   admit_event_id        :: existing -> Known { status }
//!   finalize_admitted     :: processing -> {processing|blocked|applied|rejected}
//!                            (also writes canonical_event_bytes + scope)
//!   add_blockers          :: ? -> blocked, plus blocked_by_event rows
//!   unblock_dependents(D) :: drop blocked_by_event(D, *) rows;
//!                            for each previously-waiting event,
//!                            blocked -> ready iff no remaining blocker.
//! ```
//!
//! ## Failure / restart behavior
//! - On crash, `processing` rows are flipped back to `ready` by
//!   [`crate::state::startup_recovery::recover_on_startup`].
//! - Terminal statuses (`applied`, `rejected`) are never moved by recovery.
//! - DB errors propagate to the caller; the inbound chain rolls back its
//!   transaction.
//!
//! ## Performance notes
//! - All lookups by `event_id` are PRIMARY KEY hits.
//! - `unblock_dependents` runs at most O(blockers + dependents) per applied
//!   event; a prepared statement is reused for the per-candidate
//!   `still-blocked?` check.
//! - Storage class is per-row via `scope`. Phase 1 keeps a single physical
//!   table; non-`durable` events may move to a memory-backed table later.
//!
//! ## Testing hooks
//! - In-file `tests` covers admit→known repeat, known-as-applied, and the
//!   `unblock_dependents` last-blocker flip.

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::runtime::control_loop::work_item::{BlakeId, WorkspaceId};

/// Storage class / sharing scope of an event row, per `plan.md` line 29 +
/// lines 139-149. Stable strings: do not rename without a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventScope {
    /// Replicated to every endpoint that shares the workspace. The vast
    /// majority of `event_modules` rows.
    Durable,
    /// Local to this daemon, never sent on the wire. e.g. ephemeral
    /// projector hints.
    Local,
    /// Lives only as long as a connection is meaningful. Sync messages
    /// (Have/Need/Compare/Send) are endpoint-local — they have ids and
    /// dedupe but are not durable shared events. Per `plan.md` lines
    /// 374-385.
    EndpointLocal,
}

impl EventScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventScope::Durable => "durable",
            EventScope::Local => "local",
            EventScope::EndpointLocal => "endpoint_local",
        }
    }

    pub fn parse(s: &str) -> Option<EventScope> {
        Some(match s {
            "durable" => EventScope::Durable,
            "local" => EventScope::Local,
            "endpoint_local" => EventScope::EndpointLocal,
            _ => return None,
        })
    }
}

/// Lifecycle status of a row in the canonical events table, per `plan.md`
/// line 147.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatus {
    /// Newly admitted; chained inbound processing has not finished. Used
    /// by `admit_event_id` to mark an in-flight claim before parse.
    Processing,
    /// Cleared to project: all blockers are gone. The unblocked-events
    /// queue (`plan.md` line 163).
    Ready,
    /// Waiting on at least one `blocked_by_event(blocked_by_event_id =
    /// missing_dep, event_id = self)` row.
    Blocked,
    /// Successfully applied to State.
    Applied,
    /// Permanently invalid (failed signature, malformed wire bytes, etc.).
    Rejected,
}

impl EventStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventStatus::Processing => "processing",
            EventStatus::Ready => "ready",
            EventStatus::Blocked => "blocked",
            EventStatus::Applied => "applied",
            EventStatus::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<EventStatus> {
        Some(match s {
            "processing" => EventStatus::Processing,
            "ready" => EventStatus::Ready,
            "blocked" => EventStatus::Blocked,
            "applied" => EventStatus::Applied,
            "rejected" => EventStatus::Rejected,
            _ => return None,
        })
    }
}

/// One row of `events_canonical`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub event_id: BlakeId,
    pub canonical_event_bytes: Vec<u8>,
    /// `None` while the row is in `processing` status (admission claim
    /// before parse). Populated on the first transition out of
    /// `processing` via `finalize_admitted`.
    pub workspace_id: Option<WorkspaceId>,
    pub scope: EventScope,
    pub status: EventStatus,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// Result of `admit_event_id`. Per `plan.md` line 43 + the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionResult {
    /// `event_id` was already known. Status carries the existing row's
    /// state so the caller can record observations / call
    /// `suppress_received` and stop before context loading.
    Known { status: EventStatus },
    /// First time we've seen this id. Inserted a `processing` row; the
    /// caller proceeds with parse → context → project → apply.
    NewlyClaimed,
}

/// Admission by event id, per `plan.md` line 43.
///
/// Performed BEFORE parse + context. Known event ids stop here:
/// - `applied` / `blocked` / `rejected` / `processing` (in-flight) all
///   return `Known { status }`.
/// - Caller's responsibility: on `Known`, record observations on
///   `inbound_observations` and call `suppress_received(id)` (sync
///   suppression is wired in the connection module).
///
/// On `NewlyClaimed`, an `events_canonical` row is inserted with
/// `status = processing`, `scope = durable` (default), empty `canonical_event_bytes`,
/// and the current `created_at_ms`. The caller is expected to UPDATE the
/// row with the wire bytes and final scope after parse succeeds, then
/// transition status → ready / blocked / applied / rejected as
/// appropriate.
pub fn admit_event_id(
    conn: &Connection,
    event_id: BlakeId,
    now_ms: i64,
) -> SqliteResult<AdmissionResult> {
    // Check existing row.
    let existing: Option<String> = conn
        .query_row(
            "SELECT status FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(status_str) = existing {
        let status = EventStatus::parse(&status_str).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("unknown event status: {}", status_str).into(),
            )
        })?;
        return Ok(AdmissionResult::Known { status });
    }
    // Insert in-flight claim.
    conn.execute(
        "INSERT INTO events_canonical
            (event_id, canonical_event_bytes, scope, status, created_at_ms, expires_at_ms)
         VALUES (?1, ?2, 'durable', 'processing', ?3, NULL)",
        params![event_id.to_vec(), Vec::<u8>::new(), now_ms],
    )?;
    Ok(AdmissionResult::NewlyClaimed)
}

/// Update a previously admitted row with its parsed wire bytes / scope,
/// `workspace_id`, and transition the status. Used by the inbound chain
/// after `admit_event_id` returned `NewlyClaimed` and parse succeeded.
///
/// `workspace_id` is the parsed event's workspace. It is populated on the
/// first transition out of `processing` and never overwritten afterwards
/// (plan.md line 62). Pass `None` only if the workspace truly cannot be
/// determined yet (the chain itself always has it post-parse).
pub fn finalize_admitted(
    conn: &Connection,
    event_id: &BlakeId,
    canonical_event_bytes: &[u8],
    workspace_id: Option<WorkspaceId>,
    scope: EventScope,
    status: EventStatus,
) -> SqliteResult<()> {
    // COALESCE preserves any workspace_id that was set on a prior
    // transition (defensive — finalize_admitted should only run once per
    // row, but the chain may re-enter under encrypted-recurse paths).
    let ws_blob = workspace_id.map(|w| w.to_vec());
    conn.execute(
        "UPDATE events_canonical
            SET canonical_event_bytes = ?1,
                workspace_id = COALESCE(workspace_id, ?2),
                scope        = ?3,
                status       = ?4
          WHERE event_id    = ?5",
        params![
            canonical_event_bytes,
            ws_blob,
            scope.as_str(),
            status.as_str(),
            event_id.to_vec()
        ],
    )?;
    Ok(())
}

/// Set the `workspace_id` for an already-admitted row. Idempotent: a
/// re-write with the same workspace_id is a no-op; the column is only
/// populated if it is currently NULL. Returns the number of rows
/// actually updated.
pub fn set_workspace_id(
    conn: &Connection,
    event_id: &BlakeId,
    workspace_id: &WorkspaceId,
) -> SqliteResult<usize> {
    conn.execute(
        "UPDATE events_canonical
            SET workspace_id = ?1
          WHERE event_id = ?2 AND workspace_id IS NULL",
        params![workspace_id.to_vec(), event_id.to_vec()],
    )
}

/// Read just the `workspace_id` column for an event id. Returns
/// `Ok(None)` if the row is unknown OR if the row exists but has not yet
/// been finalized (workspace_id IS NULL). The two cases are
/// indistinguishable from this helper's signature; callers that need the
/// distinction should use [`get`].
pub fn get_workspace_id(
    conn: &Connection,
    event_id: &BlakeId,
) -> SqliteResult<Option<WorkspaceId>> {
    let row: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT workspace_id FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(row.flatten().and_then(|bytes| {
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            Some(id)
        } else {
            None
        }
    }))
}

/// Insert a fully-known event row in one shot. Useful for endpoint-local
/// events that a projector creates directly (Have/Need/Compare/Send), and
/// for tests. Idempotent on `event_id`.
pub fn upsert_event(conn: &Connection, row: &EventRow) -> SqliteResult<bool> {
    let ws_blob = row.workspace_id.map(|w| w.to_vec());
    let n = conn.execute(
        "INSERT OR IGNORE INTO events_canonical
            (event_id, canonical_event_bytes, workspace_id, scope, status,
             created_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.event_id.to_vec(),
            row.canonical_event_bytes,
            ws_blob,
            row.scope.as_str(),
            row.status.as_str(),
            row.created_at_ms,
            row.expires_at_ms,
        ],
    )?;
    Ok(n > 0)
}

/// Maximum rows the multi-row insert helper accepts in one call. SQLite's
/// default `SQLITE_MAX_COMPOUND_SELECT` cap is 500 rows per VALUES list;
/// we keep some headroom (rows × 7 placeholders must fit under
/// SQLITE_MAX_VARIABLE_NUMBER, ~32k since SQLite 3.32). Callers (the
/// inbound chain) MUST chunk inputs to at most this many rows per call.
pub const MULTI_INSERT_MAX_ROWS: usize = 500;

/// Multi-row equivalent of [`upsert_event`]. Inserts a batch of fully-known
/// event rows in one statement using `INSERT OR IGNORE INTO ... VALUES
/// (..), (..), ...`. Returns the number of rows actually inserted (rows
/// that conflicted on `event_id` are silently ignored, matching the
/// single-row helper's contract).
///
/// Used by the inbound chain to admit + finalize a whole batch of inner
/// events from one InboundBytes frame in a single round-trip, replacing
/// the per-event `admit_event_id` insert + `finalize_admitted` update
/// pair (two statements per inner event → one statement per batch).
///
/// See [`MULTI_INSERT_MAX_ROWS`] for the per-call ceiling. Callers
/// processing a larger batch should chunk in advance — this helper does
/// not chunk internally because the chain's typical batches are well
/// under the cap (`DEFAULT_FRAME_BATCH = 32` events per inbound frame).
pub fn insert_event_rows_multi(
    conn: &Connection,
    rows: &[EventRow],
) -> SqliteResult<usize> {
    if rows.is_empty() {
        return Ok(0);
    }
    if rows.len() > MULTI_INSERT_MAX_ROWS {
        return Err(rusqlite::Error::ToSqlConversionFailure(
            format!(
                "insert_event_rows_multi: {} rows exceeds per-call cap of {}",
                rows.len(),
                MULTI_INSERT_MAX_ROWS
            )
            .into(),
        ));
    }
    // Build the VALUES clause: 7 placeholders per row.
    let mut sql = String::from(
        "INSERT OR IGNORE INTO events_canonical
            (event_id, canonical_event_bytes, workspace_id, scope, status,
             created_at_ms, expires_at_ms) VALUES ",
    );
    for i in 0..rows.len() {
        if i > 0 {
            sql.push(',');
        }
        let base = i * 7;
        sql.push_str(&format!(
            "(?{},?{},?{},?{},?{},?{},?{})",
            base + 1,
            base + 2,
            base + 3,
            base + 4,
            base + 5,
            base + 6,
            base + 7,
        ));
    }

    // Bind values in row order. Each row contributes 7 values matching the
    // column order above.
    let mut bound: Vec<Box<dyn rusqlite::types::ToSql>> =
        Vec::with_capacity(rows.len() * 7);
    for row in rows {
        let ws_blob = row.workspace_id.map(|w| w.to_vec());
        bound.push(Box::new(row.event_id.to_vec()));
        bound.push(Box::new(row.canonical_event_bytes.clone()));
        bound.push(Box::new(ws_blob));
        bound.push(Box::new(row.scope.as_str().to_string()));
        bound.push(Box::new(row.status.as_str().to_string()));
        bound.push(Box::new(row.created_at_ms));
        bound.push(Box::new(row.expires_at_ms));
    }
    let refs: Vec<&dyn rusqlite::types::ToSql> = bound.iter().map(|b| &**b).collect();
    let n = conn.execute(&sql, refs.as_slice())?;
    Ok(n)
}

/// Update only the `status` column for an event id.
pub fn set_status(
    conn: &Connection,
    event_id: &BlakeId,
    status: EventStatus,
) -> SqliteResult<()> {
    conn.execute(
        "UPDATE events_canonical SET status = ?1 WHERE event_id = ?2",
        params![status.as_str(), event_id.to_vec()],
    )?;
    Ok(())
}

/// Load the row for `event_id`.
pub fn get(conn: &Connection, event_id: &BlakeId) -> SqliteResult<Option<EventRow>> {
    conn.query_row(
        "SELECT event_id, canonical_event_bytes, workspace_id, scope, status,
                created_at_ms, expires_at_ms
         FROM events_canonical WHERE event_id = ?1",
        params![event_id.to_vec()],
        |row| {
            let id_blob: Vec<u8> = row.get(0)?;
            let wire: Vec<u8> = row.get(1)?;
            let ws_blob: Option<Vec<u8>> = row.get(2)?;
            let scope_s: String = row.get(3)?;
            let status_s: String = row.get(4)?;
            let created: i64 = row.get(5)?;
            let expires: Option<i64> = row.get(6)?;
            let mut id = [0u8; 32];
            if id_blob.len() == 32 {
                id.copy_from_slice(&id_blob);
            }
            let workspace_id = ws_blob.and_then(|b| {
                if b.len() == 32 {
                    let mut w = [0u8; 32];
                    w.copy_from_slice(&b);
                    Some(w)
                } else {
                    None
                }
            });
            let scope = EventScope::parse(&scope_s).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    format!("unknown scope: {}", scope_s).into(),
                )
            })?;
            let status = EventStatus::parse(&status_s).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    format!("unknown status: {}", status_s).into(),
                )
            })?;
            Ok(EventRow {
                event_id: id,
                canonical_event_bytes: wire,
                workspace_id,
                scope,
                status,
                created_at_ms: created,
                expires_at_ms: expires,
            })
        },
    )
    .optional()
}

/// Add a `blocked_by_event` edge for each missing dep, leaving
/// `events_canonical.status = blocked`. Per `plan.md` lines 151-159, both
/// the missing-dep id and the blocked event id are stored as a pair row.
pub fn add_blockers(
    conn: &Connection,
    event_id: &BlakeId,
    missing_deps: &[BlakeId],
) -> SqliteResult<()> {
    if missing_deps.is_empty() {
        return Ok(());
    }
    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO blocked_by_event (blocked_by_event_id, event_id)
         VALUES (?1, ?2)",
    )?;
    for dep in missing_deps {
        stmt.execute(params![dep.to_vec(), event_id.to_vec()])?;
    }
    set_status(conn, event_id, EventStatus::Blocked)?;
    Ok(())
}

/// Same-transaction unblocking, per `plan.md` line 161.
///
/// When event `D` becomes applied:
/// 1. delete every `blocked_by_event(blocked_by_event_id = D, *)` row,
/// 2. for each event that was waiting on D, mark it `ready` if and only if
///    it has no remaining blockers (`NOT EXISTS` any other row).
///
/// Returns the list of event ids that transitioned to `ready`. Caller is
/// expected to enqueue a `ReadyEvent` work item per id (or trust the
/// control loop's claim-ready-rows pass to pick them up later).
///
/// Unblocking does NOT recursively project. `events.status = ready` is the
/// queue; the control loop later claims a bounded batch.
pub fn unblock_dependents(
    conn: &Connection,
    applied_event_id: &BlakeId,
) -> SqliteResult<Vec<BlakeId>> {
    // 1. Collect candidates whose blocker just disappeared.
    let mut stmt = conn.prepare(
        "SELECT event_id FROM blocked_by_event WHERE blocked_by_event_id = ?1",
    )?;
    let mut candidates: Vec<BlakeId> = Vec::new();
    let mut rows = stmt.query(params![applied_event_id.to_vec()])?;
    while let Some(row) = rows.next()? {
        let blob: Vec<u8> = row.get(0)?;
        if blob.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            candidates.push(id);
        }
    }
    drop(rows);
    drop(stmt);

    // 2. Delete the satisfied edges.
    conn.execute(
        "DELETE FROM blocked_by_event WHERE blocked_by_event_id = ?1",
        params![applied_event_id.to_vec()],
    )?;

    // 3. For each candidate: if no remaining blockers, mark ready.
    let mut newly_ready: Vec<BlakeId> = Vec::new();
    let mut check_stmt = conn.prepare(
        "SELECT EXISTS(SELECT 1 FROM blocked_by_event WHERE event_id = ?1)",
    )?;
    let mut update_stmt = conn.prepare(
        "UPDATE events_canonical SET status = 'ready'
         WHERE event_id = ?1 AND status = 'blocked'",
    )?;
    for cand in candidates {
        let still_blocked: bool =
            check_stmt.query_row(params![cand.to_vec()], |r| r.get(0))?;
        if !still_blocked {
            let n = update_stmt.execute(params![cand.to_vec()])?;
            if n > 0 {
                newly_ready.push(cand);
            }
        }
    }
    Ok(newly_ready)
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
    fn admit_newly_claims_then_known_on_repeat() {
        let c = open();
        let id: BlakeId = [7u8; 32];
        match admit_event_id(&c, id, 100).unwrap() {
            AdmissionResult::NewlyClaimed => {}
            _ => panic!("expected NewlyClaimed"),
        }
        match admit_event_id(&c, id, 200).unwrap() {
            AdmissionResult::Known {
                status: EventStatus::Processing,
            } => {}
            other => panic!("expected Known(Processing), got {:?}", other),
        }
    }

    #[test]
    fn admit_known_returns_status_for_applied() {
        let c = open();
        let id: BlakeId = [9u8; 32];
        let row = EventRow {
            event_id: id,
            canonical_event_bytes: b"abc".to_vec(),
            workspace_id: Some([0xAAu8; 32]),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        };
        upsert_event(&c, &row).unwrap();
        match admit_event_id(&c, id, 100).unwrap() {
            AdmissionResult::Known {
                status: EventStatus::Applied,
            } => {}
            other => panic!("expected Known(Applied), got {:?}", other),
        }
    }

    #[test]
    fn admit_then_set_workspace_after_parse() {
        let c = open();
        let id: BlakeId = [42u8; 32];
        // Step 1: admission claims a row with a NULL workspace_id.
        match admit_event_id(&c, id, 100).unwrap() {
            AdmissionResult::NewlyClaimed => {}
            other => panic!("expected NewlyClaimed, got {:?}", other),
        }
        let row = get(&c, &id).unwrap().unwrap();
        assert_eq!(row.workspace_id, None, "admit must leave workspace_id NULL");
        assert_eq!(row.status, EventStatus::Processing);

        // Step 2: finalize_admitted sets workspace_id from parsed event.
        let ws: WorkspaceId = [0xBBu8; 32];
        finalize_admitted(
            &c,
            &id,
            b"canonical-bytes",
            Some(ws),
            EventScope::Durable,
            EventStatus::Applied,
        )
        .unwrap();

        // Step 3: subsequent get returns the workspace_id.
        let row = get(&c, &id).unwrap().unwrap();
        assert_eq!(row.workspace_id, Some(ws));
        assert_eq!(row.status, EventStatus::Applied);
        assert_eq!(row.canonical_event_bytes, b"canonical-bytes");

        // Helper: get_workspace_id matches.
        assert_eq!(get_workspace_id(&c, &id).unwrap(), Some(ws));
    }

    #[test]
    fn upsert_event_with_workspace_id() {
        // Endpoint-local synthesis path: the projector writes a row with
        // a known workspace_id directly — the column must be populated.
        let c = open();
        let id: BlakeId = [0xCCu8; 32];
        let ws: WorkspaceId = [0xEEu8; 32];
        let row = EventRow {
            event_id: id,
            canonical_event_bytes: vec![1, 2, 3, 4],
            workspace_id: Some(ws),
            scope: EventScope::EndpointLocal,
            status: EventStatus::Applied,
            created_at_ms: 7,
            expires_at_ms: None,
        };
        let inserted = upsert_event(&c, &row).unwrap();
        assert!(inserted);
        let read = get(&c, &id).unwrap().unwrap();
        assert_eq!(read.workspace_id, Some(ws));
        assert_eq!(read.scope, EventScope::EndpointLocal);

        // Idempotent: a re-upsert with the same id is a no-op.
        let inserted2 = upsert_event(&c, &row).unwrap();
        assert!(!inserted2);
    }

    #[test]
    fn finalize_admitted_does_not_overwrite_existing_workspace_id() {
        // Plan.md line 62: once finalized with a workspace_id, the column
        // must remain stable. A second finalize call with a different
        // workspace_id must be a no-op on the workspace column.
        let c = open();
        let id: BlakeId = [9u8; 32];
        admit_event_id(&c, id, 1).unwrap();
        let ws_a: WorkspaceId = [0x11u8; 32];
        let ws_b: WorkspaceId = [0x22u8; 32];
        finalize_admitted(&c, &id, b"a", Some(ws_a), EventScope::Durable, EventStatus::Ready)
            .unwrap();
        // Defensive: a second finalize with a different ws must NOT
        // change the column (COALESCE preserves the first value).
        finalize_admitted(&c, &id, b"a", Some(ws_b), EventScope::Durable, EventStatus::Ready)
            .unwrap();
        let row = get(&c, &id).unwrap().unwrap();
        assert_eq!(row.workspace_id, Some(ws_a));
    }

    #[test]
    fn set_workspace_id_only_fills_null() {
        let c = open();
        let id: BlakeId = [3u8; 32];
        admit_event_id(&c, id, 0).unwrap();
        let ws_a: WorkspaceId = [0x11u8; 32];
        let ws_b: WorkspaceId = [0x22u8; 32];
        let n = set_workspace_id(&c, &id, &ws_a).unwrap();
        assert_eq!(n, 1, "first set fills the NULL");
        let n = set_workspace_id(&c, &id, &ws_b).unwrap();
        assert_eq!(n, 0, "second set must NOT overwrite an existing ws");
        let row = get(&c, &id).unwrap().unwrap();
        assert_eq!(row.workspace_id, Some(ws_a));
    }

    #[test]
    fn unblock_dependents_marks_ready_when_last_blocker_gone() {
        let c = open();
        let dep_a: BlakeId = [1u8; 32];
        let dep_b: BlakeId = [2u8; 32];
        let blocked: BlakeId = [3u8; 32];
        // Insert the blocked event in 'blocked' status.
        upsert_event(
            &c,
            &EventRow {
                event_id: blocked,
                canonical_event_bytes: b"x".to_vec(),
                workspace_id: Some([0xAAu8; 32]),
                scope: EventScope::Durable,
                status: EventStatus::Blocked,
                created_at_ms: 0,
                expires_at_ms: None,
            },
        )
        .unwrap();
        add_blockers(&c, &blocked, &[dep_a, dep_b]).unwrap();
        // First blocker resolves: still blocked.
        let ready = unblock_dependents(&c, &dep_a).unwrap();
        assert!(ready.is_empty(), "still has dep_b -> not yet ready");
        let row = get(&c, &blocked).unwrap().unwrap();
        assert_eq!(row.status, EventStatus::Blocked);
        // Second blocker resolves: now ready.
        let ready = unblock_dependents(&c, &dep_b).unwrap();
        assert_eq!(ready, vec![blocked]);
        let row = get(&c, &blocked).unwrap().unwrap();
        assert_eq!(row.status, EventStatus::Ready);
    }
}
