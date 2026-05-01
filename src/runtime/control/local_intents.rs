//! # Local-event intent helper
//!
//! Minimal viable bridge between the daemon's CLI/RPC ingress and the
//! new substrate's event chain.
//!
//! ## Purpose
//! CLI / in-process callers build a [`ParsedEvent`], hand it to
//! [`emit_local_event`] together with the workspace it belongs to, and
//! get back the `event_id` they can poll on. The helper:
//!
//! 1. Encodes the event to canonical bytes.
//! 2. Records a `local_event_intents` row (audit + diagnostics; the
//!    dispatcher's `LocalEvents` queue drains the row to `unhandled`
//!    today — every command that goes through this helper has already
//!    materialized the canonical event by then, so the queue row is a
//!    paper trail rather than an action item).
//! 3. Inserts a `events_canonical` row at status `ready`, so the
//!    dispatcher's `drain_ready` step picks it up and runs parse →
//!    context → project → apply.
//! 4. Notifies the wake bus on the local-events and ready queues so
//!    the dispatcher's idle waiter wakes immediately.
//!
//! Plan-rework D's "single writer is the dispatcher" rule is relaxed
//! here for the cutover: the CLI process / test harness writes
//! directly. SQLite serialises the writes, so concurrent dispatcher +
//! CLI writes do not corrupt the DB; throughput is not the concern at
//! this stage.
//!
//! ## Polling
//! [`wait_for_terminal`] polls `events_canonical[event_id].status`
//! until it reaches `Applied` or `Rejected`, or the deadline elapses.
//! `Blocked` and `Processing` / `Ready` count as in-flight.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection};
use tokio::sync::Mutex;

use crate::event_modules::{encode_event, EventError, ParsedEvent};
use crate::runtime::control_loop::wake_bus::WakeBus;
use crate::state::events_canonical::{
    self, AdmissionResult, EventRow, EventScope, EventStatus,
};

/// 32-byte canonical event id (BLAKE3 of canonical bytes).
pub type EventId = [u8; 32];

/// Errors raised by the local-intent helper.
#[derive(Debug)]
pub enum LocalIntentError {
    Encode(String),
    Db(rusqlite::Error),
    AlreadyKnown {
        event_id: EventId,
        status: EventStatus,
    },
}

impl std::fmt::Display for LocalIntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalIntentError::Encode(s) => write!(f, "encode: {}", s),
            LocalIntentError::Db(e) => write!(f, "db: {}", e),
            LocalIntentError::AlreadyKnown { event_id, status } => write!(
                f,
                "event {} already known with status {:?}",
                hex::encode(&event_id[..4]),
                status
            ),
        }
    }
}

impl std::error::Error for LocalIntentError {}

impl From<EventError> for LocalIntentError {
    fn from(e: EventError) -> Self {
        LocalIntentError::Encode(e.to_string())
    }
}

impl From<rusqlite::Error> for LocalIntentError {
    fn from(e: rusqlite::Error) -> Self {
        LocalIntentError::Db(e)
    }
}

/// Outcome of a successful intent emission. The caller can poll
/// `event_id` against `events_canonical` to wait for terminal status.
#[derive(Debug, Clone)]
pub struct EmittedIntent {
    pub event_id: EventId,
    pub intent_row_id: i64,
}

/// Build, store, and admit a local event intent.
///
/// `command_kind` is the audit tag written into the `local_event_intents`
/// row (e.g. `"create_workspace"`, `"send_message"`). It exists to make
/// the row visible to operators; it does not drive any handler.
///
/// `workspace_id` is the workspace this event belongs to. For a root
/// `Workspace` event, pass `None` and the helper will use the event id
/// itself once it has been computed (root workspaces are
/// self-referential).
///
/// `scope` controls the `events_canonical.scope` column. Most
/// CLI-emitted events are `Durable`; events that should not propagate
/// to peers (`Local`, `EndpointLocal`) can opt out.
pub fn emit_local_event(
    conn: &Connection,
    command_kind: &str,
    event: &ParsedEvent,
    workspace_id: Option<EventId>,
    scope: EventScope,
) -> Result<EmittedIntent, LocalIntentError> {
    // 1. Canonical bytes + event id.
    let bytes = encode_event(event)?;
    let event_id = blake3_id(&bytes);

    // 2. Audit row in local_event_intents.
    let now_ms = now_ms();
    conn.execute(
        "INSERT INTO local_event_intents (command_kind, payload, enqueued_at_ms, status)
         VALUES (?1, ?2, ?3, 'completed')",
        params![command_kind, &bytes, now_ms],
    )?;
    let intent_row_id = conn.last_insert_rowid();

    // 3. Admit the event id and finalize at status=Ready so the
    //    dispatcher's drain_ready picks it up. If the event is
    //    already known we surface that to the caller.
    let admission = events_canonical::admit_event_id(conn, event_id, now_ms)?;
    match admission {
        AdmissionResult::NewlyClaimed => {
            // For a root workspace event, the workspace_id IS the
            // event_id (every other event in the workspace points at
            // this root via its own workspace_id field).
            let resolved_ws = workspace_id.or(Some(event_id));
            events_canonical::finalize_admitted(
                conn,
                &event_id,
                &bytes,
                resolved_ws,
                scope,
                EventStatus::Ready,
            )?;
        }
        AdmissionResult::Known { status } => {
            // If the row is already terminal, the caller can treat the
            // emission as a no-op. If it's mid-flight we still surface
            // the ID; the caller's poll will resolve it.
            if matches!(status, EventStatus::Applied | EventStatus::Rejected) {
                return Ok(EmittedIntent {
                    event_id,
                    intent_row_id,
                });
            }
            // Newly admitted but mid-flight elsewhere: fall through.
        }
    }

    Ok(EmittedIntent {
        event_id,
        intent_row_id,
    })
}

/// Convenience wrapper that takes the runtime's shared `Arc<Mutex<Connection>>`
/// and the wake bus. Notifies the dispatcher on success.
pub async fn emit_local_event_with_wake(
    db: &Arc<Mutex<Connection>>,
    wakes: &Arc<WakeBus>,
    command_kind: &str,
    event: &ParsedEvent,
    workspace_id: Option<EventId>,
    scope: EventScope,
) -> Result<EmittedIntent, LocalIntentError> {
    let result = {
        let conn = db.lock().await;
        emit_local_event(&conn, command_kind, event, workspace_id, scope)?
    };
    // Wake both queues so the dispatcher picks the row up immediately
    // instead of waiting for the idle deadline.
    wakes.notify_local_events();
    wakes.notify_ready();
    Ok(result)
}

/// Poll `events_canonical[event_id].status` until it transitions to
/// `Applied` or `Rejected`, or `deadline` elapses. Returns the terminal
/// `EventStatus`, or an error if the deadline was hit (with the most
/// recent observed status, if any).
pub async fn wait_for_terminal(
    db: &Arc<Mutex<Connection>>,
    event_id: &EventId,
    deadline: Duration,
) -> Result<EventStatus, WaitError> {
    let start = Instant::now();
    let mut last_status: Option<EventStatus> = None;
    while start.elapsed() < deadline {
        {
            let g = db.lock().await;
            let row = events_canonical::get(&g, event_id)
                .map_err(WaitError::Db)?;
            if let Some(r) = row {
                last_status = Some(r.status);
                if matches!(r.status, EventStatus::Applied | EventStatus::Rejected) {
                    return Ok(r.status);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(WaitError::Timeout {
        last_status,
        elapsed: start.elapsed(),
    })
}

/// Errors raised while waiting for terminal status.
#[derive(Debug)]
pub enum WaitError {
    Db(rusqlite::Error),
    Timeout {
        last_status: Option<EventStatus>,
        elapsed: Duration,
    },
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WaitError::Db(e) => write!(f, "db: {}", e),
            WaitError::Timeout {
                last_status,
                elapsed,
            } => write!(
                f,
                "timed out after {}ms (last status: {:?})",
                elapsed.as_millis(),
                last_status
            ),
        }
    }
}

impl std::error::Error for WaitError {}

fn blake3_id(bytes: &[u8]) -> EventId {
    let h = blake3::hash(bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(h.as_bytes());
    id
}

fn now_ms() -> i64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{ParsedEvent, WorkspaceEvent};
    use crate::state::db::ensure_infra_schema;

    fn open_db() -> Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        ensure_infra_schema(&c).unwrap();
        c
    }

    #[test]
    fn emit_local_event_writes_intent_and_canonical_rows() {
        let conn = open_db();
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 123,
            workspace_id: [0xAA; 32],
            public_key: [0xAA; 32],
            name: "test".to_string(),
        });
        let r = emit_local_event(&conn, "create_workspace", &ws, None, EventScope::Durable)
            .expect("emit");

        // local_event_intents row exists.
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM local_event_intents WHERE id = ?1",
                params![r.intent_row_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);

        // events_canonical row exists at status=ready.
        let row = events_canonical::get(&conn, &r.event_id).unwrap().unwrap();
        assert_eq!(row.status, EventStatus::Ready);
        assert_eq!(row.scope, EventScope::Durable);
        assert!(!row.canonical_event_bytes.is_empty());
        // Workspace events are self-referential roots.
        assert_eq!(row.workspace_id, Some(r.event_id));
    }
}
