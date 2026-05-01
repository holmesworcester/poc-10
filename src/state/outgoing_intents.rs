//! **Compatibility shim** over the new `outbox` boundary table.
//!
//! Refactor note (post-plan.md update): plan.md now treats sync messages
//! (Have/Need/Compare/Send) as endpoint-local *events* in the canonical
//! `events` table whose ids are the rows in `outbox`. The Phase 10 sender
//! was originally written against an `outgoing_intents` table with an
//! opaque `payload` column; that table is now dropped.
//!
//! With the slim `outbox` schema (plan.md lines 168-174 — only
//! `(connection_id, event_id, queued_at_ms)`, no status/lease/attempts),
//! the legacy claim/lease/mark-sent dance is *no longer expressible* on
//! the outbox alone. The per-connection `ConnectionSender`
//! (`runtime/jobs/sender::ConnectionSender`) is the new owner of "what's
//! in flight" via its in-memory `present` set, and the table is just the
//! deduped pending list.
//!
//! What this shim still preserves for older callers:
//!
//! - `IntentKind` / `OutgoingIntent` / `build_intent` types.
//! - `intent_id_for(...)` deterministic id derivation.
//! - `upsert_intent(...)` — synthesizes the EndpointLocal sync event in
//!   `events_canonical` and inserts the matching `outbox` row.
//!
//! What this shim **drops**:
//!
//! - `claim_intents_for_connection` / `mark_sent` / `requeue_failed` /
//!   `get_intent` — they assumed the lease/status columns the new schema
//!   doesn't have. Drive `ConnectionSender::refill_if_needed` +
//!   `drain_to_socket` directly instead.
//!
//! TODO(plan.md): remove this shim entirely once all callers are migrated
//! to construct `events_canonical` rows + `outbox` entries directly.

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::runtime::control_loop::work_item::{BlakeId, ConnectionId, WorkspaceId};
use crate::state::events_canonical::{self, EventRow, EventScope, EventStatus};
use crate::state::outbox;

/// Kind of outgoing intent. Each variant is a payload-bearing tag whose
/// `intent_id` is fully determined by `(connection_id, workspace_id,
/// kind)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentKind {
    /// "I have event_id locally — you don't need to ask for it."
    Have(BlakeId),
    /// "I want event_id — please send it."
    Need(BlakeId),
    /// "Here is the event blob with this id." (durable event the receiver
    /// should sync from us — id is the canonical durable id.)
    Send(BlakeId),
    /// "Compare this range-tree node: I have fingerprint X."
    Compare {
        node_id: Vec<u8>,
        fingerprint: [u8; 32],
    },
}

impl IntentKind {
    /// Wire tag string. Stable: do not rename without a migration.
    pub fn tag(&self) -> &'static str {
        match self {
            IntentKind::Have(_) => "have",
            IntentKind::Need(_) => "need",
            IntentKind::Send(_) => "send",
            IntentKind::Compare { .. } => "compare",
        }
    }

    /// Bytes that disambiguate the intent payload within `(connection_id,
    /// workspace_id, kind)`.
    fn payload_key_bytes(&self) -> Vec<u8> {
        match self {
            IntentKind::Have(id) | IntentKind::Need(id) | IntentKind::Send(id) => id.to_vec(),
            IntentKind::Compare {
                node_id,
                fingerprint,
            } => {
                let mut out = Vec::with_capacity(2 + node_id.len() + 32);
                out.extend_from_slice(&(node_id.len() as u16).to_be_bytes());
                out.extend_from_slice(node_id);
                out.extend_from_slice(fingerprint);
                out
            }
        }
    }
}

/// In-memory representation of one outgoing intent. The legacy `payload`
/// field is preserved so older callers and tests that key off
/// `payload_key_bytes` still work; it is not stored anywhere — the wire
/// bytes live in `events_canonical.canonical_event_bytes` for endpoint-local kinds
/// and in the durable `events` table for `Send`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingIntent {
    pub intent_id: BlakeId,
    pub kind: IntentKind,
    pub connection_id: ConnectionId,
    pub workspace_id: WorkspaceId,
    pub payload: Vec<u8>,
    pub ttl_ms: i64,
}

/// Deterministic intent id.
///
/// For `Have/Need/Compare`: `BLAKE3("out" || connection_id ||
/// workspace_id || kind_tag || payload_key)`. This doubles as the
/// endpoint-local event id we synthesize.
///
/// For `Send(event_id)`: returns `event_id` directly — the outbox row's
/// `event_id` is the durable event id by definition.
pub fn intent_id_for(
    kind: &IntentKind,
    connection_id: ConnectionId,
    workspace_id: WorkspaceId,
) -> BlakeId {
    if let IntentKind::Send(id) = kind {
        return *id;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"out");
    h.update(&connection_id);
    h.update(&workspace_id);
    h.update(kind.tag().as_bytes());
    h.update(&kind.payload_key_bytes());
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(out.as_bytes());
    id
}

/// Tag bytes used when synthesizing endpoint-local event payloads. Same
/// constants the sender uses on the receive side.
const ENVELOPE_HAVE: u8 = 0xC0;
const ENVELOPE_NEED: u8 = 0xC1;
const ENVELOPE_COMPARE: u8 = 0xC2;

fn envelope_byte(kind: &IntentKind) -> Option<u8> {
    Some(match kind {
        IntentKind::Have(_) => ENVELOPE_HAVE,
        IntentKind::Need(_) => ENVELOPE_NEED,
        IntentKind::Compare { .. } => ENVELOPE_COMPARE,
        IntentKind::Send(_) => return None,
    })
}

/// Insert an intent. For `Have/Need/Compare`: synthesize an
/// endpoint-local event in `events_canonical` (idempotent on event id),
/// then insert an `outbox(connection_id, event_id, queued_at_ms)` row.
/// For `Send(id)`: just insert the outbox row — the durable event already
/// lives in the canonical store.
///
/// Returns `true` if a new outbox row was created, `false` if it already
/// existed (idempotent on `(connection_id, event_id)`).
pub fn upsert_intent(
    conn: &Connection,
    intent: &OutgoingIntent,
    queued_at_ms: i64,
) -> SqliteResult<bool> {
    if let Some(env) = envelope_byte(&intent.kind) {
        // Wire layout for endpoint-local sync events stored in
        // `events_canonical.canonical_event_bytes` by this shim:
        //   [envelope_byte][workspace_id (32B)][payload_key_bytes ...]
        // The workspace prefix is shim-internal — it lets the sender
        // recover the intent's workspace_id from the EndpointLocal row
        // when refilling its hot queue.
        let mut wire = Vec::with_capacity(1 + 32 + intent.payload.len());
        wire.push(env);
        wire.extend_from_slice(&intent.workspace_id);
        wire.extend_from_slice(&intent.payload);
        let row = EventRow {
            event_id: intent.intent_id,
            canonical_event_bytes: wire,
            workspace_id: Some(intent.workspace_id),
            scope: EventScope::EndpointLocal,
            status: EventStatus::Applied,
            created_at_ms: queued_at_ms,
            expires_at_ms: if intent.ttl_ms > 0 && intent.ttl_ms < i64::MAX / 4 {
                Some(queued_at_ms.saturating_add(intent.ttl_ms))
            } else {
                None
            },
        };
        let _ = events_canonical::upsert_event(conn, &row)?;
    }
    outbox::enqueue(conn, intent.connection_id, intent.intent_id, queued_at_ms)
}

/// Convenience: construct an `OutgoingIntent` with the canonical
/// `intent_id` and the canonical opaque `payload` for that kind.
/// - `Have/Need/Send(id)` -> 32-byte id verbatim.
/// - `Compare{node_id, fp}` -> [u16 BE node_id_len][node_id][fp].
pub fn build_intent(
    kind: IntentKind,
    connection_id: ConnectionId,
    workspace_id: WorkspaceId,
    ttl_ms: i64,
) -> OutgoingIntent {
    let intent_id = intent_id_for(&kind, connection_id, workspace_id);
    let payload = kind.payload_key_bytes();
    OutgoingIntent {
        intent_id,
        kind,
        connection_id,
        workspace_id,
        payload,
        ttl_ms,
    }
}

/// Read pending outbox entries for `connection_id` and reconstruct
/// `OutgoingIntent`s. Used by tests and older inspection helpers — the
/// real sender path now lives in `ConnectionSender`.
///
/// Note: this is purely a SELECT — no claim, lease, or status mutation
/// (those are not representable on the slim outbox schema).
pub fn pending_intents_for_connection(
    conn: &Connection,
    connection_id: &ConnectionId,
    max: usize,
) -> SqliteResult<Vec<OutgoingIntent>> {
    let pending = outbox::pending_for_connection(conn, connection_id, max)?;
    let mut out = Vec::with_capacity(pending.len());
    for (event_id, _qts) in pending {
        if let Some(intent) = resolve_intent_for_outbox(conn, connection_id, &event_id)? {
            out.push(intent);
        }
    }
    Ok(out)
}

/// Resolve an outbox row back to a legacy `OutgoingIntent`. For
/// endpoint-local rows we recover the kind from the synthesized payload's
/// envelope byte; for durable rows we treat it as `Send(event_id)`.
fn resolve_intent_for_outbox(
    conn: &Connection,
    connection_id: &ConnectionId,
    event_id: &BlakeId,
) -> SqliteResult<Option<OutgoingIntent>> {
    if let Some(row) = events_canonical::get(conn, event_id)? {
        if row.scope == EventScope::EndpointLocal && row.canonical_event_bytes.len() >= 1 + 32 {
            // Wire layout: [env_byte][workspace_id(32)][payload_key_bytes].
            let env = row.canonical_event_bytes[0];
            let mut ws = [0u8; 32];
            ws.copy_from_slice(&row.canonical_event_bytes[1..33]);
            let payload = row.canonical_event_bytes[33..].to_vec();
            let kind = match env {
                ENVELOPE_HAVE => {
                    let id = first_32(&payload);
                    IntentKind::Have(id.unwrap_or([0u8; 32]))
                }
                ENVELOPE_NEED => {
                    let id = first_32(&payload);
                    IntentKind::Need(id.unwrap_or([0u8; 32]))
                }
                ENVELOPE_COMPARE => match decode_compare(&payload) {
                    Some(c) => c,
                    None => return Ok(None),
                },
                _ => return Ok(None),
            };
            return Ok(Some(OutgoingIntent {
                intent_id: *event_id,
                kind,
                connection_id: *connection_id,
                workspace_id: ws,
                payload,
                ttl_ms: i64::MAX / 4,
            }));
        }
    }
    Ok(Some(OutgoingIntent {
        intent_id: *event_id,
        kind: IntentKind::Send(*event_id),
        connection_id: *connection_id,
        workspace_id: lookup_workspace_for_connection(conn, connection_id).unwrap_or([0u8; 32]),
        payload: event_id.to_vec(),
        ttl_ms: i64::MAX / 4,
    }))
}

/// Best-effort workspace_id lookup for legacy callers.
fn lookup_workspace_for_connection(
    conn: &Connection,
    connection_id: &ConnectionId,
) -> Option<WorkspaceId> {
    use rusqlite::OptionalExtension;
    let blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT workspace_id FROM connection_shared_workspaces
             WHERE connection_id = ?1 LIMIT 1",
            params![connection_id.to_vec()],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();
    let blob = blob?;
    if blob.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&blob);
        Some(out)
    } else {
        None
    }
}

fn first_32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() < 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Some(out)
}

fn decode_compare(payload: &[u8]) -> Option<IntentKind> {
    if payload.len() < 2 {
        return None;
    }
    let nlen = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + nlen + 32 {
        return None;
    }
    let node_id = payload[2..2 + nlen].to_vec();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&payload[2 + nlen..2 + nlen + 32]);
    Some(IntentKind::Compare {
        node_id,
        fingerprint: fp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::db::control_loop_tables::ensure_schema;

    fn open() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
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

    fn add_shared(c: &Connection, conn_id: ConnectionId, ws: WorkspaceId) {
        c.execute(
            "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), ws.to_vec()],
        )
        .unwrap();
    }

    #[test]
    fn intent_id_is_deterministic_for_have() {
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [2u8; 32];
        let kind = IntentKind::Have([3u8; 32]);
        let id1 = intent_id_for(&kind, conn_id, ws);
        let id2 = intent_id_for(&kind, conn_id, ws);
        assert_eq!(id1, id2);
        let id_need = intent_id_for(&IntentKind::Need([3u8; 32]), conn_id, ws);
        assert_ne!(id1, id_need);
    }

    #[test]
    fn intent_id_for_send_is_event_id() {
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [2u8; 32];
        let id = intent_id_for(&IntentKind::Send([7u8; 32]), conn_id, ws);
        assert_eq!(id, [7u8; 32]);
    }

    #[test]
    fn upsert_collapses_duplicates_and_writes_outbox() {
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [2u8; 32];
        add_shared(&c, conn_id, ws);
        let intent = build_intent(IntentKind::Have([7u8; 32]), conn_id, ws, 60_000);
        assert!(upsert_intent(&c, &intent, 100).unwrap());
        assert!(!upsert_intent(&c, &intent, 200).unwrap());
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn pending_intents_recovers_have_kind() {
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [2u8; 32];
        add_shared(&c, conn_id, ws);
        let intent = build_intent(IntentKind::Have([4u8; 32]), conn_id, ws, 60_000);
        upsert_intent(&c, &intent, 0).unwrap();
        let pending = pending_intents_for_connection(&c, &conn_id, 16).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(pending[0].kind, IntentKind::Have(_)));
    }

    #[test]
    fn compare_payload_round_trip() {
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [2u8; 32];
        add_shared(&c, conn_id, ws);
        let kind = IntentKind::Compare {
            node_id: vec![0xAA, 0xBB, 0xCC, 0xDD],
            fingerprint: [0xEE; 32],
        };
        let intent = build_intent(kind.clone(), conn_id, ws, 60_000);
        upsert_intent(&c, &intent, 0).unwrap();
        let pending = pending_intents_for_connection(&c, &conn_id, 16).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, kind);
    }
}
