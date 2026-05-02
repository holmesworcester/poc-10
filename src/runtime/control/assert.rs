//! Assert system: predicate parsing, field querying, and polling assertions.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::event_id_to_base64;
use crate::db::{open_connection, schema::create_tables, timeline::EventTimeline};
use crate::event_modules::{message, peer_shared, reaction, user};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
}

impl Op {
    pub fn eval(self, actual: i64, expected: i64) -> bool {
        match self {
            Op::Eq => actual == expected,
            Op::Ne => actual != expected,
            Op::Ge => actual >= expected,
            Op::Le => actual <= expected,
            Op::Gt => actual > expected,
            Op::Lt => actual < expected,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertResponse {
    pub pass: bool,
    pub field: String,
    pub actual: i64,
    pub op: String,
    pub expected: i64,
    pub timed_out: bool,
    pub debug: Option<String>,
}

// ---------------------------------------------------------------------------
// Predicate parsing
// ---------------------------------------------------------------------------

pub fn parse_predicate(s: &str) -> Result<(String, Op, i64), String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!(
            "predicate must be \"field op value\", got {} parts: {:?}",
            parts.len(),
            s
        ));
    }
    let field = parts[0].to_string();
    let op = match parts[1] {
        "==" => Op::Eq,
        "!=" => Op::Ne,
        ">=" => Op::Ge,
        "<=" => Op::Le,
        ">" => Op::Gt,
        "<" => Op::Lt,
        other => return Err(format!("unknown operator: {}", other)),
    };
    let value: i64 = parts[2]
        .parse()
        .map_err(|e| format!("invalid value '{}': {}", parts[2], e))?;
    Ok((field, op, value))
}

// ---------------------------------------------------------------------------
// Field querying
// ---------------------------------------------------------------------------

/// Returns true when this field is a substrate-wide aggregate that does not
/// need a workspace_id scope. Cross-workspace counters live on substrate
/// tables (events_canonical, inbound_bytes, outbox).
pub fn is_substrate_field(field: &str) -> bool {
    matches!(
        field,
        "messages_total"
            | "events_applied_total"
            | "events_canonical_total"
            | "inbound_bytes_total"
            | "outbox_total"
    )
}

/// Query a predicate field against the database.
///
/// `workspace_id_b64` is `Some(...)` for per-workspace predicates and `None`
/// for substrate-wide aggregates. A per-workspace predicate with no
/// workspace_id returns an error.
pub fn query_field(
    db: &rusqlite::Connection,
    field: &str,
    workspace_id_b64: Option<&str>,
) -> Result<i64, String> {
    fn need_ws<'a>(field: &str, ws: Option<&'a str>) -> Result<&'a str, String> {
        ws.ok_or_else(|| {
            format!(
                "predicate '{}' requires a workspace scope; pass --workspace or run `topo tenant use`",
                field
            )
        })
    }

    match field {
        // Substrate-wide aggregates (no workspace scope required).
        "messages_total" => db
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "events_applied_total" => db
            .query_row(
                "SELECT COUNT(*) FROM events_canonical WHERE status = 'applied'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        "events_canonical_total" => db
            .query_row("SELECT COUNT(*) FROM events_canonical", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "inbound_bytes_total" => db
            .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "outbox_total" => db
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "store_count" | "events_count" | "event_count" => db
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "shared_event_index_count" => db
            .query_row("SELECT COUNT(*) FROM shared_event_index", [], |row| {
                row.get(0)
            })
            .map_err(|e| format!("query failed: {}", e)),
        // Wave 1: admin events dropped; admin_count always 0.
        "admin_count" => Ok(0),

        // Per-workspace counters.
        "message_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            message::count(db, ws).map_err(|e| format!("query failed: {}", e))
        }
        "reaction_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            reaction::count(db, ws).map_err(|e| format!("query failed: {}", e))
        }
        "user_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            user::count(db, ws).map_err(|e| format!("query failed: {}", e))
        }
        "peer_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            peer_shared::count(db, ws).map_err(|e| format!("query failed: {}", e))
        }
        "deleted_message_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            db.query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE workspace_id = ?1",
                rusqlite::params![ws],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e))
        }
        "workspace_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            db.query_row(
                "SELECT COUNT(*) FROM workspaces WHERE workspace_id = ?1",
                rusqlite::params![ws],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e))
        }
        "user_invite_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            db.query_row(
                "SELECT COUNT(*) FROM user_invites WHERE workspace_id = ?1",
                rusqlite::params![ws],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e))
        }
        "device_invite_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            db.query_row(
                "SELECT COUNT(*) FROM device_invites WHERE workspace_id = ?1",
                rusqlite::params![ws],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e))
        }
        "key_secret_count" => {
            let ws = need_ws(field, workspace_id_b64)?;
            db.query_row(
                "SELECT COUNT(*) FROM key_secrets WHERE workspace_id = ?1",
                rusqlite::params![ws],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e))
        }

        // Has-event probes operate against the global events table (any
        // workspace). Sub-substrate use accepts hex or base64 ids.
        other if other.starts_with("has_event:") => {
            let event_id = &other["has_event:".len()..];
            // Try as base64 first.
            let b64_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                    rusqlite::params![event_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("query failed: {}", e))?;
            if b64_count > 0 {
                return Ok(b64_count);
            }
            if let Ok(event_id_bytes) = hex::decode(event_id) {
                if event_id_bytes.len() == 32 {
                    let mut eid = [0u8; 32];
                    eid.copy_from_slice(&event_id_bytes);
                    return db
                        .query_row(
                            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                            rusqlite::params![event_id_to_base64(&eid)],
                            |row| row.get(0),
                        )
                        .map_err(|e| format!("query failed: {}", e));
                }
            }
            Ok(0)
        }
        other => Err(format!("unknown field: {}", other)),
    }
}

fn timeline_debug_for_field(db: &rusqlite::Connection, field: &str) -> Option<String> {
    let event_id = field.strip_prefix("has_event:")?;
    let event_id_b64 = if event_id.len() == 64 {
        let bytes = hex::decode(event_id).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut eid = [0u8; 32];
        eid.copy_from_slice(&bytes);
        event_id_to_base64(&eid)
    } else {
        event_id.to_string()
    };
    EventTimeline::new(db).summary(&event_id_b64).ok().flatten()
}

// ---------------------------------------------------------------------------
// Polling assertion
// ---------------------------------------------------------------------------

/// Poll a predicate until it passes or times out. `workspace_id_b64` is
/// required when the predicate is workspace-scoped; substrate aggregates
/// pass `None`.
pub fn assert_eventually(
    db_path: &str,
    workspace_id_b64: Option<&str>,
    predicate_str: &str,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<AssertResponse, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let (field, op, expected) = parse_predicate(predicate_str)?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let interval = Duration::from_millis(interval_ms);

    loop {
        let actual = query_field(&db, &field, workspace_id_b64)?;
        if op.eval(actual, expected) {
            return Ok(AssertResponse {
                pass: true,
                field,
                actual,
                op: op.symbol().to_string(),
                expected,
                timed_out: false,
                debug: None,
            });
        }
        if start.elapsed() >= timeout {
            let debug = timeline_debug_for_field(&db, &field);
            return Ok(AssertResponse {
                pass: false,
                field,
                actual,
                op: op.symbol().to_string(),
                expected,
                timed_out: true,
                debug,
            });
        }
        std::thread::sleep(interval);
    }
}
