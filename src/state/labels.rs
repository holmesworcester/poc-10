//! # Label gates
//!
//! ## Purpose
//! Generic side table that replaces per-event-type gate tables (deletion
//! tombstones, removal sets, `invite_bootstrap_trust`). A label is a
//! `(event_id, label_type, workspace_id)` triple written by a gating event
//! and read by future projectors as part of their context (`plan.md`
//! lines 164-170).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the `labels` table,
//! - the `write_label` / `read_labels` / `has_label` /
//!   `read_labels_for_event_ids` helpers,
//! - the canonical label-type vocabulary documented below.
//!
//! Does NOT own:
//! - the gating event projectors themselves (they import from here),
//! - the projection-context loader that surfaces labels to projectors,
//! - any cleanup / GC of label rows.
//!
//! ## Interfaces
//! - [`write_label`] — idempotent INSERT OR IGNORE on
//!   `(event_id, label_type, workspace_id)`.
//! - [`read_labels`] — all label types attached to one event id within a
//!   workspace.
//! - [`has_label`] — existence check for a specific label type.
//! - [`read_labels_for_event_ids`] — bulk load for the projection context
//!   (returns a `BTreeMap<base64_event_id, Vec<label_type>>`).
//!
//! ## State
//! ```text
//! labels:
//!   event_id     BLOB NOT NULL
//!   label_type   TEXT NOT NULL
//!   workspace_id BLOB NOT NULL
//!   PRIMARY KEY (event_id, label_type, workspace_id)
//! ```
//!
//! ## Invariants
//! - Idempotent writes: re-applying the same `(event_id, label_type,
//!   workspace_id)` is a no-op (replay safe).
//! - Labels are ALWAYS scoped by `workspace_id`. A "deleted" label written
//!   in workspace A does NOT mute messages in workspace B.
//! - Stable label-type strings — used as wire / projector vocabulary, do
//!   not rename without a migration.
//!
//! ## Canonical label types
//! - `"deleted"` — written on a `message_deletion` event, keyed by the
//!   target message event id. Future reactions / repeat deletions
//!   referencing that id read this label and refuse / collapse.
//! - `"removed_by:<issuer>"` — written on a `removal` event, keyed by the
//!   removed identity (user_id or peer_id). Future content events whose
//!   signer resolves to that identity read this label and refuse to
//!   project.
//! - `"expired:<event_id>"` — reserved for TTL / lifetime expiry of a
//!   target event. Future references read this label and treat the
//!   target as gone (plan.md §"Purges", "surviving fact" examples).
//! - `"revoked:<key_id>"` — reserved for key revocation. Future events
//!   encrypted to a revoked key id read this label and refuse to
//!   decrypt / project (plan.md §"Purges", "surviving fact" examples).
//! - `"superseded"` — reserved for invite supersession (bootstrap-trust
//!   gate replacement). Not yet wired — see TODO in invite_accepted
//!   projector.
//!
//! ## Relationship to purge
//! Labels survive purge as the canonical representation of semantic
//! removal; plan.md §"Purges" requires that physical compaction never
//! erase the only evidence of a semantic change. See
//! `state/projection/purge.rs` for the compactor.
//!
//! ## Flow
//! ```text
//!   On a gating event (delete X, remove U, supersede I):
//!     1. projector purges existing matching rows + drops derived state,
//!     2. projector writes ONE label row (event_id, label_type, ws),
//!     3. future incoming events read labels via the context loader and
//!        reject / block / no-op.
//! ```
//!
//! ## Failure / restart behavior
//! - Replay-safe: duplicate writes coalesce. A re-projection after restart
//!   produces the same row set.
//! - DB errors propagate; the gating projector's transaction rolls back.
//!
//! ## Performance notes
//! - Bulk load uses a single `prepare_cached` statement and one query per
//!   event id. Sized for typical context sizes (event + small dep set).
//! - PRIMARY KEY is `(event_id, label_type, workspace_id)`; all three
//!   helpers hit the index.
//!
//! ## Testing hooks
//! - In-file `tests` cover write/read round-trip, idempotent re-writes,
//!   and bulk load filtering by present ids.

use crate::crypto::{event_id_to_base64, EventId};
use rusqlite::{Connection, Result as SqliteResult};
use std::collections::BTreeMap;

/// Idempotently write a label row.
///
/// Writes `(event_id, label_type, workspace_id)`. INSERT OR IGNORE — duplicate
/// (event_id, label_type) writes are no-ops, which preserves replay safety.
pub fn write_label(
    conn: &Connection,
    workspace_id: &str,
    event_id_b64: &str,
    label_type: &str,
) -> SqliteResult<()> {
    let event_id_bytes: Vec<u8> = match crate::crypto::event_id_from_base64(event_id_b64) {
        Some(id) => id.to_vec(),
        // Fall back to raw ascii bytes if the caller didn't pass a 32-byte
        // event id (some callers use peer/tenant string ids).
        None => event_id_b64.as_bytes().to_vec(),
    };
    let workspace_id_bytes = match crate::crypto::event_id_from_base64(workspace_id) {
        Some(id) => id.to_vec(),
        None => workspace_id.as_bytes().to_vec(),
    };
    conn.execute(
        "INSERT OR IGNORE INTO labels (event_id, label_type, workspace_id)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![event_id_bytes, label_type, workspace_id_bytes],
    )?;
    Ok(())
}

/// Read all label_types attached to a single event id, scoped to a workspace.
pub fn read_labels(
    conn: &Connection,
    workspace_id: &str,
    event_id_b64: &str,
) -> SqliteResult<Vec<String>> {
    let event_id_bytes = match crate::crypto::event_id_from_base64(event_id_b64) {
        Some(id) => id.to_vec(),
        None => event_id_b64.as_bytes().to_vec(),
    };
    let workspace_id_bytes = match crate::crypto::event_id_from_base64(workspace_id) {
        Some(id) => id.to_vec(),
        None => workspace_id.as_bytes().to_vec(),
    };
    let mut stmt = conn.prepare_cached(
        "SELECT label_type FROM labels
         WHERE event_id = ?1 AND workspace_id = ?2",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![event_id_bytes, workspace_id_bytes],
        |row| row.get::<_, String>(0),
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Check existence of a specific label on an event.
pub fn has_label(
    conn: &Connection,
    workspace_id: &str,
    event_id_b64: &str,
    label_type: &str,
) -> SqliteResult<bool> {
    let event_id_bytes = match crate::crypto::event_id_from_base64(event_id_b64) {
        Some(id) => id.to_vec(),
        None => event_id_b64.as_bytes().to_vec(),
    };
    let workspace_id_bytes = match crate::crypto::event_id_from_base64(workspace_id) {
        Some(id) => id.to_vec(),
        None => workspace_id.as_bytes().to_vec(),
    };
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM labels
             WHERE event_id = ?1 AND label_type = ?2 AND workspace_id = ?3
         )",
        rusqlite::params![event_id_bytes, label_type, workspace_id_bytes],
        |row| row.get(0),
    )
}

/// Bulk-load labels for a set of event ids in a single workspace.
///
/// Returns a map keyed by base64 event id → list of label types attached.
/// Used by the projection-context loader to surface labels for the event's
/// declared deps + the event itself, in line with the plan.md guidance that
/// `get_context(event)` returns `{event, deps, labels}` and nothing else.
pub fn read_labels_for_event_ids(
    conn: &Connection,
    workspace_id: &str,
    event_ids: &[EventId],
) -> SqliteResult<BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if event_ids.is_empty() {
        return Ok(out);
    }
    let workspace_id_bytes = match crate::crypto::event_id_from_base64(workspace_id) {
        Some(id) => id.to_vec(),
        None => workspace_id.as_bytes().to_vec(),
    };
    let mut stmt = conn.prepare_cached(
        "SELECT label_type FROM labels
         WHERE event_id = ?1 AND workspace_id = ?2",
    )?;
    for eid in event_ids {
        let key_b64 = event_id_to_base64(eid);
        let rows = stmt.query_map(
            rusqlite::params![eid.as_slice(), &workspace_id_bytes],
            |row| row.get::<_, String>(0),
        )?;
        let mut labels = Vec::new();
        for row in rows {
            labels.push(row?);
        }
        if !labels.is_empty() {
            out.insert(key_b64, labels);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::db::control_loop_tables::ensure_schema;

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn write_and_read_label_roundtrip() {
        let conn = open();
        let ws = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let eid = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
        write_label(&conn, ws, eid, "deleted").unwrap();
        write_label(&conn, ws, eid, "deleted").unwrap(); // idempotent
        let labels = read_labels(&conn, ws, eid).unwrap();
        assert_eq!(labels, vec!["deleted".to_string()]);
        assert!(has_label(&conn, ws, eid, "deleted").unwrap());
        assert!(!has_label(&conn, ws, eid, "superseded").unwrap());
    }

    #[test]
    fn read_labels_for_event_ids_returns_only_present_ids() {
        let conn = open();
        let ws = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let id_a: EventId = [0x11u8; 32];
        let id_b: EventId = [0x22u8; 32];
        let a_b64 = event_id_to_base64(&id_a);
        write_label(&conn, ws, &a_b64, "deleted").unwrap();
        write_label(&conn, ws, &a_b64, "removed_by:U").unwrap();
        let map = read_labels_for_event_ids(&conn, ws, &[id_a, id_b]).unwrap();
        assert_eq!(map.len(), 1);
        let mut got = map.get(&a_b64).unwrap().clone();
        got.sort();
        assert_eq!(got, vec!["deleted".to_string(), "removed_by:U".to_string()]);
    }
}
