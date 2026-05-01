//! # Generic context loader
//!
//! ## Purpose
//! Returns the bounded `{event, deps, labels}` context for a parsed event,
//! reading from `events_canonical` and `labels`. No per-event-type SQL —
//! every projector sees the same shape (`plan.md` lines 234-240). This is
//! the Stage-1 replacement for the legacy per-event `context_loader`
//! function on `EventTypeMeta`.
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the read-side of the `events_canonical` row + canonical-bytes lookup
//!   for declared deps,
//! - the `labels` bulk read for the event id and its deps,
//! - assembly of `ContextSnapshot.deps` and `ContextSnapshot.labels`.
//!
//! Does NOT own:
//! - the legacy per-event `context_loader` callbacks on `EventTypeMeta`
//!   (those are vestigial and ignored by the substrate chain),
//! - any other field of `ContextSnapshot` — the spec says
//!   `{event, deps, labels}` and nothing else; richer state must arrive
//!   as a declared dep or a label,
//! - schema management for `events_canonical` or `labels`.
//!
//! ## Interfaces
//! - [`load_generic_context`] — produce a `ContextSnapshot` given a parsed
//!   event and a DB handle. The returned snapshot has `deps` and `labels`
//!   populated; every other field is left at its `Default` value.
//!
//! ## State
//! Reads only:
//! - `events_canonical(event_id, canonical_event_bytes, workspace_id)` —
//!   bytes are fetched per declared dep id.
//! - `labels(event_id, label_type, workspace_id)` — bulk-fetched for the
//!   event id and each declared dep id.
//!
//! ## Invariants
//! - The loader runs INSIDE the chain transaction so the read is
//!   consistent with the write path (`plan.md` lines 102-114).
//! - Deps that are not yet admitted (no `events_canonical` row, or the row
//!   exists but `canonical_event_bytes` is empty because it's still in
//!   `processing`) are silently skipped. The chain blocks-by-event on
//!   missing deps via `add_blockers` before re-running the projector, so
//!   the loader does not need to surface "missing dep" itself.
//! - Label and dep keys are base64-encoded event ids — same format as the
//!   existing `ContextSnapshot.labels` map.
//! - Workspace scope: labels are filtered by the event's `workspace_id`
//!   read from `events_canonical`. If the event itself has no admitted
//!   row yet (rare — caller normally has finalized it before calling),
//!   labels are returned as-empty rather than failing.
//!
//! ## Flow
//! ```text
//!   load_generic_context(event, db):
//!     1. dep_ids = event.dep_field_values()           // schema-driven
//!     2. for each dep_id:
//!          row = events_canonical.get(dep_id)
//!          if row.canonical_event_bytes nonempty:
//!              deps[base64(dep_id)] = bytes
//!     3. own_id = BLAKE3(encode_event(event))         // canonical
//!     4. workspace_id = events_canonical.workspace_id(own_id)  // or
//!                       fall back to first present dep's ws_id
//!     5. label_ids = [own_id] ++ dep_ids
//!        labels = read_labels_for_event_ids(label_ids, workspace_id)
//!     6. return ContextSnapshot { deps, labels, ..default() }
//! ```
//!
//! ## Failure / restart behavior
//! - DB errors propagate via `rusqlite::Error` boxed into the loader's
//!   `Result`. The chain rolls back its transaction on any `Err`.
//! - Crash mid-load: no writes performed by the loader, so restart is a
//!   plain re-read.
//!
//! ## Performance notes
//! - One query per declared dep + one prepared statement reused for
//!   labels. For typical events this is bounded (≤ ~5 deps).
//! - All reads hit PRIMARY KEY indexes on `events_canonical.event_id` and
//!   `labels(event_id, label_type, workspace_id)`.
//!
//! ## Testing hooks
//! - `tests/generic_context_test.rs` covers no-deps/no-labels, single
//!   dep present, dep with label, label-on-self, and missing-dep paths.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;

use crate::crypto::{event_id_to_base64, EventId};
use crate::event_modules::{encode_event, ParsedEvent};
use crate::state::labels::read_labels_for_event_ids;
use crate::state::projection::contract::ContextSnapshot;

/// Errors raised by the generic context loader. DB errors are the only
/// failure mode in Stage 1 — all other "misses" (absent dep, no labels,
/// missing event row) are silently coerced into empty entries.
#[derive(Debug)]
pub enum GenericContextError {
    Db(rusqlite::Error),
    Encode(String),
}

impl std::fmt::Display for GenericContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenericContextError::Db(e) => write!(f, "db error: {}", e),
            GenericContextError::Encode(msg) => write!(f, "encode error: {}", msg),
        }
    }
}

impl std::error::Error for GenericContextError {}

impl From<rusqlite::Error> for GenericContextError {
    fn from(e: rusqlite::Error) -> Self {
        GenericContextError::Db(e)
    }
}

/// Load the bounded `{event, deps, labels}` context for a parsed event.
///
/// Reads from `events_canonical` and `labels` — no per-event-type SQL.
/// Returns a `ContextSnapshot` with `deps` and `labels` populated; all
/// other fields are left at their `Default` value (caller must not depend
/// on them being filled in by this loader — see plan.md "if a projector
/// needs more state, that state must arrive as a declared dep or a
/// label").
///
/// `event` is the already-parsed, already-admitted event. Its declared
/// deps are extracted via `ParsedEvent::dep_field_values()` (the same
/// accessor used by the dep-cache and admission machinery).
pub fn load_generic_context(
    event: &ParsedEvent,
    db: &Connection,
) -> Result<ContextSnapshot, GenericContextError> {
    // 1. Extract declared dep ids (schema-driven, no per-type branching).
    let dep_pairs = event.dep_field_values();
    let dep_ids: Vec<EventId> = dep_pairs.iter().map(|(_field, id)| *id).collect();

    // 2. Determine the event's own id + workspace. We hash the canonical
    // bytes here rather than asking the caller, so the loader stays
    // self-contained. If encoding fails (shouldn't happen for an admitted
    // event), surface as an error rather than silently misattributing.
    let own_bytes = encode_event(event)
        .map_err(|e| GenericContextError::Encode(format!("{:?}", e)))?;
    let own_id: EventId = blake3_id(&own_bytes);

    // Read the event's row to recover its workspace_id. If the row isn't
    // present (loader called pre-finalize), fall back to the first
    // present dep's workspace; if nothing matches, leave workspace empty
    // and labels will come back empty (no labels can match an unknown
    // workspace).
    let mut workspace_id_bytes: Option<Vec<u8>> = lookup_workspace_id(db, &own_id)?;

    // 3. Load each dep's canonical bytes (skipping absent / unfinalized
    // rows). Also fall back to the first dep's workspace_id for the
    // labels query if the event itself is not yet finalized.
    let mut deps: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for dep_id in &dep_ids {
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = db
            .query_row(
                "SELECT canonical_event_bytes, workspace_id
                   FROM events_canonical WHERE event_id = ?1",
                params![dep_id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((bytes, ws)) = row {
            // Skip rows that are still in `processing` (no bytes yet).
            // The chain will block on these via blocked_by_event.
            if !bytes.is_empty() {
                deps.insert(event_id_to_base64(dep_id), bytes);
            }
            if workspace_id_bytes.is_none() {
                if let Some(b) = ws {
                    if b.len() == 32 {
                        workspace_id_bytes = Some(b);
                    }
                }
            }
        }
    }

    // 4. Bulk-load labels for own_id + every dep_id, scoped to the
    // event's workspace. Empty workspace → empty labels (consistent with
    // the workspace-scoped invariant of `labels`).
    let mut label_ids: Vec<EventId> = Vec::with_capacity(dep_ids.len() + 1);
    label_ids.push(own_id);
    label_ids.extend(dep_ids.iter().copied());

    let labels = if let Some(ws_bytes) = workspace_id_bytes {
        // `read_labels_for_event_ids` accepts the workspace as a base64
        // string OR raw ascii bytes. The labels table stores 32-byte
        // workspace ids, so encode our 32-byte ws bytes as base64.
        let ws_b64 = if ws_bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&ws_bytes);
            event_id_to_base64(&id)
        } else {
            // Defensive — should not happen for finalized rows.
            String::new()
        };
        read_labels_for_event_ids(db, &ws_b64, &label_ids)?
    } else {
        BTreeMap::new()
    };

    // 5. Sync-family extension. compare/have/need projectors need state
    // that lives in `negentropy_tree` materialized rows or in
    // `events_canonical` itself. We populate it here at context-load time
    // so the pure projector dispatch path can drive the recursive fold
    // without doing any DB reads of its own.
    let mut snap = ContextSnapshot {
        deps,
        labels,
        ..Default::default()
    };
    populate_sync_context(&mut snap, event, db)?;
    Ok(snap)
}

/// When `event` is a sync-family event (Compare/Have/Need), populate the
/// `local_sync_*` fields of the snapshot. No-op for any other variant.
///
/// This is intentionally branch-on-variant rather than dispatched through
/// the registry — the sync extension is a small, statically-known set of
/// fields and the generic loader is the right place to assemble it.
fn populate_sync_context(
    snap: &mut ContextSnapshot,
    event: &ParsedEvent,
    db: &Connection,
) -> Result<(), GenericContextError> {
    match event {
        ParsedEvent::Compare(ev) => {
            // F_v for the local tree.
            let fp = crate::event_modules::sync::negentropy_tree::node_fingerprint(
                db,
                &ev.workspace_id,
                &ev.node_id,
            )?;
            snap.local_sync_node_fingerprint = Some(fp);

            // children = distinct node_ids of length len+1 that prefix any
            // strictly-longer membership row beneath ev.node_id.
            let prefix_len = ev.node_id.len() as i64;
            let child_len = prefix_len + 1;
            let mut stmt = db.prepare(
                "SELECT DISTINCT substr(node_id, 1, ?3) AS child
                 FROM negentropy_root_membership
                 WHERE workspace_id = ?1
                   AND length(node_id) > ?4
                   AND substr(node_id, 1, ?4) = ?2
                 ORDER BY child ASC",
            )?;
            let mut rows = stmt.query(params![
                ev.workspace_id.to_vec(),
                ev.node_id.to_vec(),
                child_len,
                prefix_len,
            ])?;
            let mut child_paths: Vec<Vec<u8>> = Vec::new();
            while let Some(row) = rows.next()? {
                child_paths.push(row.get(0)?);
            }
            // Drop `stmt`/`rows` borrows before re-borrowing `db` for the
            // per-child fingerprint reads.
            drop(rows);
            drop(stmt);
            let mut children: Vec<(Vec<u8>, [u8; 32])> =
                Vec::with_capacity(child_paths.len());
            for path in child_paths {
                let fp = crate::event_modules::sync::negentropy_tree::node_fingerprint(
                    db,
                    &ev.workspace_id,
                    &path,
                )?;
                children.push((path, fp));
            }
            snap.local_sync_node_children = children;

            // members at exactly ev.node_id.
            let mut stmt2 = db.prepare(
                "SELECT event_id FROM negentropy_root_membership
                 WHERE workspace_id = ?1 AND node_id = ?2
                 ORDER BY event_id ASC",
            )?;
            let mut rows2 =
                stmt2.query(params![ev.workspace_id.to_vec(), ev.node_id.to_vec()])?;
            let mut members: Vec<[u8; 32]> = Vec::new();
            while let Some(row) = rows2.next()? {
                let blob: Vec<u8> = row.get(0)?;
                if blob.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&blob);
                    members.push(id);
                }
            }
            snap.local_sync_node_members = members;
        }
        ParsedEvent::Have(ev) => {
            let row: Option<String> = db
                .query_row(
                    "SELECT status FROM events_canonical WHERE event_id = ?1",
                    params![ev.event_id.as_slice()],
                    |r| r.get::<_, String>(0),
                )
                .optional()?;
            let has = match row {
                Some(s) => s != "rejected",
                None => false,
            };
            snap.local_sync_has_event = Some(has);
        }
        ParsedEvent::Need(ev) => {
            let row: Option<(String, Vec<u8>)> = db
                .query_row(
                    "SELECT status, canonical_event_bytes FROM events_canonical
                     WHERE event_id = ?1",
                    params![ev.event_id.as_slice()],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            let (has, bytes) = match row {
                Some((status, bytes)) => {
                    let sendable = status != "rejected" && !bytes.is_empty();
                    (sendable, if sendable { Some(bytes) } else { None })
                }
                None => (false, None),
            };
            snap.local_sync_has_event = Some(has);
            snap.local_sync_event_bytes = bytes;
        }
        _ => {}
    }
    Ok(())
}

fn lookup_workspace_id(
    db: &Connection,
    event_id: &EventId,
) -> Result<Option<Vec<u8>>, GenericContextError> {
    let row: Option<Option<Vec<u8>>> = db
        .query_row(
            "SELECT workspace_id FROM events_canonical WHERE event_id = ?1",
            params![event_id.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let ws = row.flatten().filter(|b| b.len() == 32);
    Ok(ws)
}

fn blake3_id(bytes: &[u8]) -> EventId {
    let h = blake3::hash(bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(h.as_bytes());
    id
}
