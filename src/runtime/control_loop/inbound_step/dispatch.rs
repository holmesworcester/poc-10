//! Per-inner-event dispatch: batched admit/finalize plus
//! project-and-apply.
//!
//! `process_inner_events_batched` is the entry point used by
//! `handle_inbound_bytes` after `unwrap` produces inner canonical events.
//! It chunks inner events under SQLite's compound-INSERT cap and folds
//! the per-event admit + finalize work into a single multi-row INSERT
//! per chunk. After the batched insert, projector dispatch still runs
//! per event because the projector registry is per-event-type.
//!
//! `project_and_apply` is the shared tail used by both inner-event
//! dispatch and `handle_ready_event_in_tx`. It loads context, runs the
//! projector, applies write_ops, and updates `events_canonical` status.
//! For `ParsedEvent::Encrypted` it delegates to
//! [`super::encrypted_recurse::apply_encrypted`].

use rusqlite::Connection;

use crate::event_modules::{parse_event, registry, ParsedEvent};
use crate::state::events_canonical::{
    add_blockers, insert_event_rows_multi, set_status, unblock_dependents, EventRow, EventScope,
    EventStatus, MULTI_INSERT_MAX_ROWS,
};
use crate::state::projection::contract::{ProjectorResult, SqlVal, WriteOp};
use crate::state::projection::decision::ProjectionDecision;

use super::super::work_item::{BlakeId, WorkspaceId};
use super::encrypted_recurse::apply_encrypted;
use super::sync_maintenance::apply_sync_maintenance;
use super::{base64_id, blake3_id, ChainError, InnerEventDisposition, InnerEventResult};

/// Batched admit + finalize for a slice of inner events from one inbound
/// frame. See the call site in `process_inbound_bytes_after_dedupe` for
/// the design notes. Two phases: a single multi-row INSERT covering all
/// admit-and-finalize tuples (replacing the `admit_event_id` SELECT+INSERT
/// + `finalize_admitted` UPDATE per event), then a per-event project +
/// apply loop.
pub(super) fn process_inner_events_batched(
    db: &Connection,
    inner_events: &[crate::event_modules::connection::wrap::InnerCanonicalEvent],
    now_ms: i64,
    out: &mut Vec<InnerEventResult>,
) -> Result<(), ChainError> {
    if inner_events.is_empty() {
        return Ok(());
    }

    // Chunk by `MULTI_INSERT_MAX_ROWS` to stay well under SQLite's
    // compound-insert / variable-count caps. Typical batches (32 events)
    // fit in one chunk; the loop is defensive for sender-side coalescing
    // changes that might raise the per-frame inner count.
    for chunk in inner_events.chunks(MULTI_INSERT_MAX_ROWS) {
        process_inner_events_chunk(db, chunk, now_ms, out)?;
    }
    Ok(())
}

fn process_inner_events_chunk(
    db: &Connection,
    inner_events: &[crate::event_modules::connection::wrap::InnerCanonicalEvent],
    now_ms: i64,
    out: &mut Vec<InnerEventResult>,
) -> Result<(), ChainError> {
    // 1. Compute event ids and prepare a probe set.
    let event_ids: Vec<BlakeId> = inner_events
        .iter()
        .map(|i| blake3_id(&i.bytes))
        .collect();

    // 2. Find which event_ids already exist + their statuses. Single
    //    `IN (..)` query replaces the per-event `admit_event_id` SELECT
    //    inside `events_canonical`.
    let existing: std::collections::HashMap<BlakeId, EventStatus> =
        load_existing_statuses(db, &event_ids).map_err(ChainError::Db)?;

    // 3. For each inner: classify into Known / NeedsAdmit-and-parse-OK /
    //    NeedsAdmit-and-parse-failed. Build the multi-row INSERT.
    enum InnerClass {
        AlreadyKnown(EventStatus),
        Parsed(ParsedEvent),
        ParseFailed(String),
    }
    let mut classes: Vec<InnerClass> = Vec::with_capacity(inner_events.len());
    let mut to_insert: Vec<EventRow> = Vec::with_capacity(inner_events.len());
    for (idx, inner) in inner_events.iter().enumerate() {
        let event_id = event_ids[idx];
        if let Some(status) = existing.get(&event_id).copied() {
            classes.push(InnerClass::AlreadyKnown(status));
            continue;
        }
        match parse_event(&inner.bytes) {
            Ok(parsed) => {
                to_insert.push(EventRow {
                    event_id,
                    canonical_event_bytes: inner.bytes.clone(),
                    workspace_id: Some(inner.workspace_id),
                    scope: EventScope::Durable,
                    status: EventStatus::Processing,
                    created_at_ms: now_ms,
                    expires_at_ms: None,
                });
                classes.push(InnerClass::Parsed(parsed));
            }
            Err(e) => {
                // Same shape as the prior single-event path: claim a row
                // for the event_id with status='rejected', empty bytes
                // (wire bytes for an unparseable inner are not retained
                // — they would never replay anyway).
                to_insert.push(EventRow {
                    event_id,
                    canonical_event_bytes: Vec::new(),
                    workspace_id: None,
                    scope: EventScope::Durable,
                    status: EventStatus::Rejected,
                    created_at_ms: now_ms,
                    expires_at_ms: None,
                });
                classes.push(InnerClass::ParseFailed(format!("{:?}", e)));
            }
        }
    }

    // 4. Single multi-row INSERT (no-op if every inner was AlreadyKnown).
    if !to_insert.is_empty() {
        let _ = insert_event_rows_multi(db, &to_insert).map_err(ChainError::Db)?;
    }

    // 5. Per-event project + apply for the parseable, newly-admitted set.
    //    `AlreadyKnown` and `ParseFailed` short-circuit straight to a
    //    disposition without touching the projector. Iterate in arrival
    //    order so callers see results in the same order as the inner
    //    events on the wire.
    for (idx, class) in classes.into_iter().enumerate() {
        let event_id = event_ids[idx];
        let disposition = match class {
            InnerClass::AlreadyKnown(status) => {
                InnerEventDisposition::AlreadyKnown { status }
            }
            InnerClass::ParseFailed(error) => {
                InnerEventDisposition::ParseFailed { error }
            }
            InnerClass::Parsed(parsed) => project_and_apply(
                db,
                &event_id,
                &parsed,
                Some(inner_events[idx].workspace_id),
            )?,
        };
        out.push(InnerEventResult {
            event_id,
            disposition,
        });
    }
    Ok(())
}

/// Bulk-load the existing `(event_id -> status)` map for a slice of
/// candidate event_ids. Returns one row per id that is already in
/// `events_canonical`. Missing ids are simply absent from the map.
fn load_existing_statuses(
    db: &Connection,
    event_ids: &[BlakeId],
) -> rusqlite::Result<std::collections::HashMap<BlakeId, EventStatus>> {
    let mut out = std::collections::HashMap::with_capacity(event_ids.len());
    if event_ids.is_empty() {
        return Ok(out);
    }
    // Build `IN (?, ?, ?, ...)` placeholders. SQLITE_MAX_VARIABLE_NUMBER
    // is at least 32k since 3.32; the chain caps the chunk well below.
    let placeholders: Vec<String> = (1..=event_ids.len()).map(|i| format!("?{}", i)).collect();
    let sql = format!(
        "SELECT event_id, status FROM events_canonical WHERE event_id IN ({})",
        placeholders.join(",")
    );
    let bound: Vec<Box<dyn rusqlite::types::ToSql>> = event_ids
        .iter()
        .map(|id| -> Box<dyn rusqlite::types::ToSql> { Box::new(id.to_vec()) })
        .collect();
    let refs: Vec<&dyn rusqlite::types::ToSql> = bound.iter().map(|b| &**b).collect();
    let mut stmt = db.prepare(&sql)?;
    let mut rows = stmt.query(refs.as_slice())?;
    while let Some(r) = rows.next()? {
        let id_blob: Vec<u8> = r.get(0)?;
        if id_blob.len() != 32 {
            continue;
        }
        let status_str: String = r.get(1)?;
        let status = match EventStatus::parse(&status_str) {
            Some(s) => s,
            None => continue,
        };
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_blob);
        out.insert(id, status);
    }
    Ok(out)
}

pub(super) fn project_and_apply(
    db: &Connection,
    event_id: &BlakeId,
    parsed: &ParsedEvent,
    workspace_id: Option<WorkspaceId>,
) -> Result<InnerEventDisposition, ChainError> {
    // Special case: encrypted events are decrypted-and-recursed into the
    // inner canonical bytes. The encrypted module's `project_pure` is a
    // sentinel that returns Reject — the chain must handle decrypt before
    // ever reaching projector dispatch (plan.md wave-1 encrypted path).
    if let ParsedEvent::Encrypted(ev) = parsed {
        return apply_encrypted(db, event_id, ev, workspace_id);
    }

    let type_code = parsed.event_type_code();
    let meta = match registry().lookup(type_code) {
        Some(m) => m,
        None => {
            let reason = format!("unknown event type code {}", type_code);
            set_status(db, event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            return Ok(InnerEventDisposition::Rejected { reason });
        }
    };

    // Step 3d: get_context. Generic loader reads {event, deps, labels}
    // from `events_canonical` and `labels`, with no per-event-type SQL
    // (plan.md lines 234-240). Other ContextSnapshot fields are left at
    // their default — projectors that need bootstrap_context,
    // signer_user_mismatch_reason, or any other legacy field will be
    // migrated in Stage 2 (#9). Per plan.md: if a projector needs more
    // state, that state must arrive as a declared dependency or a
    // label.
    let ctx = match crate::state::generic_context::load_generic_context(parsed, db) {
        Ok(c) => c,
        Err(e) => {
            // Surface as a DB error — the chain rolls back its
            // transaction. Encode failures shouldn't occur for an
            // already-admitted event but are mapped to the same path.
            return Err(match e {
                crate::state::generic_context::GenericContextError::Db(err) => {
                    ChainError::Db(err)
                }
                crate::state::generic_context::GenericContextError::Encode(msg) => {
                    ChainError::Db(rusqlite::Error::ToSqlConversionFailure(msg.into()))
                }
            });
        }
    };

    // Step 3e: project. Per plan.md Stage 2 (translation rule 4),
    // projectors no longer take a `recorded_by: &str` parameter.
    // They derive their workspace context from the parsed event
    // itself (or use a sentinel for the legacy `recorded_by` column
    // until Stage 3 drops it).
    let event_id_b64 = base64_id(event_id);
    let result: ProjectorResult = (meta.projector)(&event_id_b64, parsed, &ctx);

    match result.decision {
        ProjectionDecision::Valid => {
            // Step 3f-Apply: write_ops, then mark applied.
            execute_write_ops(db, &result.write_ops).map_err(ChainError::WriteOps)?;
            set_status(db, event_id, EventStatus::Applied).map_err(ChainError::Db)?;
            // Step 3g: unblock dependents but do NOT recurse — they go
            // on the events.status=ready queue.
            let _newly_ready =
                unblock_dependents(db, event_id).map_err(ChainError::Db)?;
            // Connection-event post-apply: derive secrets + endpoints +
            // bootstrap a Compare. This runs inside the same transaction
            // as the apply so the rows commit atomically with the event.
            if let ParsedEvent::Connection(c) = parsed {
                let now_ms_local = c.created_at_ms as i64;
                let local_endpoint_id = crate::runtime::control_loop::OutboxWakeContext::current()
                    .map(|ctx| ctx.local_endpoint_id)
                    .unwrap_or([0u8; 32]);
                crate::event_modules::connection::post_apply::apply_connection_post(
                    db,
                    c,
                    &local_endpoint_id,
                    now_ms_local,
                )
                .map_err(ChainError::Db)?;
            }
            // Phase: incremental sync-state maintenance. Only durable rows
            // participate in the negentropy/dep-cache fingerprint — local
            // and endpoint-local rows are not part of the durable graph
            // (plan.md lines 374-385).
            apply_sync_maintenance(db, event_id, workspace_id)?;
            Ok(InnerEventDisposition::Applied)
        }
        ProjectionDecision::Block { missing } => {
            // `add_blockers` short-circuits on empty `missing` and
            // does not touch status — flip the row to `blocked`
            // directly so the events_canonical lifecycle reflects
            // the projector's verdict either way.
            if missing.is_empty() {
                set_status(db, event_id, EventStatus::Blocked).map_err(ChainError::Db)?;
            } else {
                add_blockers(db, event_id, &missing).map_err(ChainError::Db)?;
            }
            Ok(InnerEventDisposition::Blocked {
                missing_deps: missing,
            })
        }
        ProjectionDecision::Reject { reason } => {
            set_status(db, event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            Ok(InnerEventDisposition::Rejected { reason })
        }
        ProjectionDecision::AlreadyProcessed => {
            // Treat as Applied for status — the projector signalled
            // idempotent no-op. Still run unblock_dependents in case the
            // earlier apply happened in a now-forgotten transaction.
            set_status(db, event_id, EventStatus::Applied).map_err(ChainError::Db)?;
            let _newly_ready =
                unblock_dependents(db, event_id).map_err(ChainError::Db)?;
            apply_sync_maintenance(db, event_id, workspace_id)?;
            Ok(InnerEventDisposition::Applied)
        }
    }
}

/// Apply a list of projector `WriteOp`s. Mirror of
/// `state::projection::apply::write_exec::execute_write_ops` (which is
/// `pub(crate)` in a different submodule). Kept inline so this module is
/// self-contained.
fn execute_write_ops(conn: &Connection, ops: &[WriteOp]) -> rusqlite::Result<()> {
    for op in ops {
        match op {
            WriteOp::InsertOrIgnore {
                table,
                columns,
                values,
            } => {
                let cols = columns.join(", ");
                let placeholders: Vec<String> =
                    (1..=values.len()).map(|i| format!("?{}", i)).collect();
                let sql = format!(
                    "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                    table,
                    cols,
                    placeholders.join(", ")
                );
                let bound: Vec<Box<dyn rusqlite::types::ToSql>> = values
                    .iter()
                    .map(|v| -> Box<dyn rusqlite::types::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let refs: Vec<&dyn rusqlite::types::ToSql> = bound.iter().map(|b| &**b).collect();
                conn.execute(&sql, refs.as_slice())?;
            }
            WriteOp::Delete {
                table,
                where_clause,
            } => {
                let conds: Vec<String> = where_clause
                    .iter()
                    .enumerate()
                    .map(|(i, (c, _))| format!("{} = ?{}", c, i + 1))
                    .collect();
                let sql = format!("DELETE FROM {} WHERE {}", table, conds.join(" AND "));
                let bound: Vec<Box<dyn rusqlite::types::ToSql>> = where_clause
                    .iter()
                    .map(|(_, v)| -> Box<dyn rusqlite::types::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let refs: Vec<&dyn rusqlite::types::ToSql> = bound.iter().map(|b| &**b).collect();
                conn.execute(&sql, refs.as_slice())?;
            }
        }
    }
    Ok(())
}
