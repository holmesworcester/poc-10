//! Read-only views over the content purge queue tables.
//!
//! Scope: the cheap presence-check the post-admission hook uses to decide
//! whether to drain the content-purge worker before returning, plus
//! row-level reads needed by the worker drain and crash-recovery paths.
//! Writes (admitting an instruction, stamping retire coords, clearing
//! the queue rows after retire succeeds) belong to the projectors and
//! the worker.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::rows::{
    decode_purge_instruction, decode_purge_retire_coords, purge_instruction_key, PurgeInstruction,
    PurgeRetireCoords, PURGE_INSTRUCTIONS, PURGE_RETIRE_COORDS,
};

pub fn has_purge_instructions(store: &Store) -> Result<bool, String> {
    let any = store
        .table_rows_with_key_prefix(PURGE_INSTRUCTIONS, &[], 1)
        .map_err(|err| format!("load purge instructions: {err}"))?;
    Ok(!any.is_empty())
}

/// List a bounded batch of pending purge instructions in key order.
///
/// The worker uses this to drain at most `limit` instructions per tick.
/// Ordering is lexicographic on `(workspace_id, target_event_id)`, which
/// is good enough — drains are convergent regardless of dispatch order.
pub fn list_purge_instructions(
    store: &Store,
    limit: usize,
) -> Result<Vec<PurgeInstruction>, String> {
    store
        .table_rows_with_key_prefix(PURGE_INSTRUCTIONS, &[], limit)
        .map_err(|err| format!("load purge instructions: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_purge_instruction(&key, &value))
        .collect()
}

/// Read the retire coords stamped during the purge transaction for one
/// target event id. Returns `None` if no coords row was written (e.g. for
/// kinds that do not retire their own leaf, like reactions and file slices).
pub fn purge_retire_coords_for(
    store: &Store,
    workspace_id: EventId,
    target_event_id: EventId,
) -> Result<Option<PurgeRetireCoords>, String> {
    let key = purge_instruction_key(workspace_id, target_event_id);
    let value = store
        .table_row(PURGE_RETIRE_COORDS, &key)
        .map_err(|err| format!("load purge_retire_coords: {err}"))?;
    match value {
        Some(value) => Ok(Some(decode_purge_retire_coords(&key, &value)?)),
        None => Ok(None),
    }
}

/// List a bounded batch of pending retire-coords rows. The worker's
/// fix-up phase scans this on every drain so a retire walk that didn't
/// finish on a prior tick (crash, panic) gets a fresh attempt.
pub fn list_purge_retire_coords(
    store: &Store,
    limit: usize,
) -> Result<Vec<PurgeRetireCoords>, String> {
    store
        .table_rows_with_key_prefix(PURGE_RETIRE_COORDS, &[], limit)
        .map_err(|err| format!("load purge_retire_coords: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_purge_retire_coords(&key, &value))
        .collect()
}
