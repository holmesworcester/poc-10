//! Sync-state maintenance hooks invoked after a durable apply.
//!
//! `apply_sync_maintenance` runs the negentropy / dep-cache update for an
//! `events_canonical` row that has just transitioned to `applied`, but
//! only when the row's scope is `Durable`. Local and endpoint-local rows
//! do not participate in the durable graph fingerprint
//! (plan.md lines 374-385).

use rusqlite::{params, Connection, OptionalExtension};

use crate::event_modules::sync::maintenance as sync_maintenance;
use crate::state::events_canonical::{get_workspace_id, EventScope};

use super::super::work_item::{BlakeId, WorkspaceId};
use super::ChainError;

/// Run the sync-state maintenance hooks (`negentropy_tree` +
/// `dep_cache`) for `event_id` iff it is `EventScope::Durable`. The chain
/// already ran inside one transaction so the maintenance writes commit
/// atomically with the apply.
///
/// `workspace_id` is `None` when the caller is `handle_ready_event`. In
/// that case we read it directly from `events_canonical.workspace_id`,
/// which `finalize_admitted` populated when the row first transitioned
/// out of `processing`. If the column is still NULL (legacy row, or a
/// scope/status mismatch), we skip silently — the apply itself is
/// unaffected.
pub(super) fn apply_sync_maintenance(
    db: &Connection,
    event_id: &BlakeId,
    workspace_id: Option<WorkspaceId>,
) -> Result<(), ChainError> {
    // Resolve the events_canonical scope. Maintenance is only correct for
    // durable rows.
    let scope_str: Option<String> = db
        .query_row(
            "SELECT scope FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| r.get(0),
        )
        .optional()
        .map_err(ChainError::Db)?;
    let scope = match scope_str.as_deref().and_then(EventScope::parse) {
        Some(s) => s,
        // Unknown scope — skip rather than guess. This mostly affects
        // legacy rows.
        None => return Ok(()),
    };
    if scope != EventScope::Durable {
        return Ok(());
    }

    // Recover workspace_id from the explicit caller hint, falling back to
    // `events_canonical.workspace_id` (populated by finalize_admitted on
    // the first transition out of `processing`).
    let ws = match workspace_id {
        Some(w) => w,
        None => match get_workspace_id(db, event_id).map_err(ChainError::Db)? {
            Some(w) => w,
            None => return Ok(()),
        },
    };

    sync_maintenance::after_durable_apply(&ws, event_id, db).map_err(ChainError::Db)?;
    Ok(())
}
