//! Daemon/workspace uniqueness invariant.
//!
//! Plan.md line 114: "a daemon hosts at most one instance of any given
//! workspace, so workspace_id alone identifies the local processing scope
//! and there is no separate recorded_by."
//!
//! This module enforces that invariant in the mutating command paths
//! (`create_workspace_for_db`, `accept_invite`, `join_workspace_as_new_user`,
//! and the device-link flow) by guarding every new local-tenant binding
//! against pre-existing instances of the same workspace on this daemon.
//!
//! "Hosts" is defined here as: there is at least one row in
//! `invites_accepted` whose `workspace_id` matches. Because every local
//! tenant that joins or self-creates a workspace writes an
//! `InviteAccepted` event (which projects into the `invites_accepted`
//! table), this is a sufficient proxy for the durable local-tenant
//! binding. A single daemon may still host many distinct workspaces; it
//! is the *same* workspace_id appearing under more than one local tenant
//! that is forbidden.
//!
//! There is also a startup check (`check_workspace_uniqueness_on_startup`)
//! that scans `invites_accepted` and logs any pre-existing duplicate so
//! operators are alerted to legacy state that violates the new invariant.

use crate::crypto::{event_id_to_base64, EventId};
use rusqlite::Connection;

/// Workspace identifier for the uniqueness invariant. Matches the
/// runtime/control_loop alias and the `EventId` shape used throughout
/// the event modules.
pub type WorkspaceId = EventId;

/// Error returned when binding a new local tenant to `workspace_id`
/// would violate the daemon/workspace uniqueness invariant.
#[derive(Debug, Clone)]
pub struct EndpointWorkspaceUniquenessError {
    pub workspace_id: WorkspaceId,
    pub reason: String,
}

impl std::fmt::Display for EndpointWorkspaceUniquenessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "daemon already hosts workspace {}: {}",
            event_id_to_base64(&self.workspace_id),
            self.reason
        )
    }
}

impl std::error::Error for EndpointWorkspaceUniquenessError {}

/// Returns true if this daemon already hosts an instance of `workspace_id`.
///
/// "Hosts" means there is at least one local-tenant binding for that
/// workspace, materialized as a row in `invites_accepted`. The daemon
/// owns the database, so any row here represents a tenant that has
/// committed to the workspace via this endpoint.
pub fn endpoint_already_hosts_workspace(
    db: &Connection,
    workspace_id: &WorkspaceId,
) -> rusqlite::Result<bool> {
    let ws_b64 = event_id_to_base64(workspace_id);
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM invites_accepted WHERE workspace_id = ?1",
        rusqlite::params![&ws_b64],
        |row| row.get(0),
    )?;
    Ok(count >= 1)
}

/// Guard fn to call from mutating command paths before binding a new
/// local tenant to `workspace_id`. Returns `Err` if the workspace is
/// already hosted on this daemon.
pub fn assert_endpoint_can_host(
    db: &Connection,
    workspace_id: &WorkspaceId,
) -> Result<(), EndpointWorkspaceUniquenessError> {
    let already = endpoint_already_hosts_workspace(db, workspace_id).map_err(|e| {
        EndpointWorkspaceUniquenessError {
            workspace_id: *workspace_id,
            reason: format!("uniqueness probe failed: {}", e),
        }
    })?;
    if already {
        return Err(EndpointWorkspaceUniquenessError {
            workspace_id: *workspace_id,
            reason: "an existing local tenant is already bound to this workspace_id \
                     (plan.md line 114: at most one workspace instance per daemon endpoint)"
                .to_string(),
        });
    }
    Ok(())
}

/// Sanity check intended for `create_workspace_for_db`: the workspace_id
/// is freshly minted, so it must not already appear in any local table.
/// This catches the (vanishingly unlikely) collision case and any logic
/// bug that would re-emit a known workspace as new.
pub fn assert_endpoint_can_host_fresh(
    db: &Connection,
    workspace_id: &WorkspaceId,
) -> Result<(), EndpointWorkspaceUniquenessError> {
    assert_endpoint_can_host(db, workspace_id)
}

/// Startup check: scan `invites_accepted` for any workspace_id that has
/// been bound under more than one distinct `recorded_by` (i.e. legacy
/// multi-tenant state that pre-dates the new invariant). Logs a clear
/// error for each violating workspace; for poc-8/9 we log and return
/// `Ok(())` rather than refuse to start. Full quarantine semantics can
/// come later — the goal here is operator visibility, not data loss.
pub fn check_workspace_uniqueness_on_startup(db: &Connection) -> rusqlite::Result<()> {
    // `recorded_by` may be NULL on the new schema (it's a nullable
    // shadow column), so COUNT(DISTINCT recorded_by) collapses NULLs and
    // misses the legacy multi-tenant pattern in the all-NULL case. We
    // still want to flag legacy DBs that carry per-tenant rows. Group
    // and count; treat NULL as a single bucket distinct from any
    // non-NULL recorder.
    let mut stmt = match db.prepare(
        "SELECT workspace_id,
                COUNT(DISTINCT IFNULL(recorded_by, '')) AS distinct_recorders,
                COUNT(*) AS total_rows
         FROM invites_accepted
         WHERE workspace_id IS NOT NULL
         GROUP BY workspace_id
         HAVING distinct_recorders > 1 OR total_rows > 1",
    ) {
        Ok(s) => s,
        Err(e) => {
            // Schema not present (e.g. very early init) — nothing to check.
            tracing::debug!(
                "workspace uniqueness startup check skipped: {} (table likely absent)",
                e
            );
            return Ok(());
        }
    };

    let rows = stmt.query_map([], |row| {
        let workspace_id: String = row.get(0)?;
        let distinct_recorders: i64 = row.get(1)?;
        let total_rows: i64 = row.get(2)?;
        Ok((workspace_id, distinct_recorders, total_rows))
    })?;

    let mut violations = 0usize;
    for r in rows {
        match r {
            Ok((workspace_id, distinct_recorders, total_rows)) => {
                tracing::error!(
                    "workspace uniqueness violation at startup: workspace_id={} \
                     has {} distinct recorder(s) across {} invites_accepted row(s); \
                     plan.md line 114 requires at most one local-tenant binding per workspace. \
                     Quarantine semantics not yet implemented; logging only.",
                    workspace_id,
                    distinct_recorders,
                    total_rows
                );
                violations += 1;
            }
            Err(e) => {
                tracing::warn!("startup uniqueness scan row error: {}", e);
            }
        }
    }
    if violations == 0 {
        tracing::debug!("workspace uniqueness startup check passed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    fn seed_invite_accepted(
        db: &Connection,
        recorded_by: &str,
        event_id: &str,
        workspace_id: &str,
    ) {
        db.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, event_id, "tenant-evt", "invite-evt", workspace_id, 1i64],
        )
        .expect("insert invites_accepted");
    }

    #[test]
    fn endpoint_already_hosts_returns_false_for_unknown() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let ws: WorkspaceId = [0xAA; 32];
        let hosts = endpoint_already_hosts_workspace(&db, &ws).expect("probe");
        assert!(!hosts, "fresh DB must report no hosted workspace");

        assert_endpoint_can_host(&db, &ws).expect("guard must pass on fresh DB");
    }

    #[test]
    fn endpoint_already_hosts_returns_true_after_accept() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let ws: WorkspaceId = [0x33; 32];
        let ws_b64 = event_id_to_base64(&ws);
        seed_invite_accepted(&db, "tenant-A", "ia-1", &ws_b64);

        let hosts = endpoint_already_hosts_workspace(&db, &ws).expect("probe");
        assert!(hosts, "after invite_accepted insert the workspace must be reported as hosted");

        let err = assert_endpoint_can_host(&db, &ws)
            .expect_err("guard must reject the second binding");
        assert_eq!(err.workspace_id, ws);
        assert!(
            err.reason.contains("plan.md line 114"),
            "uniqueness error must reference plan.md line 114, got: {}",
            err.reason
        );
    }

    #[test]
    fn startup_check_logs_legacy_duplicates() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let ws: WorkspaceId = [0x44; 32];
        let ws_b64 = event_id_to_base64(&ws);
        // Two distinct recorders for the same workspace: legacy multi-tenant pattern.
        seed_invite_accepted(&db, "tenant-A", "ia-A", &ws_b64);
        seed_invite_accepted(&db, "tenant-B", "ia-B", &ws_b64);

        // Should log but not return Err.
        check_workspace_uniqueness_on_startup(&db).expect("startup check returns Ok");
    }
}
