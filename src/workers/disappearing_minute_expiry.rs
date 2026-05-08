//! Disappearing-minute expiry worker.
//!
//! Inputs: workspace TTL settings, the logical clock, sealed message rows.
//! State: per-event leaf rows + minute_node + sealed/plaintext message rows
//! + canonical event bytes. Step: when `logical_time` advances past a
//! stored message's authored `expires_at_minute`, retire that message's
//! per-event leaf (delegating to the encryption worker's existing
//! per-leaf retirement primitive), exact-row-delete the read-model rows,
//! and purge canonical bytes. Outputs: per-leaf tombstones written by the
//! encryption worker, plus row deletes.
//!
//! Slice 1 ships with per-leaf retirement: every expired message produces
//! its own leaf tombstone. The plan's "one tombstone per minute"
//! optimization is left for slice 3 (deletion summary monotonicity); the
//! retention/cover-summary contract is identical either way because both
//! peers retire the same set of leaves deterministically.
//!
//! Fairness: bounded by `ctx.options.work_limit`.

use crate::core::daemon::{StepContext, Worker};
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::content::message::schema as message_schema;
use crate::protocol::event_modules::content::message::types::{
    message_event_id_in_minute, UNIX_MINUTE_MS,
};
use crate::protocol::event_modules::identity::workspace::schema as workspace_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::encryption as encryption_worker;
use crate::workers::pipeline_helpers::event_pipeline::EventRegistry;
use crate::workers::pipeline_helpers::purging;
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpiryReport {
    pub retired_message_leaves: usize,
    pub purged_event_bytes: usize,
    pub deleted_message_rows: usize,
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "disappearing_minute_expiry",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let store = app.store();
    let report = run(
        store,
        app,
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("disappearing minute expiry: {err}"))?;
    ctx.report
        .add("disappearing_retired_leaves", report.retired_message_leaves);
    ctx.report
        .add("disappearing_purged_event_bytes", report.purged_event_bytes);
    Ok(())
}

/// Single public worker entrypoint. The daemon-step shim above and any
/// future ad-hoc test caller both go through this function.
pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<ExpiryReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => drain(store, registry, limit),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

fn drain<R>(store: &Store, registry: &R, limit: usize) -> Result<ExpiryReport, String>
where
    R: EventRegistry,
{
    let mut report = ExpiryReport::default();

    // No clock pinned ⇒ nothing expires. Slice 1 leaves clock advancement
    // to the daemon driver and tests that pin time explicitly.
    let Some(now_ms) = logical_clock::logical_time(store)? else {
        return Ok(report);
    };
    let now_minute = now_ms / UNIX_MINUTE_MS;

    let workspaces = workspace_schema::list_all(store)?;
    let mut expired_jobs: Vec<ExpireMessageJob> = Vec::new();

    for workspace in workspaces {
        if workspace.disappearing_ttl_minutes == 0 {
            continue;
        }
        let sealed = sealed_messages_for_workspace(store, workspace.workspace_id)?;
        for row in sealed {
            if row.expires_at_minute == u64::MAX {
                continue;
            }
            if row.expires_at_minute >= now_minute {
                continue;
            }
            // Recompute the deterministic per-event leaf coord. Both peers
            // re-derive it from the canonical message fields, so retiring
            // the same coord on every peer keeps the FS state convergent.
            let event_id_in_minute = message_event_id_in_minute(
                &row.workspace_id,
                &row.author_user_id,
                &row.removal_frontier_id,
                row.created_at_ms,
            );
            expired_jobs.push(ExpireMessageJob {
                workspace_id: row.workspace_id,
                removal_frontier_id: row.removal_frontier_id,
                created_at_ms: row.created_at_ms,
                event_id_in_minute,
                message_id: row.message_id,
            });
        }
    }

    let job_count = expired_jobs.len().min(limit);
    for job in expired_jobs.into_iter().take(job_count) {
        process_job(store, registry, &mut report, job)?;
    }

    Ok(report)
}

#[derive(Debug, Clone, Copy)]
struct ExpireMessageJob {
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
    message_id: EventId,
}

fn process_job<R: EventRegistry>(
    store: &Store,
    registry: &R,
    report: &mut ExpiryReport,
    job: ExpireMessageJob,
) -> Result<(), String> {
    // Delete the read-model and sealed rows + purge canonical bytes for
    // the expired message in one transaction. Mirrors the post-deletion
    // cleanup `content_purge` does for `message_deletion` events; the
    // disappearing path skips writing a deletion-fact event and simply
    // executes the same retention work driven by the clock.
    let messages_deleted = store
        .write_transaction(|tx_store| {
            let key = message_schema::message_key(job.workspace_id, job.message_id);
            let mut deleted = 0usize;
            deleted += tx_store
                .delete_table_rows_in_tx(message_schema::MESSAGES, vec![key.clone()])?
                as usize;
            tx_store
                .delete_table_rows_in_tx(message_schema::SEALED_MESSAGES, vec![key])?;
            purging::purge_event_storage_in_tx(tx_store, &job.message_id)?;
            Ok::<_, rusqlite::Error>(deleted)
        })
        .map_err(|err| format!("expire message cleanup: {err}"))?;
    report.deleted_message_rows += messages_deleted;

    // Retire the per-event leaf chain via the encryption worker. This
    // tombstones the leaf row, materializes splits to keep cover for any
    // surviving siblings in the minute, and purges retained leaf bytes.
    let output = encryption_worker::run(
        store,
        registry,
        encryption_worker::Work::RetireDeletedEventLeaf {
            workspace_id: job.workspace_id,
            removal_frontier_id: job.removal_frontier_id,
            created_at_ms: job.created_at_ms,
            event_id_in_minute: job.event_id_in_minute,
        },
    )
    .map_err(|err| format!("retire expired-minute leaf: {err}"))?;
    let encryption_worker::Output::RetiredDeletedEventLeaf(retired) = output else {
        return Err("unexpected encryption worker output retiring expired leaf".to_string());
    };
    if retired.leaf_id.is_some() {
        report.retired_message_leaves += 1;
    }
    report.purged_event_bytes += retired.purged_event_bytes;
    Ok(())
}

fn sealed_messages_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<message_schema::SealedMessageRow>, String> {
    Ok(message_schema::list_sealed(store, usize::MAX)?
        .into_iter()
        .filter(|row| row.workspace_id == workspace_id)
        .collect())
}
