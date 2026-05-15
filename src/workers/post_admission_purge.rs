//! Post-admission purge hook.

use std::cell::Cell;

use crate::core::store::Store;
use crate::protocol::event_modules::content::message_deletion;

use super::{content_purge, pipeline_helpers, schema};

thread_local! {
    /// Re-entrancy guard for the content-purge post-admission hook.
    ///
    /// The purge worker's post-commit retire step runs the encryption worker's
    /// `RetireDeletedEventLeaf`, which internally drains ready events through
    /// `AdmitAndDrain`. That drain calls every registered post-admission hook,
    /// including this one. Without a guard, an unprocessed cascade row in
    /// `content.purge_instructions` (file/slice rows enqueued during the
    /// message branch) would re-enter `content_purge::run` while the message's
    /// retire walk is still in progress, racing two retire walks that both
    /// want to wipe the same time-tree internals -- a guaranteed tombstone
    /// row-value conflict. Setting this flag on entry and clearing on exit
    /// turns nested invocations into a no-op so the outer drain can finish
    /// its retire walks and queue-row cleanup before the next caller runs.
    static IN_CONTENT_PURGE_DRAIN: Cell<bool> = const { Cell::new(false) };
}

/// Drain pending content-purge work triggered during admission.
///
/// The deletion projector writes a `content.purge_instructions` row whenever
/// a signed deletion fact is admitted. This helper observes that row and
/// runs `content_purge::Drain` once so any in-process admission path -- the
/// inline `delete-message` call, a one-shot sync invocation, a scripted
/// batch, or the daemon's `event_admission` step -- reaches the same
/// forward-secrecy end state without depending on a separately scheduled
/// daemon tick. The daemon's belt-and-suspenders worker remains in
/// `daemon_workers()` for any path this hook misses, and the queue rows
/// survive a crash so a restart can re-drain them.
///
/// Re-entrancy: returns immediately if a content-purge drain is already
/// running on this thread. See `IN_CONTENT_PURGE_DRAIN` for why.
pub(crate) fn drain_post_admission_purge_pending<R>(
    store: &Store,
    registry: &R,
) -> Result<(), String>
where
    R: pipeline_helpers::event_pipeline::EventRegistry,
{
    if IN_CONTENT_PURGE_DRAIN.with(|cell| cell.get()) {
        return Ok(());
    }
    drain_pending_reprojections_until_idle(store, registry)?;
    if !message_deletion::queries::has_purge_instructions(store)? {
        return Ok(());
    }
    IN_CONTENT_PURGE_DRAIN.with(|cell| cell.set(true));
    let result = content_purge::run(
        store,
        registry,
        content_purge::Work::Drain {
            limit: pipeline_helpers::event_pipeline::DEFAULT_READY_BATCH,
        },
    );
    IN_CONTENT_PURGE_DRAIN.with(|cell| cell.set(false));
    result?;
    Ok(())
}

fn drain_pending_reprojections_until_idle<R>(store: &Store, registry: &R) -> Result<(), String>
where
    R: pipeline_helpers::event_pipeline::EventRegistry,
{
    let limit = pipeline_helpers::event_pipeline::DEFAULT_READY_BATCH;
    while store
        .table_row_count(schema::PENDING_REPROJECTIONS)
        .map_err(|err| format!("count pending reprojections: {err}"))?
        > 0
    {
        let report =
            pipeline_helpers::event_pipeline::drain_pending_reprojections(store, registry, limit)?;
        if report.reprojected_events == 0 {
            break;
        }
    }
    Ok(())
}
