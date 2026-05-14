//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Each worker exposes one
//! synchronous `run` function over a small `Work` enum. Callers provide the
//! schedule by choosing which worker receives the next bounded work item.
//!
//! Implementations live in this directory so reviewers can see every active
//! queue/status/index drain in one place. `pipeline_helpers::event_pipeline` is shared
//! machinery, not a scheduled worker. Event modules own event syntax, semantic
//! schemas, commands, and projectors; workers own bounded movement between
//! explicit inputs and outputs.
//!
//! See `src/workers/README.md` for the universal worker contract, queue list,
//! and caller-owned scheduling rules.

use std::cell::Cell;

use crate::core::daemon::Worker;
use crate::core::store::Store;
use crate::protocol::event_modules::content::message_deletion;

pub mod connection;
pub mod content_purge;
pub mod dependency_unblock;
pub mod disappearing_floor_dispatcher;
pub mod disappearing_minute_expiry;
pub mod encryption;
pub mod event_admission;
pub mod event_projection;
pub(crate) mod pipeline_helpers;
pub mod schema;
pub mod sync;
pub mod transit_in;
pub mod transit_out;

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
    /// want to wipe the same time-tree internals — a guaranteed tombstone
    /// row-value conflict. Setting this flag on entry and clearing on exit
    /// turns nested invocations into a no-op so the outer drain can finish
    /// its retire walks and queue-row cleanup before the next caller runs.
    static IN_CONTENT_PURGE_DRAIN: Cell<bool> = const { Cell::new(false) };
}

/// Drain pending content-purge work triggered during admission.
///
/// The deletion projector writes a `content.purge_instructions` row whenever
/// a signed deletion fact is admitted. This helper observes that row and
/// runs `content_purge::Drain` once so any in-process admission path — the
/// inline `delete-message` call, a one-shot sync invocation, a scripted
/// batch, or the daemon's `event_admission` step — reaches the same
/// forward-secrecy end state without depending on a separately scheduled
/// daemon tick. The daemon's belt-and-suspenders worker remains in
/// `daemon_workers()` for any path this hook misses, and the queue rows
/// survive a crash so a restart can re-drain them.
///
/// Re-entrancy: returns immediately if a content-purge drain is already
/// running on this thread. See `IN_CONTENT_PURGE_DRAIN` for why.
pub fn drain_post_admission_purge_pending<R>(store: &Store, registry: &R) -> Result<(), String>
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

/// Protocol context required by daemon worker descriptors.
pub trait DaemonWorkerContext: pipeline_helpers::event_pipeline::EventRegistry {
    fn store(&self) -> &Store;
    fn sync_index(&self) -> &crate::protocol::event_modules::sync::SyncIndex;
}

pub fn daemon_workers<C>() -> Vec<Worker<C>>
where
    C: DaemonWorkerContext,
{
    vec![
        transit_in::daemon_worker(),
        event_admission::daemon_worker(),
        event_projection::daemon_worker(),
        dependency_unblock::daemon_worker(),
        encryption::daemon_worker(),
        content_purge::daemon_worker(),
        // Per-message TTL retirements first; the cover-horizon chop in the
        // next worker subsumes any per-leaf tombstones whose minutes fall
        // under the new floor, so running expiry first minimizes transient
        // state.
        disappearing_minute_expiry::daemon_worker(),
        disappearing_floor_dispatcher::daemon_worker(),
        connection::daemon_worker(),
        // The sync tick drains the negentropy pending-purge queue as its
        // first step (one place owns every `SyncIndex` mutation), then
        // does its response-producing work over an index that no longer
        // references purged ids.
        sync::daemon_worker(),
        transit_out::daemon_worker(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_worker_catalog_lists_named_workers() {
        let names: Vec<&'static str> = daemon_workers::<TestContext>()
            .iter()
            .map(|w| w.name)
            .collect();
        assert!(names.contains(&"transit_in"));
        assert!(names.contains(&"connection"));
        assert!(names.contains(&"encryption"));
        assert!(names.contains(&"sync_tick"));
        assert!(names.contains(&"transit_out"));
        // The negentropy purge drainer is folded into the sync tick as
        // an internal step, so the catalog no longer enumerates it as a
        // separate worker.
        assert!(!names.contains(&"negentropy_purge_drainer"));
        assert!(!names.contains(&"peer_supervisor"));
    }

    #[test]
    fn sync_tick_runs_after_disappearing_floor_dispatcher() {
        // The sync tick's first step drains the negentropy pending
        // purge queue, so the dispatcher (which writes purge rows
        // during a chop) must run before sync to keep the same
        // schedule property the standalone drainer used to provide.
        let names: Vec<&'static str> = daemon_workers::<TestContext>()
            .iter()
            .map(|w| w.name)
            .collect();
        let floor = names
            .iter()
            .position(|n| *n == "disappearing_floor_dispatcher")
            .expect("disappearing_floor_dispatcher in catalog");
        let sync = names
            .iter()
            .position(|n| *n == "sync_tick")
            .expect("sync_tick in catalog");
        assert!(
            floor < sync,
            "sync_tick must run after the chop dispatcher so chop-emitted purge rows are drained from a single SyncIndex-owning worker"
        );
    }

    /// Test-only DaemonWorkerContext. Workers are never actually invoked here;
    /// the list is built only to surface their `name` field.
    struct TestContext;

    impl crate::workers::pipeline_helpers::event_pipeline::EventRegistry for TestContext {
        fn event_from_bytes(
            &self,
            _bytes: Vec<u8>,
        ) -> Result<crate::protocol::event_modules::types::EventRecord, String> {
            Err("not implemented".to_string())
        }

        fn project_network_in(
            &self,
            _store: &Store,
            _inbound: &crate::core::network_queues::InboundNetworkRow,
        ) -> Result<crate::workers::pipeline_helpers::event_pipeline::ProjectionOutput, String>
        {
            Err("not implemented".to_string())
        }

        fn record_from_canonical_in(
            &self,
            _store: &Store,
            _bytes: Vec<u8>,
            _receive: Option<crate::protocol::event_modules::types::ReceiveMetadata>,
            _provenance: Option<crate::workers::schema::TransitProvenance>,
        ) -> Result<crate::workers::pipeline_helpers::event_pipeline::ReceivedRecord, String>
        {
            Err("not implemented".to_string())
        }

        fn project_record(
            &self,
            _store: &Store,
            _event: &crate::workers::pipeline_helpers::event_pipeline::EventWithContext<'_>,
        ) -> Result<crate::workers::pipeline_helpers::event_pipeline::ProjectionDecision, String>
        {
            Err("not implemented".to_string())
        }
    }

    impl DaemonWorkerContext for TestContext {
        fn store(&self) -> &Store {
            unimplemented!("test context does not provide a store")
        }

        fn sync_index(&self) -> &crate::protocol::event_modules::sync::SyncIndex {
            unimplemented!()
        }
    }
}
