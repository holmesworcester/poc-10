//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Each worker exposes one
//! synchronous `run` function over a small `Work` enum. Callers provide the
//! schedule by choosing which worker receives the next bounded work item.
//!
//! Implementations live in this directory so reviewers can see every active
//! queue/status/index drain in one place. `pipeline_helpers::event_pipeline` is
//! shared machinery, not a scheduled worker. Event modules own event syntax, semantic
//! schemas, commands, and projectors; workers own bounded movement between
//! explicit inputs and outputs.
//!
//! This catalog is legacy production-path plumbing. New target behavior should
//! move to facts, `WakeLoop`, projectors, context matchers, and flat handlers
//! instead of adding worker entries here.

use super::{
    connection, content_purge, dependency_unblock, disappearing_floor_dispatcher,
    disappearing_minute_expiry, encryption, event_admission, event_projection, pipeline_helpers,
    sync, transit_in, transit_out,
};
use crate::core::store::Store;
use crate::legacy::daemon::Worker;

/// Protocol context required by daemon worker descriptors.
pub trait DaemonWorkerContext: pipeline_helpers::event_pipeline::EventRegistry {
    fn store(&self) -> &Store;
    fn sync_index(&self) -> &crate::legacy::protocol::event_modules::sync::SyncIndex;
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

    impl crate::legacy::workers::pipeline_helpers::event_pipeline::EventRegistry for TestContext {
        fn event_from_bytes(
            &self,
            _bytes: Vec<u8>,
        ) -> Result<crate::legacy::protocol::event_modules::types::EventRecord, String> {
            Err("not implemented".to_string())
        }

        fn project_network_in(
            &self,
            _store: &Store,
            _inbound: &crate::core::network_queues::InboundNetworkRow,
        ) -> Result<
            crate::legacy::workers::pipeline_helpers::event_pipeline::ProjectionOutput,
            String,
        > {
            Err("not implemented".to_string())
        }

        fn record_from_canonical_in(
            &self,
            _store: &Store,
            _bytes: Vec<u8>,
            _receive: Option<crate::legacy::protocol::event_modules::types::ReceiveMetadata>,
            _provenance: Option<crate::legacy::workers::queue_rows::TransitProvenance>,
        ) -> Result<crate::legacy::workers::pipeline_helpers::event_pipeline::ReceivedRecord, String>
        {
            Err("not implemented".to_string())
        }

        fn project_record(
            &self,
            _store: &Store,
            _event: &crate::legacy::workers::pipeline_helpers::event_pipeline::EventWithContext<'_>,
        ) -> Result<
            crate::legacy::workers::pipeline_helpers::event_pipeline::ProjectionDecision,
            String,
        > {
            Err("not implemented".to_string())
        }
    }

    impl DaemonWorkerContext for TestContext {
        fn store(&self) -> &Store {
            unimplemented!("test context does not provide a store")
        }

        fn sync_index(&self) -> &crate::legacy::protocol::event_modules::sync::SyncIndex {
            unimplemented!()
        }
    }
}
