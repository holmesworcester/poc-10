//! Event projection worker.
//!
//! Inputs: `event_modules.ready_events`, `event_modules.pending_reprojections`.
//! State: event status, projector-owned rows, and generic event labels.
//! Step: load Applied direct-dependency context for ready events, run exactly
//! one event-module projector per event, and commit either Apply or WaitForDeps.
//! Outputs: projector rows and labels, `event_modules.recently_valid_events`,
//! `event_modules.pending_reprojections`, and
//! `event_modules.applied_shared_events` for shared events; WaitForDeps moves
//! the event back to Blocked and writes blocker edges.
//! Consume: ready rows and pending reprojection rows are consumed only inside
//! the same transaction that commits the projector decision.
//! Failure: projection errors abort the current event and leave it ready for a
//! later drain attempt.
//! Fairness: `Work::Drain { limit }` bounds one call.

use crate::core::daemon::{self, StepContext, Worker};
use crate::core::store::Store;
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, ApplyReadyReport, EventRegistry,
};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => pipeline::drain_ready_events(store, registry, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "event_projection",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    daemon::run_step(
        ctx,
        "project ready events",
        |app, limit| run(app.store(), app, Work::Drain { limit }),
        |report, daemon_report| {
            daemon_report.add("ready_events", report.applied_events);
            daemon_report.add("reprojected_events", report.reprojected_events);
            daemon_report.add("unblocked_events", report.unblocked_events);
        },
    )
}
