//! SQL-backed runtime pipeline.
//!
//! Core's runtime is a set of SQLite-backed queues. This facade exposes the
//! queue entry points; concrete modules own their storage dependencies.
//!
//! - `admission`: submit and purge facts, plus externally projected context.
//! - `fact_context`: wake due facts and run the fact/context fixed-point loop.
//! - `projection`: claim one pending fact and commit projection effects.
//! - `dispatch`: claim one intent and commit handler intent output.
//! - `effects`: validation and SQL commit helpers for shared core effects.

mod admission;
pub(crate) mod context;
mod dispatch;
mod effects;
mod fact_context;
mod projection;

/// Public outcome returned by runtime pipeline calls.
///
/// Runtime callers only need to know whether a bounded pass moved work forward
/// and whether any handler asked to retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkStatus {
    pub progressed: bool,
    pub retried: bool,
}

impl WorkStatus {
    pub fn idle() -> Self {
        Self::default()
    }

    pub fn progressed(progressed: bool) -> Self {
        Self {
            progressed,
            retried: false,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.progressed |= other.progressed;
        self.retried |= other.retried;
    }

    pub fn is_idle(self) -> bool {
        !self.progressed && !self.retried
    }
}

pub(crate) use admission::{
    commit_projected_context_offers, purge_fact_from_store, submit_fact_to_store,
    submit_facts_to_store,
};
pub(crate) use dispatch::{
    dispatch_queued_intent, next_queued_intent, submit_intent_to_store,
    submit_local_intent_to_store,
};
pub(crate) use effects::commit_pipeline_effects_to_store;
pub(crate) use fact_context::{drain_pending_projection, process_due_time_range};
pub(crate) use projection::ProjectionProgress;
