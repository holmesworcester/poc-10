//! SQL-backed runtime pipeline.
//!
//! Core's runtime is a set of SQLite-backed queues. This facade exposes the
//! queue entry points; concrete modules own their storage dependencies.
//!
//! - `project_pending_facts`: enqueue facts, admit due time wakes, drain
//!   pending facts, and commit projection effects.
//! - `dispatch`: claim one intent and commit handler intent output.
//! - `commit_effects`: validation and SQL commit helpers for shared core effects.

mod commit_effects;
pub(crate) mod context;
mod dispatch;
mod insert_select;
mod project_pending_facts;

/// Public outcome returned by runtime pipeline calls.
///
/// Runtime callers only need to know whether a bounded pass moved work forward
/// and whether any handler asked to retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkStatus {
    /// Whether a bounded pass committed or staged any work.
    pub progressed: bool,
    /// Whether a handler asked to leave work queued for a later pass.
    pub retried: bool,
}

impl WorkStatus {
    /// No progress and no retry.
    pub fn idle() -> Self {
        Self::default()
    }

    /// Build status from a simple progressed flag.
    pub fn progressed(progressed: bool) -> Self {
        Self {
            progressed,
            retried: false,
        }
    }

    /// Accumulate status across pipeline stages.
    pub fn merge(&mut self, other: Self) {
        self.progressed |= other.progressed;
        self.retried |= other.retried;
    }

    /// Return whether the pass did nothing and hit no retry.
    pub fn is_idle(self) -> bool {
        !self.progressed && !self.retried
    }
}

pub(crate) use commit_effects::commit_pipeline_effects_to_store;
pub(crate) use dispatch::{
    dispatch_queued_intent, next_queued_intent, submit_intent_to_store,
    submit_local_intent_to_store,
};
pub(crate) use project_pending_facts::{
    commit_projected_context_offers, drain_pending_projection, process_due_time_range,
    purge_fact_from_store, submit_fact_to_store, submit_facts_to_store, ProjectionProgress,
};
