//! SQL-backed runtime pipeline.
//!
//! Core's runtime is a set of SQLite-backed queues. This facade exposes the
//! queue entry points that `Runtime` is allowed to call while keeping concrete
//! storage dependencies in worker modules. Callers submit facts and intents,
//! admit due time ranges, drain pending projection, dispatch queued handlers,
//! and purge exact facts through this boundary.
//!
//! The important invariant is that each worker owns its own atomic commit
//! boundary. Projection workers do not delete a pending row until replacement
//! context and effects commit. Dispatch workers do not delete an intent row
//! until handler output commits. The facade reports only whether a bounded pass
//! progressed or retried; it does not expose protocol meaning or partial worker
//! state.
//!
//! Change this file when the public runtime pipeline vocabulary changes. Change
//! the submodules when queue ordering, context fanout, handler dispatch, effect
//! commits, or checked fanout SQL changes. Protocol policy, fact decoding, row
//! meaning, and network-frame interpretation belong in protocol scopes.
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
    dispatch_queued_intent, dispatch_queued_intent_filtering_intents, next_queued_intent,
    submit_intent_to_store, submit_local_intent_to_store,
};
pub(crate) use project_pending_facts::{
    commit_projected_context_offers, drain_pending_projection,
    drain_pending_projection_filtering_intents, process_due_time_range, purge_fact_from_store,
    submit_fact_to_store, submit_facts_to_store, ProjectionProgress,
};
