//! `StepResult` per `plan.md` lines 86-92.
//!
//! A module returns `StepResult { state_updates, queue_writes, effects }` and
//! the control loop commits state + queue in one transaction, then runs the
//! effects. Effects may enqueue more work but never project events directly.

use super::work_item::{EndpointId, WorkItem};

/// Pending mutations to in-DB tables. Phase 1: opaque payload — modules
/// produce SQL fragments / row tuples through their own `apply` step. The
/// shape will get nailed down once we wire actual projectors against this
/// substrate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateUpdates {
    /// Event ids to hard-purge.
    pub purges: Vec<[u8; 32]>,
    /// New rows. `(table_name, row_payload)` — `row_payload` is opaque to the
    /// control loop; the dispatcher routes it to the table-owning module's
    /// apply path.
    ///
    /// TODO(plan.md): replace `Vec<u8>` with a typed row enum once the
    /// projector contract is migrated to this substrate (see
    /// `state::pipeline`).
    pub new_rows: Vec<(String, Vec<u8>)>,
}

impl StateUpdates {
    pub fn is_empty(&self) -> bool {
        self.purges.is_empty() && self.new_rows.is_empty()
    }

    pub fn merge(&mut self, other: StateUpdates) {
        self.purges.extend(other.purges);
        self.new_rows.extend(other.new_rows);
    }
}

/// Items to enqueue (the only mechanism for advancing work between stages).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueWrites {
    pub items: Vec<WorkItem>,
}

impl QueueWrites {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn push(&mut self, item: WorkItem) {
        self.items.push(item);
    }

    pub fn extend<I: IntoIterator<Item = WorkItem>>(&mut self, items: I) {
        self.items.extend(items);
    }
}

/// External effects: side effects the control loop runs *after* the
/// state+queue commit. Adding a new effect type means the control loop has to
/// learn how to run it, so this enum stays small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effects {
    /// Hand a wrapped frame to the transport layer.
    TransportSend {
        remote_endpoint_id: EndpointId,
        frame: super::super::transport_v2::OutboundFrame,
    },
    /// Notify a job runner to schedule a follow-up tick. (Stub for now.)
    /// TODO(plan.md): finalize the scheduling shape — does this go through
    /// the queue with a delay, or via a separate timer wheel?
    ScheduleAt {
        job_name: String,
        at_ms: i64,
    },
    /// Diagnostic: ignore-but-record. Used by tests / sims.
    Noop,
}

/// What a module returns from `step`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepResult {
    pub state_updates: StateUpdates,
    pub queue_writes: QueueWrites,
    pub effects: Vec<Effects>,
}

impl StepResult {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_queue(items: Vec<WorkItem>) -> Self {
        Self {
            queue_writes: QueueWrites { items },
            ..Self::default()
        }
    }

    pub fn with_effect(effect: Effects) -> Self {
        Self {
            effects: vec![effect],
            ..Self::default()
        }
    }
}

