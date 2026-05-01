//! # Wake bus for the control-loop dispatcher
//!
//! Plan-rework D: replaces the polling workers in `runtime.rs` with a
//! single round-robin dispatcher that waits on a process-wide wake bus.
//! Each queue kind (Inbound, ReadyEvents, Outbox, Jobs) carries its own
//! `tokio::sync::Notify`. Producers (transport bridge, projectors that
//! emit ready events / outbox rows, the schedule tick) call the matching
//! `notify_*` method; the dispatcher's idle path waits on
//! `Wakes::any().notified()` and resumes immediately.
//!
//! The `Notify` semantics fit well: a `notified()` future resolves on the
//! NEXT `notify_one`/`notify_waiters`. A producer notification while no
//! one is waiting is "remembered" by `notify_one`, so a wake during a
//! busy round of the dispatcher isn't lost — the next idle wait sees it.
//!
//! See `plan.md` lines ~30 ("single-writer runtime substrate"), ~190
//! ("one process-wide control-loop writer").

use std::sync::Arc;

use tokio::sync::Notify;

/// Per-queue-kind wake handles. Held behind an `Arc` so producers can
/// signal from any task without a clone-of-channel-machinery cost.
#[derive(Default)]
pub struct WakeBus {
    /// Pending `inbound_bytes` rows ready for the dispatcher's inbound step.
    pub inbound: Notify,
    /// Pending `events_canonical.status='ready'` rows.
    pub ready: Notify,
    /// `outbox` row(s) freshly enqueued; the dispatcher's outbox step
    /// enumerates affected `connection_id`s and notifies their sender
    /// actor wake channels.
    pub outbox: Notify,
    /// Job scheduler tick (currently unused — kept for symmetry with plan).
    pub jobs: Notify,
    /// Locally-created event intents (CLI/RPC ingress). The dispatcher's
    /// `LocalEvents` step drains rows from `local_event_intents` whose
    /// `status = 'pending'`. RPC handlers wake the dispatcher after
    /// inserting an intent row so the round-robin pass picks it up
    /// without waiting for the next idle deadline.
    pub local_events: Notify,
}

impl WakeBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Notify the dispatcher that there is fresh inbound work. Idempotent:
    /// `Notify::notify_one` collapses repeated signals while no one is
    /// waiting into a single resume.
    pub fn notify_inbound(&self) {
        self.inbound.notify_one();
    }
    pub fn notify_ready(&self) {
        self.ready.notify_one();
    }
    pub fn notify_outbox(&self) {
        self.outbox.notify_one();
    }
    pub fn notify_jobs(&self) {
        self.jobs.notify_one();
    }
    pub fn notify_local_events(&self) {
        self.local_events.notify_one();
    }

    /// Notify all queue kinds — used on shutdown to release any pending
    /// `notified()` future and let the dispatcher observe `shutdown`.
    pub fn notify_all(&self) {
        self.inbound.notify_waiters();
        self.ready.notify_waiters();
        self.outbox.notify_waiters();
        self.jobs.notify_waiters();
        self.local_events.notify_waiters();
    }
}
