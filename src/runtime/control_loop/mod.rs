//! # Control Loop
//!
//! ## Purpose
//! The control loop is the runtime substrate. It claims one [`WorkItem`] at
//! a time, opens a transaction, dispatches to the registered handler for that
//! kind, and commits — nothing else. It is the only writer in the system.
//! Domain behavior (sync, bootstrap, auth, dependency policy, event-type
//! semantics) lives above this layer in event modules and job modules
//! (`plan.md` lines 53-188).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the [`ModuleRegistry`] mapping `WorkItemKind -> StepHandler`,
//! - queue storage and per-row leases (see [`queue`]),
//! - the single-writer transaction boundary,
//! - clock ticks and resource limits,
//! - effect runners for TCP egress and local IO via [`transport_bridge`].
//!
//! Does NOT own:
//! - any sync, gossip, or peering policy,
//! - connection bring-up, key derivation, or auth (lives in
//!   `event_modules::connection`),
//! - dependency / blocker semantics (lives in
//!   [`crate::state::events_canonical`]),
//! - event parsing, projection, or wire layout (lives in `event_modules`).
//!
//! ## Interfaces
//! - [`dispatch_step`] — claim-free dispatch of one [`WorkItem`] against a
//!   [`ModuleRegistry`] inside a [`StepContext`].
//! - [`ModuleRegistry`] / [`StepHandler`] — handler registration surface.
//! - [`StepResult`], [`Effects`], [`QueueWrites`], [`StateUpdates`] — the
//!   single value a handler returns; the dispatcher applies it to the queue
//!   and the DB.
//! - [`claim_one`] / [`mark_done`] / [`mark_failed`] / [`requeue`] /
//!   [`release_lease`] — durable work-queue surface.
//! - [`handle_inbound_bytes`] / [`handle_ready_event`] — chained step
//!   entrypoints for the `InboundBytes` and `ReadyEvent` work kinds.
//! - [`run_transport_bridge`] — fans inbound TCP frames into the queue.
//! - [`register_default_handlers`] — wires the default handler for every
//!   `WorkItemKind`.
//!
//! ## State
//! - `work_queue` (legacy table; see [`queue`]) — durable rows for
//!   `InboundBytes` payloads. `ReadyEvent` and `OutboxWake` work flows
//!   through `events_canonical.status = 'ready'` and the `outbox` table
//!   respectively rather than this queue (`plan.md` line 79-87).
//! - In-process [`ModuleRegistry`] held by the daemon.
//! - Transient `OutboxWakeContext` and per-connection `ConnectionSender`s
//!   live behind a `OnceLock` — see
//!   [`default_handlers::OutboxWakeContext`].
//!
//! ## Invariants
//! - One [`WorkItem`] is processed in exactly one DB transaction. Either
//!   every [`StepResult`] effect commits, or none does.
//! - The control loop is the only writer; handlers never spawn their own
//!   writer.
//! - `WorkItem` has exactly four variants — `InboundBytes`, `ReadyEvent`,
//!   `OutboxWake`, `JobTick`. Refactors must preserve that.
//! - `OutboundFrame` is a transit-only type: it is never queued, only
//!   minted by `event_modules::connection::wrap{,_bootstrap}` and consumed
//!   by `transport_v2::send`.
//!
//! ## Flow
//! ```text
//!   TCP listener --> InboundBytes work item --> [claim] --> handler chain
//!                                                              |
//!                  events_canonical.status='ready' <------------+
//!                          |                                    |
//!                       ReadyEvent ------> [claim] --> project/apply
//!                                                              |
//!                          outbox(connection_id, event_id) <----+
//!                          |
//!                       OutboxWake -----> [claim] --> ConnectionSender
//!                                                          |
//!                                                       wrap + send (TCP)
//! ```
//!
//! ## Failure / restart behavior
//! - On crash mid-step the open transaction is rolled back; no partial
//!   effect persists.
//! - On restart, transient row statuses are reset by
//!   [`crate::state::startup_recovery`]: `events_canonical.processing ->
//!   ready` and `inbound_bytes.processing -> pending`. The in-memory
//!   `outbox` is rebuilt by sync.
//! - A handler that returns `Err` releases the queue lease; the row is
//!   eligible to be claimed again. Repeat failure ultimately marks the
//!   row `failed` (see [`mark_failed`]).
//!
//! ## Performance notes
//! - One transaction per work item is the bound on commit cost. Handlers
//!   keep their own internal batching where it matters (the inbound chain
//!   coalesces all per-frame effects under one tx; the sender wraps up to
//!   `DEFAULT_FRAME_BATCH` events into one outbound frame).
//! - `OutboxWake` deduplicates by `connection_id` at the queue layer so a
//!   slow peer can't flood the queue.
//! - Per-connection `ConnectionSender`s isolate backpressure: a slow peer
//!   pauses only its own refill (`plan.md` line 211).
//!
//! ## Testing hooks
//! - `tests/control_loop_*.rs` — integration coverage for inbound chain and
//!   outbox drain.
//! - Unit tests in submodules (notably `default_handlers::tests` and
//!   `inbound_step::tests`) exercise the dispatcher under in-memory
//!   SQLite.

pub mod default_handlers;
pub mod dispatcher;
pub mod dispatcher_loop;
pub mod inbound_step;
pub mod queue;
pub mod runtime;
pub mod sender_actor;
pub mod step;
pub mod transport_bridge;
pub mod wake_bus;
pub mod work_item;

pub use default_handlers::{
    inbound_bytes_handler, job_tick_stub, outbox_wake_handler, ready_event_handler,
    register_default_handlers, OutboxWakeContext, OUTBOX_WAKE_HIGH_WATER_BYTES,
    OUTBOX_WAKE_LOW_WATER_BYTES, OUTBOX_WAKE_RETRY_BACKOFF_MS,
};
pub use dispatcher::{step as dispatch_step, ModuleRegistry, StepContext, StepHandler};
pub use inbound_step::{
    handle_inbound_bytes, handle_ready_event, ChainError, InboundOrigin, InboundOutcome,
    InnerEventDisposition, InnerEventResult,
};
pub use queue::{
    claim_one, ensure_schema, mark_done, mark_failed, release_lease, requeue, ClaimedWork,
    QueueRow,
};
pub use runtime::{ControlLoopHandles, ControlLoopRuntime, RuntimeError};
pub use transport_bridge::{
    forward_deliveries, install_transport_bridge_in_runtime, run_transport_bridge, BridgeError,
    InboundFrame, InstalledTransportBridge,
};
pub use step::{Effects, QueueWrites, StateUpdates, StepResult};
pub use work_item::{
    BlakeId, ConnectionId, EndpointId, InboundBytes, JobTick, OutboxWake, ReadyEvent, WorkItem,
    WorkItemKind, WorkspaceId,
};
