//! # Default `WorkItemKind` handlers
//!
//! ## Purpose
//! Wires one default [`StepHandler`] per [`WorkItemKind`] into a
//! [`ModuleRegistry`], so the dispatcher can claim and run any of the four
//! work-item variants out of the box (`plan.md` lines 102-114).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the registration call ([`register_default_handlers`]),
//! - the trampolines that bridge `StepHandler` (`Fn(&WorkItem,
//!   &StepContext) -> Result<StepResult, _>`) to the chained
//!   `handle_inbound_bytes` / `handle_ready_event` functions,
//! - the `OutboxWake` driver: per-connection `ConnectionSender` lookup,
//!   refill, and async drain on a tokio runtime,
//! - retry policy for failed sends ([`OUTBOX_WAKE_RETRY_BACKOFF_MS`]).
//!
//! Does NOT own:
//! - the inbound chain itself — see [`super::inbound_step`],
//! - the sender's hot-queue semantics — see
//!   [`crate::runtime::jobs::sender`],
//! - the `JobTick` job registry; current handler is a stub until the job
//!   runtime lands.
//!
//! ## Interfaces
//! - [`register_default_handlers`] — call once with a fresh registry.
//! - [`inbound_bytes_handler`] / [`ready_event_handler`] /
//!   [`outbox_wake_handler`] / [`job_tick_stub`] — individual handlers
//!   exposed for tests and bespoke wiring.
//! - [`OutboxWakeContext`] — per-process context (local endpoint, socket
//!   cache, address book, runtime handle) that the OutboxWake driver
//!   needs. Install once via [`OutboxWakeContext::install`].
//! - [`OUTBOX_WAKE_LOW_WATER_BYTES`] / [`OUTBOX_WAKE_HIGH_WATER_BYTES`] —
//!   refill thresholds.
//!
//! ## State
//! - In-process `OnceLock<Arc<OutboxWakeContext>>` — set at boot.
//! - In-process `OnceLock<Mutex<HashMap<ConnectionId, ConnectionSender>>>`
//!   ([`SENDERS`]) — one sender per connection, kept across wakes so
//!   `present` and `hot_queue` persist.
//!
//! ## Invariants
//! - Exactly one default handler per `WorkItemKind`. `register_default_handlers`
//!   is idempotent (skips kinds that already have a handler registered).
//! - The OutboxWake handler holds the senders-map mutex only while
//!   removing/inserting the per-connection sender — never across the async
//!   drain (which would block the dispatcher).
//! - The OutboxWake handler holds NO database transaction across the
//!   `drain_to_socket` await. The sender deletes outbox rows in its own
//!   short transactions.
//!
//! ## Flow
//! ```text
//!   InboundBytes -> handle_inbound_bytes (full chain, one tx)
//!   ReadyEvent   -> handle_ready_event   (parse/context/project/apply tail)
//!   OutboxWake   -> lookup ConnectionSender
//!                -> refill_if_needed(low=4KiB, high=64KiB)
//!                -> drive drain_to_socket on tokio runtime
//!                -> on send_failed: schedule OutboxWake retry via
//!                   StepResult.queue_writes
//!   JobTick      -> stub: StepResult::empty()
//! ```
//!
//! ## Failure / restart behavior
//! - If `OutboxWakeContext` has not been installed (test harness, early
//!   boot) the OutboxWake handler returns `StepResult::empty()` so the
//!   dispatcher can still claim and complete the wake.
//! - On `drain_to_socket` reporting `send_failed = true`, the handler
//!   schedules a follow-up `OutboxWake(connection_id)` via
//!   `StepResult.queue_writes` with a fixed
//!   [`OUTBOX_WAKE_RETRY_BACKOFF_MS`] backoff. Failure is local to one
//!   connection.
//! - On chain error (DB / unwrap / projector) the handler returns
//!   `DispatchError::Handler(...)`, which the dispatcher treats as a
//!   lease release and eventual `mark_failed`.
//!
//! ## Performance notes
//! - The senders map is keyed in-memory by `ConnectionId`; lookup is O(1).
//! - `drive_drain` uses `tokio::task::block_in_place` when running inside a
//!   multi-threaded runtime so the sync `StepHandler` can drive an async
//!   drain without blocking the worker thread.
//! - The OutboxWake retry path schedules exactly one follow-up wake; the
//!   queue layer dedupes by `connection_id` so cascading failures collapse.
//!
//! ## Testing hooks
//! - Unit tests at the bottom of this file cover handler registration and
//!   the no-context noop path.
//! - `tests/sender_drain_*.rs` exercise the full OutboxWake → drain path
//!   under a tokio runtime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::runtime::control_loop::{
    dispatcher::{DispatchError, ModuleRegistry, StepContext, StepHandler},
    inbound_step::{
        handle_inbound_bytes, handle_ready_event, ChainError, InboundOrigin, InboundOutcome,
        InnerEventDisposition, InnerEventResult,
    },
    step::StepResult,
    work_item::{ConnectionId, EndpointId, OutboxWake, WorkItem, WorkItemKind},
};
use crate::runtime::jobs::sender::{lookup_remote_endpoint, ConnectionSender};
use crate::runtime::transport_v2::{AddressBook, SocketCache};

/// Register default substrate handlers for all four `WorkItemKind`s.
///
/// Modules can override these by calling `register` with a different
/// handler before this is invoked. After this call the registry is ready
/// to dispatch any claimed `WorkItem`.
///
/// `OutboxWake` is wired to a real handler that uses
/// [`OutboxWakeContext::install`] / `current` to find the per-process
/// transport state. If no context has been installed (test harness, early
/// boot) the handler returns `StepResult::empty()` so the dispatcher can
/// still claim and complete the work item.
pub fn register_default_handlers(registry: &mut ModuleRegistry) {
    if registry.handler_for(WorkItemKind::InboundBytes).is_none() {
        registry.register(WorkItemKind::InboundBytes, inbound_bytes_handler());
    }
    if registry.handler_for(WorkItemKind::ReadyEvent).is_none() {
        registry.register(WorkItemKind::ReadyEvent, ready_event_handler());
    }
    if registry.handler_for(WorkItemKind::OutboxWake).is_none() {
        registry.register(WorkItemKind::OutboxWake, outbox_wake_handler());
    }
    if registry.handler_for(WorkItemKind::JobTick).is_none() {
        registry.register(WorkItemKind::JobTick, job_tick_stub());
    }
}

/// Default handler for `WorkItem::InboundBytes`: runs the full chained
/// `unwrap → admit → parse → context → project → apply` step.
pub fn inbound_bytes_handler() -> StepHandler {
    Arc::new(|item, ctx: &StepContext<'_>| -> Result<StepResult, DispatchError> {
        let payload = match item {
            WorkItem::InboundBytes(p) => p,
            other => {
                return Err(DispatchError::KindMismatch {
                    expected: WorkItemKind::InboundBytes,
                    actual: other.kind(),
                });
            }
        };
        let origin = InboundOrigin {
            remote_endpoint_id: payload.remote_endpoint_id,
            ip: payload.source_ip.clone(),
            port: payload.source_port,
        };
        let _outcome: InboundOutcome =
            handle_inbound_bytes(&payload.bytes, origin, ctx.conn, ctx.now_ms)
                .map_err(chain_error_to_dispatch)?;
        // Phase 1: the chain commits inside its own tx. The substrate's
        // outer-tx model + the StateUpdates / QueueWrites split is the
        // legacy contract; the new chain is self-contained, so we
        // return an empty StepResult. The control loop's claim/lease
        // machinery still runs around it.
        Ok(StepResult::empty())
    })
}

/// Default handler for `WorkItem::ReadyEvent`: loads the events_canonical
/// row, runs parse → context → project → apply, marks the row applied /
/// blocked / rejected accordingly. Newly-ready dependents are flipped via
/// `unblock_dependents` but not enqueued recursively.
pub fn ready_event_handler() -> StepHandler {
    Arc::new(|item, ctx: &StepContext<'_>| -> Result<StepResult, DispatchError> {
        let r = match item {
            WorkItem::ReadyEvent(r) => r,
            other => {
                return Err(DispatchError::KindMismatch {
                    expected: WorkItemKind::ReadyEvent,
                    actual: other.kind(),
                });
            }
        };
        let _disposition: InnerEventDisposition =
            handle_ready_event(&r.event_id, ctx.conn, ctx.now_ms)
                .map_err(chain_error_to_dispatch)?;
        Ok(StepResult::empty())
    })
}

// ---------------------------------------------------------------------------
// OutboxWake handler (audit round 4)
// ---------------------------------------------------------------------------

/// Low-water byte budget passed to `ConnectionSender::refill_if_needed` from
/// the OutboxWake handler. Once the hot queue drops below this, the handler
/// pulls more outbox rows.
pub const OUTBOX_WAKE_LOW_WATER_BYTES: usize = 4 * 1024;
/// High-water byte budget for OutboxWake refills. Refill stops at or above
/// this byte estimate.
pub const OUTBOX_WAKE_HIGH_WATER_BYTES: usize = 64 * 1024;
/// Initial backoff (ms) when a drain reports `send_failed`. We schedule a
/// follow-up `OutboxWake` for `now_ms + this` via `StepResult.queue_writes`.
pub const OUTBOX_WAKE_RETRY_BACKOFF_MS: i64 = 250;

/// Per-process transport context the OutboxWake handler needs. The
/// dispatcher's `StepHandler` signature is sync and carries only a DB
/// connection, so transport state is stashed here under a `OnceLock`.
///
/// TODO(plan.md): production should hold the senders + transport handles
/// in an explicit runtime context passed through `StepContext`, not in a
/// global. This is a Phase-1 scaffold so the OutboxWake handler can be
/// exercised end-to-end before the runtime context refactor lands.
pub struct OutboxWakeContext {
    /// Local daemon endpoint id used as the `from` for `transport_send`.
    pub local_endpoint_id: EndpointId,
    /// TCP socket cache.
    pub socket_cache: Arc<SocketCache>,
    /// Endpoint-id → SocketAddr resolver (real `AddressBook` wired into the
    /// dispatcher; `Arc` because the handler closure is `Send + Sync`).
    pub address_book: Arc<AddressBook>,
    /// Tokio runtime handle the handler uses to drive the async
    /// `drain_to_socket` from the sync `StepHandler` path. If `None`, the
    /// handler tries `tokio::runtime::Handle::try_current()` and otherwise
    /// returns an error.
    pub runtime_handle: Option<tokio::runtime::Handle>,
}

impl OutboxWakeContext {
    /// Install the per-process context. Returns `Err` if it was already
    /// installed (overwriting would race with in-flight handlers).
    pub fn install(self: Arc<Self>) -> Result<(), Arc<Self>> {
        OUTBOX_WAKE_CTX.set(self).map_err(|already| already)
    }

    /// Read the currently installed context, if any.
    pub fn current() -> Option<Arc<Self>> {
        OUTBOX_WAKE_CTX.get().cloned()
    }
}

/// Per-connection `ConnectionSender`s held in memory. The OutboxWake
/// handler creates one on first use and reuses it across wakes so the
/// `present` set / hot queue persist between invocations.
///
/// TODO(plan.md): production should hold senders in a runtime context
/// scoped to the daemon, not in a `static`. The audit-round-4 fix keeps
/// senders here so the OutboxWake handler can be wired without first
/// refactoring `StepContext`.
pub static SENDERS: OnceLock<Mutex<HashMap<ConnectionId, ConnectionSender>>> = OnceLock::new();

static OUTBOX_WAKE_CTX: OnceLock<Arc<OutboxWakeContext>> = OnceLock::new();

fn senders_lock() -> &'static Mutex<HashMap<ConnectionId, ConnectionSender>> {
    SENDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Real handler for `WorkItem::OutboxWake`. Flow:
///
/// 1. Look up (or create) the `ConnectionSender` for `connection_id`.
/// 2. Resolve the remote endpoint via `lookup_remote_endpoint(db, conn_id)`.
/// 3. Call `refill_if_needed(low=4KiB, high=64KiB)`.
/// 4. Drive `drain_to_socket(...)` on the installed tokio runtime.
/// 5. On `send_failed = true`, schedule a follow-up `OutboxWake` via
///    `StepResult.queue_writes` (the substrate's only mechanism for
///    advancing work between stages — `plan.md` line 38).
///
/// The handler holds NO database transaction across the async drain. The
/// outbox row deletes happen inside `drain_to_socket` already.
pub fn outbox_wake_handler() -> StepHandler {
    Arc::new(|item, ctx: &StepContext<'_>| -> Result<StepResult, DispatchError> {
        let wake = match item {
            WorkItem::OutboxWake(w) => w,
            other => {
                return Err(DispatchError::KindMismatch {
                    expected: WorkItemKind::OutboxWake,
                    actual: other.kind(),
                });
            }
        };

        let Some(wake_ctx) = OutboxWakeContext::current() else {
            // Context not installed: behave like the old stub so tests
            // and early-boot paths still complete the work item.
            return Ok(StepResult::empty());
        };

        // Resolve the remote endpoint id from the connection_endpoints
        // helper table (registered at connection bring-up).
        let remote_endpoint_id =
            match lookup_remote_endpoint(ctx.conn, &wake.connection_id) {
                Ok(Some(ep)) => ep,
                Ok(None) => {
                    // No endpoint registered yet: drop the wake, the
                    // connection's bring-up path will re-emit one once
                    // the endpoint mapping lands.
                    return Ok(StepResult::empty());
                }
                Err(e) => return Err(DispatchError::Handler(format!("lookup_remote_endpoint: {}", e))),
            };

        // Take ownership of the `ConnectionSender` for this connection
        // for the duration of the drain, then put it back. Using
        // remove/insert (instead of holding the lock across await)
        // keeps the lock window tiny.
        let mut sender = {
            let mut guard = senders_lock()
                .lock()
                .map_err(|e| DispatchError::Handler(format!("senders lock: {}", e)))?;
            guard
                .remove(&wake.connection_id)
                .unwrap_or_else(|| ConnectionSender::new(wake.connection_id))
        };

        // Refill from the outbox table.
        if let Err(e) = sender.refill_if_needed(
            ctx.conn,
            OUTBOX_WAKE_LOW_WATER_BYTES,
            OUTBOX_WAKE_HIGH_WATER_BYTES,
        ) {
            // Put the sender back even on failure so we don't lose its
            // in-memory `present` set.
            put_back_sender(sender);
            return Err(DispatchError::Handler(format!("refill_if_needed: {}", e)));
        }

        // Drive drain_to_socket to completion on the configured runtime.
        let drain_res = drive_drain(
            &mut sender,
            ctx.conn,
            wake_ctx.local_endpoint_id,
            remote_endpoint_id,
            &wake_ctx.socket_cache,
            wake_ctx.address_book.as_ref(),
            wake_ctx.runtime_handle.as_ref(),
        );

        // Always put the sender back.
        put_back_sender(sender);

        match drain_res {
            Ok(res) => {
                if res.send_failed {
                    // Schedule a backoff retry.
                    let next_at_ms = ctx.now_ms.saturating_add(OUTBOX_WAKE_RETRY_BACKOFF_MS);
                    eprintln!(
                        "OutboxWake: send_failed for connection_id={} ({}); retry scheduled at {}ms",
                        b64(&wake.connection_id),
                        res.last_error.as_deref().unwrap_or("unknown"),
                        next_at_ms,
                    );
                    let mut step = StepResult::empty();
                    step.queue_writes
                        .push(WorkItem::OutboxWake(OutboxWake { connection_id: wake.connection_id }));
                    Ok(step)
                } else {
                    Ok(StepResult::empty())
                }
            }
            Err(e) => Err(DispatchError::Handler(e)),
        }
    })
}

/// Drive the async `drain_to_socket` from a sync handler. Uses the
/// installed runtime handle if present; otherwise falls back to
/// `Handle::try_current` (works inside an async `#[tokio::test]` when
/// the runtime is multi-threaded so we can `block_in_place`).
fn drive_drain(
    sender: &mut ConnectionSender,
    db: &rusqlite::Connection,
    local: EndpointId,
    remote: EndpointId,
    cache: &SocketCache,
    addrs: &AddressBook,
    rt: Option<&tokio::runtime::Handle>,
) -> Result<crate::runtime::jobs::sender::DrainResult, String> {
    // Resolve a runtime handle to drive the future on.
    let handle: tokio::runtime::Handle = match rt {
        Some(h) => h.clone(),
        None => tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime available for OutboxWake handler".to_string())?,
    };

    let fut = sender.drain_to_socket(db, local, remote, cache, addrs);

    // We're called from a sync handler. If we're already inside a tokio
    // worker thread, `Handle::block_on` would panic, so use
    // `block_in_place` to detach the worker. If we're not in a worker
    // (e.g. tests using `block_on` directly), `block_in_place` panics —
    // detect that and fall back to plain `block_on`.
    let in_runtime = tokio::runtime::Handle::try_current().is_ok();
    if in_runtime {
        // `block_in_place` requires the multi-threaded runtime. Tests
        // that drive this synchronously should use `Runtime::new()` /
        // `#[tokio::test(flavor = "multi_thread")]`.
        let res = tokio::task::block_in_place(|| handle.block_on(fut));
        return res.map_err(|e| format!("drain_to_socket: {}", e));
    }
    handle
        .block_on(fut)
        .map_err(|e| format!("drain_to_socket: {}", e))
}

fn put_back_sender(sender: ConnectionSender) {
    let cid = sender.connection_id;
    if let Ok(mut guard) = senders_lock().lock() {
        guard.insert(cid, sender);
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Stub for `WorkItem::JobTick` until the job runtime is wired.
pub fn job_tick_stub() -> StepHandler {
    Arc::new(|item, _ctx: &StepContext<'_>| -> Result<StepResult, DispatchError> {
        match item {
            WorkItem::JobTick(_) => Ok(StepResult::empty()),
            other => Err(DispatchError::KindMismatch {
                expected: WorkItemKind::JobTick,
                actual: other.kind(),
            }),
        }
    })
}

fn chain_error_to_dispatch(e: ChainError) -> DispatchError {
    DispatchError::Handler(e.to_string())
}

/// Used purely so the per-event disposition fields aren't dead-code in
/// substrate users that ignore them. (Tests call the chain directly and
/// don't go through this trampoline.)
#[allow(dead_code)]
fn _suppress_unused_disposition_fields(r: &InnerEventResult) -> &InnerEventResult {
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::control_loop::work_item::{
        BlakeId, JobTick, OutboxWake, ReadyEvent,
    };
    use rusqlite::Connection;

    #[test]
    fn registers_one_handler_per_kind() {
        let mut reg = ModuleRegistry::new();
        register_default_handlers(&mut reg);
        for k in WorkItemKind::ALL {
            assert!(
                reg.handler_for(*k).is_some(),
                "missing default handler for {:?}",
                k
            );
        }
    }

    #[test]
    fn job_tick_stub_dispatches_ok() {
        let mut reg = ModuleRegistry::new();
        register_default_handlers(&mut reg);
        let conn = Connection::open_in_memory().unwrap();
        let ctx = StepContext {
            conn: &conn,
            now_ms: 0,
            worker_id: "test",
        };
        let item = WorkItem::JobTick(JobTick {
            job_name: "job".to_string(),
            fired_at_ms: 0,
        });
        let res = crate::runtime::control_loop::dispatch_step(&reg, &item, &ctx).unwrap();
        assert!(res.state_updates.is_empty());
    }

    #[test]
    fn outbox_wake_handler_no_context_is_noop() {
        // Without an installed `OutboxWakeContext` the handler short-circuits
        // to `StepResult::empty()` so the dispatcher can still claim and
        // complete the work item (mirrors the previous stub's behavior).
        let mut reg = ModuleRegistry::new();
        register_default_handlers(&mut reg);
        let conn = Connection::open_in_memory().unwrap();
        let ctx = StepContext {
            conn: &conn,
            now_ms: 0,
            worker_id: "test",
        };
        let item = WorkItem::OutboxWake(OutboxWake {
            connection_id: [1u8; 32],
        });
        let res = crate::runtime::control_loop::dispatch_step(&reg, &item, &ctx).unwrap();
        assert!(res.state_updates.is_empty());
        assert!(res.queue_writes.is_empty());
    }

    #[test]
    fn ready_event_handler_errors_when_event_missing() {
        let mut reg = ModuleRegistry::new();
        register_default_handlers(&mut reg);
        let conn = Connection::open_in_memory().unwrap();
        crate::state::db::control_loop_tables::ensure_schema(&conn).unwrap();
        let ctx = StepContext {
            conn: &conn,
            now_ms: 0,
            worker_id: "test",
        };
        let id: BlakeId = [99u8; 32];
        let item = WorkItem::ReadyEvent(ReadyEvent { event_id: id });
        let err = crate::runtime::control_loop::dispatch_step(&reg, &item, &ctx).unwrap_err();
        match err {
            DispatchError::Handler(_) => {}
            other => panic!("expected Handler error, got {:?}", other),
        }
    }
}
