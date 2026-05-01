//! # ConnectionSender (per-connection hot-queue actor)
//!
//! ## Purpose
//! One actor per active connection that owns the in-memory hot queue,
//! refills it from the `outbox` table on `OutboxWake`, wraps batches into
//! `OutboundFrame`s, and drains them to TCP. Replaces the Phase 10
//! ad-hoc `SenderJob::tick(...)` job (`plan.md` lines 178-185 + 211).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the per-connection `hot_queue: VecDeque<EventId>` and `present:
//!   HashSet<EventId>` for in-flight/queued ids,
//! - the `bytes_in_hot_queue` running estimate,
//! - low-/high-water refill thresholds and the per-frame batch size,
//! - workspace recovery for outbound events
//!   (see `recover_workspace_id`) and the audit-round-4 refusal on
//!   ambiguous workspace.
//!
//! Does NOT own:
//! - the durable outbox rows — that's [`crate::state::outbox`],
//! - the wire / wrap layout — that's
//!   `event_modules::connection::wrap`,
//! - TCP I/O — that's [`crate::runtime::transport_v2`],
//! - retry / backoff — the OutboxWake handler in
//!   `runtime/control_loop/default_handlers` decides when to schedule
//!   the next wake.
//!
//! ## Interfaces
//! - [`ConnectionSender::new`] / [`ConnectionSender::refill_if_needed`] /
//!   [`ConnectionSender::drain_to_socket`].
//! - [`DrainResult`] — `(frames_written, event_ids_completed,
//!   send_failed, last_error)`.
//! - [`SenderTick`] / [`legacy_job_tick`] — compatibility wrappers for
//!   schedulers that still mint `OutboxWake` via a tick path.
//! - [`upsert_connection_endpoint`] / [`lookup_remote_endpoint`] — the
//!   `connection_endpoints` helper table the OutboxWake handler reads.
//! - [`INTENT_ENVELOPE_HAVE`] / `_NEED` / `_COMPARE` — the tag bytes used
//!   when synthesizing endpoint-local sync events; receivers dispatch on
//!   these.
//!
//! ## State
//! ```text
//! ConnectionSender:
//!   connection_id:      ConnectionId
//!   hot_queue:          VecDeque<EventId>      // FIFO, by outbox order
//!   present:            HashSet<EventId>       // in-flight or queued
//!   bytes_in_hot_queue: usize                  // running estimate
//! ```
//! Plus the per-process `connection_endpoints` table for endpoint lookup.
//!
//! ## Invariants
//! - `hot_queue` ordering matches `outbox.queued_at_ms ASC, event_id ASC`.
//! - **No database transaction is held while writing to the socket**
//!   (`plan.md` line 185). Outbox row deletes happen in a separate short
//!   transaction after socket-accept.
//! - On send failure: `present` is cleared for the affected ids, `outbox`
//!   rows STAY pending. Caller backs off the connection.
//! - On socket-accept: `outbox` rows are deleted AND `present` releases
//!   the same ids.
//! - Workspace recovery for an outbound event is authoritative or the
//!   sender REFUSES (audit round 4). No `LIMIT 1` fallback that could
//!   leak an event into a workspace the receiver isn't entitled to.
//! - Senders share no in-memory state — each one's `present` and
//!   `hot_queue` are private. Backpressure on one connection cannot
//!   starve another (slow-peer isolation, `plan.md` line 211).
//!
//! ## Flow
//! ```text
//!   OutboxWake(connection_id) (control loop)
//!     -> lookup ConnectionSender for connection_id
//!     -> refill_if_needed(low=8KiB, high=64KiB)
//!         -> outbox::pending_for_connection(...)
//!         -> skip ids already in `present`
//!         -> push into hot_queue + present, accumulate byte estimate
//!     -> drain_to_socket(local, remote, cache, resolver)
//!         -> for each batch up to DEFAULT_FRAME_BATCH:
//!              load_inner_event(id) -> Found(ws, bytes) | Stale | Ambiguous
//!              - Stale     -> delete outbox row, drop from present
//!              - Ambiguous -> mark send_failed, leave outbox row, drop
//!                             from present, do not send
//!              - Found     -> group by workspace
//!              connection_wrap(...) -> OutboundFrame
//!              transport_send(frame)
//!              - Ok        -> outbox::delete(ids), drop ids from present
//!              - Err       -> mark send_failed, drop from present,
//!                             RETURN early (cache dropped stream)
//! ```
//!
//! ## Failure / restart behavior
//! - Process crash → all in-memory state is lost; on restart the sender
//!   starts empty and refills on the next `OutboxWake`.
//! - `wrap` failure on `NoOutboundSecret` aborts the whole drain (the
//!   connection isn't ready); other wrap errors only skip the failing
//!   batch.
//! - Transport error on send drops the cached stream, marks the drain
//!   `send_failed`, and bails — the OutboxWake handler reschedules with
//!   `OUTBOX_WAKE_RETRY_BACKOFF_MS` backoff.
//! - Ambiguous workspace (multiple shared, no on-row workspace_id) is
//!   refused; the row stays pending awaiting an explicit projector fix.
//!
//! ## Performance notes
//! - Refill pages outbox in chunks of `DEFAULT_REFILL_PAGE` (256) to bound
//!   per-wake work; if the page is entirely already-`present`, the page
//!   widens up to a backstop of 4096 to avoid pathological loops.
//! - `DEFAULT_FRAME_BATCH = 32` events per outbound frame trades smaller
//!   batches (finer delete cadence) for fewer wraps per drain.
//! - `bytes_in_hot_queue` is a saturating estimate over event payload
//!   sizes, derived from `length(canonical_event_bytes)` (or the legacy
//!   `events.blob` length).
//! - The slow-peer property: with one sender per connection, a stuck
//!   peer fills only its own queue and only its own refill pauses.
//!
//! ## Testing hooks
//! - In-file `tests` cover refill skipping `present`, low-water no-op,
//!   schedule-tick validation, full drain end-to-end (with a real TCP
//!   listener), send-failure leaving outbox pending, and the audit-round-4
//!   ambiguous-workspace refusal regression test
//!   (`refuses_send_when_workspace_id_ambiguous`).

use std::collections::{BTreeMap, HashSet, VecDeque};

use rusqlite::{params, Connection as SqlConnection, OptionalExtension};

use crate::event_modules::connection::wrap::{wrap as connection_wrap, InnerCanonicalEvent, WrapError};
use crate::runtime::control_loop::work_item::{
    BlakeId, ConnectionId, EndpointId, JobTick, OutboxWake, WorkItem, WorkspaceId,
};
use crate::runtime::transport_v2::{
    send as transport_send, AddressResolver, OutboundFrame, SocketCache, TransportError,
};
use crate::state::events_canonical::{self, EventScope};
use crate::state::outbox;

/// Tag byte prepended to `payload_key_bytes` when synthesizing inner-event
/// blobs for non-Send sync intents. Receiver dispatches on this byte.
///
/// Kept exported because the legacy `outgoing_intents` shim, the roundtrip
/// test, and any code unwrapping endpoint-local sync events all dispatch on
/// these bytes.
pub const INTENT_ENVELOPE_HAVE: u8 = 0xC0;
pub const INTENT_ENVELOPE_NEED: u8 = 0xC1;
pub const INTENT_ENVELOPE_COMPARE: u8 = 0xC2;

/// Default low-water mark in estimated bytes. The hot queue refills when
/// `bytes_in_hot_queue < low_water`.
pub const DEFAULT_LOW_WATER_BYTES: usize = 8 * 1024;
/// Default high-water mark in estimated bytes. Refill stops at or above this.
pub const DEFAULT_HIGH_WATER_BYTES: usize = 64 * 1024;
/// Default maximum number of outbox rows examined per refill pass. Bounds
/// the work the sender does in one wake.
pub const DEFAULT_REFILL_PAGE: usize = 256;
/// Default maximum number of inner events crammed into a single
/// `OutboundFrame`. Smaller batches give finer-grained delete cadence; the
/// hot queue can produce as many frames as needed in one drain.
pub const DEFAULT_FRAME_BATCH: usize = 32;

/// Job-tick discriminator string used in legacy `JobTick` payloads. Kept for
/// callers that still wake the sender via the JobTick path; new code uses
/// `OutboxWake` directly.
pub const SENDER_TICK_JOB_NAME: &str = "sender";

/// Outcome of a single `drain_to_socket` call. The caller (control loop or
/// test) decides when to retry on failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainResult {
    /// Frames the sender successfully handed to TCP.
    pub frames_written: usize,
    /// Event ids whose `outbox` rows were deleted because their containing
    /// frame was socket-accepted.
    pub event_ids_completed: Vec<BlakeId>,
    /// True iff *any* frame in this drain failed to send. The caller is
    /// expected to back off; the sender has already cleared the affected
    /// ids from `present` so a later retry can re-pull them from `outbox`.
    pub send_failed: bool,
    /// Error reason from the last failed send, if any. Useful for tests
    /// and observability.
    pub last_error: Option<String>,
}

/// Per-connection send owner per `plan.md` lines 178-185.
///
/// `hot_queue` and `present` are in-memory only; the `outbox` table is the
/// durable source of truth for "what still needs sending". On a fresh
/// process this struct starts empty and `refill_if_needed` re-populates it
/// from the table.
pub struct ConnectionSender {
    pub connection_id: ConnectionId,
    /// FIFO of event ids ready to send for this connection. Ordering is
    /// `outbox.queued_at_ms ASC, event_id ASC`.
    hot_queue: VecDeque<BlakeId>,
    /// In-flight or queued ids. Used to dedupe refill against rows the
    /// previous wake already pulled but hasn't completed yet.
    present: HashSet<BlakeId>,
    /// Running estimate of bytes in `hot_queue`. Cheap upper bound.
    bytes_in_hot_queue: usize,
    /// Cached resolution of `connection_shared_workspaces` for this
    /// connection. Loaded lazily on first use and reused across all
    /// drains for this actor's lifetime.
    ///
    /// At most ~handful of workspaces per connection in practice; storing
    /// the whole set is bounded and lets the ambiguity-check answer in
    /// O(set size) instead of running a `LIMIT 2` SQL probe per outbound
    /// row. The previous shape ran the per-row query inside
    /// `recover_workspace_id`'s ambiguity branch, which dominated the
    /// sender hot path during the perf test (24% gap at 100k frames).
    ///
    /// `None` means "not yet loaded"; an empty Vec means "loaded, no
    /// shared workspaces". The cache is treated as static for the actor's
    /// lifetime.
    ///
    /// TODO: invalidate this cache when the connection event rotates
    /// (i.e. when `connection_shared_workspaces` rows for this
    /// `connection_id` change). Today the actor is recycled when the
    /// connection itself is, so this is sound for the current daemon
    /// model — but a per-connection rotation that preserves the actor
    /// would need an explicit invalidation hook.
    shared_workspaces_cache: Option<Vec<WorkspaceId>>,
}

impl ConnectionSender {
    pub fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            hot_queue: VecDeque::new(),
            present: HashSet::new(),
            bytes_in_hot_queue: 0,
            shared_workspaces_cache: None,
        }
    }

    /// Look up the (cached) set of shared workspaces for this connection.
    /// Loads on first call and reuses thereafter — see field doc for the
    /// invalidation TODO.
    fn shared_workspaces<'a>(
        &'a mut self,
        db: &SqlConnection,
    ) -> rusqlite::Result<&'a [WorkspaceId]> {
        if self.shared_workspaces_cache.is_none() {
            let mut stmt = db.prepare(
                "SELECT workspace_id FROM connection_shared_workspaces
                 WHERE connection_id = ?1",
            )?;
            let mut rows = stmt.query(params![self.connection_id.to_vec()])?;
            let mut out: Vec<WorkspaceId> = Vec::new();
            while let Some(row) = rows.next()? {
                let blob: Vec<u8> = row.get(0)?;
                if blob.len() != 32 {
                    continue;
                }
                let mut ws = [0u8; 32];
                ws.copy_from_slice(&blob);
                out.push(ws);
            }
            self.shared_workspaces_cache = Some(out);
        }
        Ok(self
            .shared_workspaces_cache
            .as_ref()
            .map(|v| v.as_slice())
            .unwrap_or(&[]))
    }

    /// Bytes currently estimated to be in the hot queue.
    pub fn bytes_in_hot_queue(&self) -> usize {
        self.bytes_in_hot_queue
    }

    /// Number of event ids currently sitting in `hot_queue` (does not count
    /// ids that are in `present` only because they were already drained but
    /// not yet completed/cleared).
    pub fn hot_queue_len(&self) -> usize {
        self.hot_queue.len()
    }

    /// True if id `event_id` is currently tracked as in-flight or queued.
    pub fn contains(&self, event_id: &BlakeId) -> bool {
        self.present.contains(event_id)
    }

    /// Refill the hot queue from `outbox` rows for this connection, until
    /// `bytes_in_hot_queue >= high_water_bytes` or no more rows are
    /// available. Skips ids already in `present`.
    ///
    /// No-op if the hot queue is already at or above `low_water_bytes`.
    pub fn refill_if_needed(
        &mut self,
        db: &SqlConnection,
        low_water_bytes: usize,
        high_water_bytes: usize,
    ) -> rusqlite::Result<()> {
        if self.bytes_in_hot_queue >= low_water_bytes {
            return Ok(());
        }
        // Pull bounded pages of pending rows until we hit the high-water
        // mark OR the outbox has no more rows for this connection.
        // (Plan-rework D: previous version exited after the first page
        // that added anything, which left the hot queue under-populated
        // and forced an extra wake per page. Now we keep refilling.)
        let mut page_offset = 0usize;
        while self.bytes_in_hot_queue < high_water_bytes {
            let pending = outbox::pending_for_connection(
                db,
                &self.connection_id,
                DEFAULT_REFILL_PAGE.saturating_add(page_offset),
            )?;
            if pending.is_empty() {
                return Ok(());
            }
            let mut added_this_iter = false;
            let mut all_present = true;
            for (event_id, _qts) in pending {
                if self.present.contains(&event_id) {
                    continue;
                }
                all_present = false;
                let est_bytes = estimate_event_bytes(db, &event_id)?.unwrap_or(0);
                self.hot_queue.push_back(event_id);
                self.present.insert(event_id);
                self.bytes_in_hot_queue =
                    self.bytes_in_hot_queue.saturating_add(est_bytes);
                added_this_iter = true;
                if self.bytes_in_hot_queue >= high_water_bytes {
                    break;
                }
            }
            if !added_this_iter && all_present {
                // Page was entirely already-present; widen and try again.
                page_offset = page_offset.saturating_add(DEFAULT_REFILL_PAGE);
                if page_offset > 4096 {
                    // Backstop: don't loop forever if every row is in-flight.
                    return Ok(());
                }
                continue;
            }
            // Reset page_offset (we made progress); loop will hit the
            // high_water guard or run out of rows.
            page_offset = 0;
        }
        Ok(())
    }

    /// Drain the hot queue into one or more `OutboundFrame`s and write each
    /// to TCP. After socket-accept of a frame: deletes the corresponding
    /// `outbox` rows and removes the ids from `present`. On send failure:
    /// removes the ids from `present`, leaves `outbox` rows pending, and
    /// returns `send_failed = true` so the caller can back off.
    ///
    /// Holds **no** database transaction while writing to the socket
    /// (plan.md line 185).
    pub async fn drain_to_socket(
        &mut self,
        db: &SqlConnection,
        local_endpoint_id: EndpointId,
        remote_endpoint_id: EndpointId,
        cache: &SocketCache,
        resolver: &dyn AddressResolver,
    ) -> rusqlite::Result<DrainResult> {
        let mut result = DrainResult::default();
        if self.hot_queue.is_empty() {
            return Ok(result);
        }

        // Pull up to `DEFAULT_FRAME_BATCH` ids per frame, group by workspace,
        // wrap, then send.
        loop {
            let mut take: Vec<BlakeId> = Vec::with_capacity(DEFAULT_FRAME_BATCH);
            while take.len() < DEFAULT_FRAME_BATCH {
                let Some(id) = self.hot_queue.pop_front() else {
                    break;
                };
                take.push(id);
            }
            if take.is_empty() {
                break;
            }

            // Resolve to (workspace_id, bytes) tuples by reading
            // events_canonical. Three outcomes per id:
            //   Found     → batch it for wrapping under that workspace.
            //   Stale     → drop the outbox row (no event row exists).
            //   Ambiguous → REFUSE to send (audit round 4): the event row
            //               exists but workspace_id can't be authoritatively
            //               derived. We log, mark `send_failed`, clear from
            //               `present`, and leave the outbox row pending. We
            //               do NOT guess a workspace, since picking the
            //               wrong one would leak the event into a workspace
            //               the receiver isn't entitled to.
            let mut by_ws: BTreeMap<WorkspaceId, Vec<(BlakeId, Vec<u8>)>> =
                BTreeMap::new();
            let mut bytes_freed: usize = 0;
            let mut stale_ids: Vec<BlakeId> = Vec::new();
            let mut ambiguous_ids: Vec<BlakeId> = Vec::new();
            // Populate the per-connection shared_workspaces cache once
            // per drain pass; subsequent rows reuse the in-memory slice
            // instead of running a `LIMIT 2` probe per row.
            let shared_ws_cached: Vec<WorkspaceId> =
                self.shared_workspaces(db)?.to_vec();
            for id in &take {
                match load_inner_event_with_cache(
                    db,
                    id,
                    &shared_ws_cached,
                )? {
                    LoadInnerOutcome::Found(ws, bytes) => {
                        bytes_freed = bytes_freed.saturating_add(bytes.len());
                        by_ws.entry(ws).or_default().push((*id, bytes));
                    }
                    LoadInnerOutcome::Stale => {
                        // No event row → drop the outbox row; nothing to
                        // send.
                        stale_ids.push(*id);
                    }
                    LoadInnerOutcome::Ambiguous => {
                        // Event row exists but workspace is undecidable.
                        // Refuse + record (no fallback).
                        ambiguous_ids.push(*id);
                    }
                }
            }
            // Reduce hot-queue byte estimate for what we just popped.
            self.bytes_in_hot_queue =
                self.bytes_in_hot_queue.saturating_sub(bytes_freed);

            if !stale_ids.is_empty() {
                let _ = outbox::delete(db, &self.connection_id, &stale_ids)?;
                for id in &stale_ids {
                    self.present.remove(id);
                }
            }

            if !ambiguous_ids.is_empty() {
                // Clear from `present` so a future refill can pick them
                // up again (e.g. after a projector fix populates the
                // workspace), but leave the outbox row in place. Mark the
                // drain as failed and surface a useful error message.
                for id in &ambiguous_ids {
                    self.present.remove(id);
                }
                let err = LoadInnerError::AmbiguousWorkspace {
                    event_id: ambiguous_ids[0],
                };
                let msg = format!(
                    "{} (n={}, connection_id={})",
                    err,
                    ambiguous_ids.len(),
                    {
                        use base64::Engine;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(self.connection_id)
                    }
                );
                eprintln!("ConnectionSender: refused send: {}", msg);
                result.send_failed = true;
                result.last_error = Some(msg);
            }

            for (ws, items) in by_ws {
                let inner_events: Vec<InnerCanonicalEvent> = items
                    .iter()
                    .map(|(_id, bytes)| InnerCanonicalEvent {
                        workspace_id: ws,
                        bytes: bytes.clone(),
                    })
                    .collect();
                let ids_in_batch: Vec<BlakeId> =
                    items.iter().map(|(id, _)| *id).collect();

                let frame: OutboundFrame =
                    match connection_wrap(self.connection_id, &inner_events, db) {
                        Ok(f) => f,
                        Err(e) => {
                            // No outbound secret / wrap-time policy failure.
                            // Leave outbox rows pending; clear from present
                            // so a later refill can pick them back up.
                            for id in &ids_in_batch {
                                self.present.remove(id);
                            }
                            result.send_failed = true;
                            result.last_error = Some(format!("wrap: {}", e));
                            // For NoOutboundSecret bail the whole drain —
                            // the connection isn't ready and retrying every
                            // batch this drain costs CPU for nothing.
                            if matches!(e, WrapError::NoOutboundSecret) {
                                return Ok(result);
                            }
                            continue;
                        }
                    };

                match transport_send(
                    cache,
                    resolver,
                    local_endpoint_id,
                    remote_endpoint_id,
                    frame,
                )
                .await
                {
                    Ok(()) => {
                        // Socket accepted the frame: delete outbox rows and
                        // clear present. We do these in two separate calls
                        // (no transaction held during the await above).
                        let _ = outbox::delete(db, &self.connection_id, &ids_in_batch)?;
                        for id in &ids_in_batch {
                            self.present.remove(id);
                            result.event_ids_completed.push(*id);
                        }
                        result.frames_written =
                            result.frames_written.saturating_add(1);
                    }
                    Err(e) => {
                        for id in &ids_in_batch {
                            self.present.remove(id);
                        }
                        result.send_failed = true;
                        result.last_error =
                            Some(format!("transport: {}", transport_error_string(&e)));
                        // Don't keep trying batches after a transport failure
                        // on this connection — the cache already dropped the
                        // stream and the next ones would hit the same wall.
                        return Ok(result);
                    }
                }
            }
        }

        Ok(result)
    }
}

/// Reason a `load_inner_event` call refused to produce a `(workspace_id,
/// bytes)` tuple. Distinguishes "row genuinely missing" (stale outbox row,
/// drop it) from "row exists but we cannot authoritatively pin its
/// workspace" (refuse send, log, keep outbox row pending so an explicit
/// projector fix or schema migration can recover).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadInnerError {
    /// `events_canonical` row exists but its workspace_id can't be derived
    /// authoritatively. Audit round 4 (codex): we used to fall back to
    /// `connection_shared_workspaces LIMIT 1` here, which would leak an
    /// event into a workspace the receiver wasn't entitled to. The sender
    /// now refuses instead.
    AmbiguousWorkspace { event_id: BlakeId },
}

impl std::fmt::Display for LoadInnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadInnerError::AmbiguousWorkspace { event_id } => {
                use base64::Engine;
                let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(event_id);
                write!(
                    f,
                    "ambiguous workspace_id for event_id {} — refusing to send",
                    id
                )
            }
        }
    }
}

/// Outcome of `load_inner_event`. We need three states (not just
/// `Result<Option<...>>`) so the drain loop can tell apart:
///   - Found: ship it.
///   - Stale: outbox row references a deleted/missing event — safe to drop.
///   - Ambiguous: event is real but workspace is undecidable — refuse,
///     log, and leave the outbox row pending. Importantly we DO NOT pick
///     "any" workspace, because that risks leaking the event into a
///     workspace the receiver isn't entitled to. (Audit round 4.)
enum LoadInnerOutcome {
    Found(WorkspaceId, Vec<u8>),
    /// The event row is missing entirely — caller should delete the
    /// stale outbox entry.
    Stale,
    /// The event row exists but we cannot authoritatively pin its
    /// workspace. Caller skips the row, records a send failure, and
    /// leaves the outbox row pending.
    Ambiguous,
}

/// Look up the inner event payload for `event_id` using the per-actor
/// `connection_shared_workspaces` cache.
///
/// Returns `LoadInnerOutcome::Found(workspace_id, bytes)` when the event
/// has an authoritative workspace_id, `Stale` if the row is missing
/// entirely, and `Ambiguous` if the row exists but the workspace can't
/// be derived authoritatively (audit round 4: we no longer guess).
///
/// Authoritative sources (in priority order):
///   1. `events_canonical.scope = EndpointLocal` rows synthesized by the
///      `outgoing_intents` shim carry `[envelope_byte][workspace_id]` at
///      `canonical_event_bytes[..33]`. Recover from there.
///   2. For other scopes, the cached `shared_workspaces` slice. If — and
///      only if — exactly ONE workspace is shared with this connection,
///      that workspace is authoritative (the receiver is entitled to it
///      by definition; there's no ambiguity for the sender to resolve).
///      Two-or-more shared workspaces → `Ambiguous`, refuse to send.
///
/// We deliberately do NOT fall back to picking an arbitrary workspace
/// when multiple are shared. The previous `LIMIT 1` fallback could end
/// up wrapping an event under a workspace_id the receiver wasn't
/// entitled to receive for that event — a cross-workspace data leak.
fn load_inner_event_with_cache(
    db: &SqlConnection,
    event_id: &BlakeId,
    shared_workspaces: &[WorkspaceId],
) -> rusqlite::Result<LoadInnerOutcome> {
    if let Some(row) = events_canonical::get(db, event_id)? {
        let bytes = row.canonical_event_bytes;
        let ws =
            recover_workspace_id_cached(&row.scope, &bytes, shared_workspaces);
        let Some(ws) = ws else {
            return Ok(LoadInnerOutcome::Ambiguous);
        };
        return Ok(LoadInnerOutcome::Found(ws, bytes));
    }
    Ok(LoadInnerOutcome::Stale)
}

/// Pure cache-fed workspace recovery for an `events_canonical` row.
/// Takes the cached shared-workspaces slice for the connection.
///   - EndpointLocal scope: pull workspace from `[envelope][workspace_id]`
///     prefix.
///   - Otherwise: exactly-one-shared-workspace → return it; zero or more
///     than one → return None so the caller refuses to send.
fn recover_workspace_id_cached(
    scope: &EventScope,
    canonical_event_bytes: &[u8],
    shared_workspaces: &[WorkspaceId],
) -> Option<WorkspaceId> {
    if matches!(scope, EventScope::EndpointLocal) && canonical_event_bytes.len() >= 1 + 32 {
        let mut ws = [0u8; 32];
        ws.copy_from_slice(&canonical_event_bytes[1..33]);
        return Some(ws);
    }
    if shared_workspaces.len() == 1 {
        Some(shared_workspaces[0])
    } else {
        None
    }
}

/// Cheap byte-size estimate for a candidate event id. Returns the canonical
/// `canonical_event_bytes` length if known, the legacy `events.blob` length otherwise,
/// or `None` if neither row exists.
fn estimate_event_bytes(
    db: &SqlConnection,
    event_id: &BlakeId,
) -> rusqlite::Result<Option<usize>> {
    if let Some(n) = db
        .query_row(
            "SELECT length(canonical_event_bytes) FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    {
        return Ok(Some(n as usize));
    }
    if let Some(n) = legacy_event_blob_size(db, event_id)? {
        return Ok(Some(n));
    }
    Ok(None)
}

fn legacy_event_blob_size(
    db: &SqlConnection,
    event_id: &BlakeId,
) -> rusqlite::Result<Option<usize>> {
    use base64::Engine;
    // The legacy `events` table keys by URL-safe-no-pad b64 strings.
    let id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(event_id);
    // Existence check first — some test setups don't create the legacy table.
    let table_exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='events')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if !table_exists {
        return Ok(None);
    }
    db.query_row(
        "SELECT length(blob) FROM events WHERE event_id = ?1",
        params![id_b64],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .map(|opt| opt.map(|n| n as usize))
}

// `lookup_legacy_event_blob` and `lookup_any_workspace_for_event` were
// removed in audit round 4. The latter selected an arbitrary workspace
// via `LIMIT 1` from `connection_shared_workspaces` which could leak
// events across workspaces; the former was only ever used downstream of
// it. The send path now refuses (LoadInnerOutcome::Ambiguous) instead of
// guessing.

fn transport_error_string(e: &TransportError) -> String {
    format!("{}", e)
}

// ---------------------------------------------------------------------------
// connection_endpoints helper table (kept for endpoint lookup)
// ---------------------------------------------------------------------------

/// Ensure the `connection_endpoints` table exists.
///
/// TODO(plan.md): the connection projector should populate this directly
/// from `Connection.endpoint_a/endpoint_b` once `connection_id` becomes the
/// canonical event id.
pub fn ensure_connection_endpoints_schema(db: &SqlConnection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS connection_endpoints (
            connection_id      BLOB PRIMARY KEY,
            remote_endpoint_id BLOB NOT NULL
        );",
    )?;
    Ok(())
}

/// Diagnostic helper for tests / wiring code: register a connection.
pub fn upsert_connection_endpoint(
    db: &SqlConnection,
    connection_id: ConnectionId,
    remote_endpoint_id: EndpointId,
) -> rusqlite::Result<()> {
    ensure_connection_endpoints_schema(db)?;
    db.execute(
        "INSERT OR REPLACE INTO connection_endpoints (connection_id, remote_endpoint_id)
         VALUES (?1, ?2)",
        params![connection_id.to_vec(), remote_endpoint_id.to_vec()],
    )?;
    Ok(())
}

/// Look up the remote endpoint id registered for `connection_id`.
pub fn lookup_remote_endpoint(
    db: &SqlConnection,
    connection_id: &ConnectionId,
) -> rusqlite::Result<Option<EndpointId>> {
    let blob: Option<Vec<u8>> = db
        .query_row(
            "SELECT remote_endpoint_id FROM connection_endpoints WHERE connection_id = ?1",
            params![connection_id.to_vec()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(blob) = blob else { return Ok(None) };
    if blob.len() != 32 {
        return Ok(None);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&blob);
    Ok(Some(out))
}

// ---------------------------------------------------------------------------
// Compatibility surface for callers that still construct `OutboxWake` work
// items via a "scheduler tick".
// ---------------------------------------------------------------------------

/// Marker payload used by the clock module / scheduler to wake the sender
/// for `connection_id`. Wraps an `OutboxWake` work item so callers don't
/// need to remember the variant shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderTick(pub OutboxWake);

impl SenderTick {
    pub fn for_connection(connection_id: ConnectionId) -> Self {
        Self(OutboxWake { connection_id })
    }

    pub fn into_work_item(self) -> WorkItem {
        WorkItem::OutboxWake(self.0)
    }
}

/// Legacy `JobTick` discriminator helper. Kept for the small handful of
/// scheduler integrations that still mint job ticks instead of outbox
/// wakes.
pub fn legacy_job_tick(now_ms: i64) -> JobTick {
    JobTick {
        job_name: SENDER_TICK_JOB_NAME.to_string(),
        fired_at_ms: now_ms,
    }
}

/// Aggregated drain summary, useful for observability.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderTickReport {
    pub connections_seen: usize,
    pub frames_sent: usize,
    pub events_completed: usize,
    pub send_failures: usize,
}

/// Phase 10 placeholder schedule handle — kept so the daemon main can call
/// it without #[cfg]. Returns the period verbatim for validation.
pub fn schedule_sender_tick(every_ms: u64) -> ScheduleHandle {
    assert!(every_ms > 0, "schedule_sender_tick: every_ms must be > 0");
    ScheduleHandle {
        job_name: SENDER_TICK_JOB_NAME,
        every_ms,
    }
}

/// Opaque handle returned by [`schedule_sender_tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleHandle {
    pub job_name: &'static str,
    pub every_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::connection::secrets::{
        upsert as upsert_secret, SecretDirection, SecretRow,
    };
    use crate::state::db::control_loop_tables::ensure_schema as ensure_cl_schema;

    fn open() -> SqlConnection {
        let c = SqlConnection::open_in_memory().unwrap();
        ensure_cl_schema(&c).unwrap();
        crate::event_modules::connection::secrets::ensure_schema(&c).unwrap();
        ensure_connection_endpoints_schema(&c).unwrap();
        // Workspace-membership table that wrap reads.
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
                connection_id BLOB NOT NULL,
                workspace_id  BLOB NOT NULL,
                PRIMARY KEY (connection_id, workspace_id)
            );",
        )
        .unwrap();
        c
    }

    fn add_shared(c: &SqlConnection, conn_id: &ConnectionId, ws: &WorkspaceId) {
        c.execute(
            "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), ws.to_vec()],
        )
        .unwrap();
    }

    fn add_outbound_secret(c: &SqlConnection, conn_id: ConnectionId) {
        upsert_secret(
            c,
            &SecretRow {
                connection_secret_id: [0xAA; 32],
                key: [0xBB; 32],
                direction: SecretDirection::Outbound,
                connection_id: conn_id,
                ttl_ms: i64::MAX / 2,
                created_at_ms: 0,
            },
        )
        .unwrap();
    }

    /// Synthesize an EndpointLocal sync-event in `events_canonical` and
    /// queue an outbox row for it. Mirrors what the `outgoing_intents` shim
    /// does for `Have(...)` events.
    fn enqueue_have(
        c: &SqlConnection,
        conn_id: &ConnectionId,
        ws: &WorkspaceId,
        announced_id: BlakeId,
        queued_at_ms: i64,
    ) -> BlakeId {
        let mut wire = Vec::with_capacity(1 + 32 + 32);
        wire.push(INTENT_ENVELOPE_HAVE);
        wire.extend_from_slice(ws);
        wire.extend_from_slice(&announced_id);
        // Fixed event id — derive from announce id so tests can predict it.
        let mut h = blake3::Hasher::new();
        h.update(b"test-have");
        h.update(conn_id);
        h.update(ws);
        h.update(&announced_id);
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(h.finalize().as_bytes());
        events_canonical::upsert_event(
            c,
            &events_canonical::EventRow {
                event_id,
                canonical_event_bytes: wire,
                workspace_id: Some(*ws),
                scope: EventScope::EndpointLocal,
                status: events_canonical::EventStatus::Applied,
                created_at_ms: queued_at_ms,
                expires_at_ms: None,
            },
        )
        .unwrap();
        outbox::enqueue(c, *conn_id, event_id, queued_at_ms).unwrap();
        event_id
    }

    #[test]
    fn refill_skips_present_ids() {
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [10u8; 32];
        add_shared(&c, &conn_id, &ws);
        let e1 = enqueue_have(&c, &conn_id, &ws, [11u8; 32], 0);
        let e2 = enqueue_have(&c, &conn_id, &ws, [12u8; 32], 1);

        let mut sender = ConnectionSender::new(conn_id);
        sender.refill_if_needed(&c, 1, 4096).unwrap();
        assert_eq!(sender.hot_queue_len(), 2);
        assert!(sender.contains(&e1));
        assert!(sender.contains(&e2));
        // Refill again: nothing new should arrive (both ids in `present`).
        sender.refill_if_needed(&c, 1, 4096).unwrap();
        assert_eq!(sender.hot_queue_len(), 2);
    }

    #[test]
    fn refill_respects_low_water() {
        // If the queue is already above low_water, refill is a no-op.
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let ws: WorkspaceId = [10u8; 32];
        add_shared(&c, &conn_id, &ws);
        let _ = enqueue_have(&c, &conn_id, &ws, [11u8; 32], 0);
        let mut sender = ConnectionSender::new(conn_id);
        // Force the byte counter above low water artificially by refilling
        // to high_water and then asking for a refill at low_water == 1.
        sender.refill_if_needed(&c, 1, 4096).unwrap();
        let len_before = sender.hot_queue_len();
        // Add another row — but with low_water above current bytes, refill
        // should still be a no-op since current bytes >= low_water? No,
        // here we want the opposite: current is high already, so refill
        // does nothing. Use low_water = 1 (already exceeded).
        let _ = enqueue_have(&c, &conn_id, &ws, [12u8; 32], 1);
        sender.refill_if_needed(&c, 1, 4096).unwrap();
        assert_eq!(
            sender.hot_queue_len(),
            len_before,
            "above low_water means no refill"
        );
    }

    #[test]
    fn schedule_sender_tick_validates_period() {
        let h = schedule_sender_tick(1_000);
        assert_eq!(h.every_ms, 1_000);
        assert_eq!(h.job_name, SENDER_TICK_JOB_NAME);
    }

    #[test]
    #[should_panic(expected = "every_ms must be > 0")]
    fn schedule_sender_tick_rejects_zero() {
        let _ = schedule_sender_tick(0);
    }

    #[test]
    fn sender_tick_into_work_item_carries_connection_id() {
        let conn_id: ConnectionId = [7u8; 32];
        let item = SenderTick::for_connection(conn_id).into_work_item();
        match item {
            WorkItem::OutboxWake(w) => assert_eq!(w.connection_id, conn_id),
            _ => panic!("expected OutboxWake"),
        }
    }

    #[tokio::test]
    async fn drain_writes_frame_and_deletes_outbox_rows() {
        use crate::runtime::transport_v2::{accept_loop, AddressBook, InboundDelivery};
        use std::net::SocketAddr;

        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let local: EndpointId = [2u8; 32];
        let remote: EndpointId = [3u8; 32];
        let ws: WorkspaceId = [10u8; 32];
        upsert_connection_endpoint(&c, conn_id, remote).unwrap();
        add_shared(&c, &conn_id, &ws);
        add_outbound_secret(&c, conn_id);
        let e1 = enqueue_have(&c, &conn_id, &ws, [11u8; 32], 0);

        let book = AddressBook::new();
        let cache = SocketCache::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundDelivery>(8);
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let local_addr = accept_loop(bind, tx).await.unwrap();
        book.insert(remote, local_addr);

        let mut sender = ConnectionSender::new(conn_id);
        sender.refill_if_needed(&c, 1, 8192).unwrap();
        let res = sender
            .drain_to_socket(&c, local, remote, &cache, &book)
            .await
            .unwrap();
        assert_eq!(res.frames_written, 1);
        assert_eq!(res.event_ids_completed, vec![e1]);
        assert!(!res.send_failed);

        // Outbox row was deleted.
        let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
        assert!(pending.is_empty());
        // `present` was cleared.
        assert!(!sender.contains(&e1));

        // Receiver got bytes.
        let _got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn drain_send_failure_leaves_outbox_pending_and_clears_present() {
        // No outbound secret -> wrap fails on first batch.
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let local: EndpointId = [2u8; 32];
        let remote: EndpointId = [3u8; 32];
        let ws: WorkspaceId = [10u8; 32];
        upsert_connection_endpoint(&c, conn_id, remote).unwrap();
        add_shared(&c, &conn_id, &ws);
        // intentionally no outbound secret
        let e1 = enqueue_have(&c, &conn_id, &ws, [11u8; 32], 0);

        let book = crate::runtime::transport_v2::AddressBook::new();
        let cache = SocketCache::new();
        let mut sender = ConnectionSender::new(conn_id);
        sender.refill_if_needed(&c, 1, 8192).unwrap();
        assert!(sender.contains(&e1));
        let res = sender
            .drain_to_socket(&c, local, remote, &cache, &book)
            .await
            .unwrap();
        assert_eq!(res.frames_written, 0);
        assert!(res.send_failed);
        // `present` cleared.
        assert!(!sender.contains(&e1));
        // Outbox row still pending.
        let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, e1);
    }

    /// Audit round 4 regression test (codex):
    ///
    /// Construct a connection with TWO shared workspaces and an outbox row
    /// pointing at a Durable `events_canonical` row that does NOT carry the
    /// EndpointLocal `[envelope_byte][workspace_id]` prefix. The previous
    /// implementation fell back to `connection_shared_workspaces LIMIT 1`,
    /// which would have wrapped the event under whichever workspace
    /// happened to come back first — a cross-workspace leak. The fixed
    /// sender refuses, marks `send_failed = true`, leaves the outbox row
    /// pending, and clears `present`.
    #[tokio::test]
    async fn refuses_send_when_workspace_id_ambiguous() {
        let c = open();
        let conn_id: ConnectionId = [1u8; 32];
        let local: EndpointId = [2u8; 32];
        let remote: EndpointId = [3u8; 32];
        let ws_a: WorkspaceId = [0xAA; 32];
        let ws_b: WorkspaceId = [0xBB; 32];
        upsert_connection_endpoint(&c, conn_id, remote).unwrap();
        // Two shared workspaces — exactly the conditions where a
        // `LIMIT 1` fallback would silently pick one.
        add_shared(&c, &conn_id, &ws_a);
        add_shared(&c, &conn_id, &ws_b);
        add_outbound_secret(&c, conn_id);

        // Synthesize a Durable `events_canonical` row whose
        // `canonical_event_bytes` does NOT begin with the EndpointLocal
        // workspace-prefix layout — i.e. the workspace can't be recovered
        // from the wire bytes.
        let event_id: BlakeId = [0x42; 32];
        let opaque_bytes: Vec<u8> = vec![0x55; 64]; // arbitrary durable payload
        // workspace_id intentionally `None` here: this test exercises the
        // sender path where the workspace can't be recovered from the
        // wire bytes (legacy/opaque durable payload).
        events_canonical::upsert_event(
            &c,
            &events_canonical::EventRow {
                event_id,
                canonical_event_bytes: opaque_bytes,
                workspace_id: None,
                scope: EventScope::Durable,
                status: events_canonical::EventStatus::Applied,
                created_at_ms: 0,
                expires_at_ms: None,
            },
        )
        .unwrap();
        outbox::enqueue(&c, conn_id, event_id, 0).unwrap();

        let book = crate::runtime::transport_v2::AddressBook::new();
        let cache = SocketCache::new();
        let mut sender = ConnectionSender::new(conn_id);
        sender.refill_if_needed(&c, 1, 8192).unwrap();
        assert!(sender.contains(&event_id));

        let res = sender
            .drain_to_socket(&c, local, remote, &cache, &book)
            .await
            .unwrap();

        // No frame went out.
        assert_eq!(res.frames_written, 0);
        assert!(res.event_ids_completed.is_empty());
        // Drain reports failure with a clear "ambiguous workspace" error.
        assert!(res.send_failed, "expected send_failed = true");
        let err = res
            .last_error
            .expect("expected last_error to record the refusal");
        assert!(
            err.contains("ambiguous workspace_id") || err.contains("Ambiguous"),
            "expected ambiguous-workspace error, got: {}",
            err
        );
        // Outbox row is STILL pending — the sender did not delete it.
        let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
        assert_eq!(pending.len(), 1, "outbox row must remain for retry");
        assert_eq!(pending[0].0, event_id);
        // `present` was cleared so a future refill can pick it back up.
        assert!(!sender.contains(&event_id));
    }
}
