//! # Dispatcher loop (single-writer round-robin)
//!
//! Plan-rework D: the runtime substrate's single async task that owns
//! the SQLite `Connection` exclusively and round-robins across the four
//! queue kinds:
//!
//! ```text
//!   Inbound -> ReadyEvents -> Outbox -> Jobs -> ...
//! ```
//!
//! Each step claims a small batch and processes it inside ONE
//! transaction. Each step returns whether it made progress. After a
//! full round-robin pass with no progress the dispatcher waits on the
//! shared `WakeBus` (or a deadline) before the next pass.
//!
//! This satisfies plan.md's single-writer rule: the dispatcher is the
//! ONLY tokio task that holds a writing handle to SQLite. The transport
//! bridge writes inbound bytes to a memory channel + notifies the bus;
//! it does NOT write through the DB itself. Connection-sender actors
//! read from the outbox + delete on socket-accept, but those happen on
//! per-actor connections and the dispatcher never holds the same
//! connection.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{params, Connection};
use tokio::sync::{mpsc, oneshot};

use crate::runtime::control_loop::sender_actor::{spawn_sender_actor, WakeTx};
use crate::runtime::control_loop::transport_bridge::InboundFrame;
use crate::runtime::control_loop::wake_bus::WakeBus;
use crate::runtime::control_loop::work_item::{BlakeId, ConnectionId, EndpointId};
use crate::runtime::transport_v2::{AddressBook, SocketCache};

/// Maximum rows the dispatcher claims for a single queue-kind step.
/// Inbound is batched aggressively because the chain's per-frame work
/// (insert + observation + unwrap + admit + parse + project + apply)
/// commits in one transaction; bigger batches amortize the fsync.
const BATCH_INBOUND: usize = 256;
const BATCH_READY: usize = 128;
const BATCH_OUTBOX: usize = 64;
const BATCH_JOBS: usize = 16;
const BATCH_LOCAL_EVENTS: usize = 32;

/// Idle wait deadline. Even when no wake fires we wake periodically so
/// background timers (job schedules) and any wake-loss bug ultimately
/// make progress. The notify path means typical wakes are immediate.
const IDLE_DEADLINE: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug)]
enum QueueKind {
    Inbound,
    ReadyEvents,
    Outbox,
    Jobs,
    /// Locally-created event intents (CLI/RPC ingress). Drains pending
    /// rows from `local_event_intents` and dispatches each to a
    /// registered handler. During the daemon cutover phase the RPC
    /// handlers still write canonical events directly; this queue
    /// kind exists as scaffolding for the per-handler migrations.
    LocalEvents,
}

/// Per-connection sender actor handles, lazily created on first wake.
type SenderHandles = HashMap<ConnectionId, WakeTx>;

/// Run the dispatcher loop. Owns `conn` exclusively until shutdown
/// fires.
///
/// `db_path` is needed so the dispatcher can spawn per-connection
/// sender actors with their own SQLite connections.
pub async fn run_dispatcher(
    conn: Connection,
    wakes: Arc<WakeBus>,
    local_endpoint_id: EndpointId,
    socket_cache: Arc<SocketCache>,
    address_book: Arc<AddressBook>,
    db_path: PathBuf,
    mut inbound_rx: mpsc::Receiver<InboundFrame>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut rr: VecDeque<QueueKind> = VecDeque::from([
        QueueKind::Inbound,
        QueueKind::ReadyEvents,
        QueueKind::Outbox,
        QueueKind::Jobs,
        QueueKind::LocalEvents,
    ]);
    let mut senders: SenderHandles = HashMap::new();

    loop {
        // Check shutdown before claiming any work.
        if shutdown.try_recv().is_ok() {
            return;
        }

        let mut made_progress = false;
        let len = rr.len();
        for _ in 0..len {
            let kind = rr.pop_front().unwrap();
            let progress = match kind {
                QueueKind::Inbound => {
                    drain_inbound(&conn, BATCH_INBOUND, &mut inbound_rx)
                }
                QueueKind::ReadyEvents => drain_ready(&conn, BATCH_READY),
                QueueKind::Outbox => drain_outbox(
                    &conn,
                    BATCH_OUTBOX,
                    &mut senders,
                    local_endpoint_id,
                    &socket_cache,
                    &address_book,
                    &db_path,
                ),
                QueueKind::Jobs => drain_jobs(&conn, BATCH_JOBS),
                QueueKind::LocalEvents => drain_local_events(&conn, BATCH_LOCAL_EVENTS),
            };
            made_progress |= progress;
            rr.push_back(kind);
        }

        if !made_progress {
            // Idle: wait on any wake, the periodic deadline, or shutdown.
            tokio::select! {
                _ = wakes.inbound.notified() => {},
                _ = wakes.ready.notified() => {},
                _ = wakes.outbox.notified() => {},
                _ = wakes.jobs.notified() => {},
                _ = wakes.local_events.notified() => {},
                _ = tokio::time::sleep(IDLE_DEADLINE) => {},
                _ = &mut shutdown => return,
            }
        } else {
            // Yield to the executor between busy passes so other
            // tasks (sender actors, transport bridge) get a chance to
            // run. Without this the dispatcher can starve the runtime
            // when one of the queue surfaces stays "always making
            // progress" (e.g. outbox rows that haven't been drained
            // yet because the sender actor hasn't completed).
            tokio::task::yield_now().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Per-kind drains
// ---------------------------------------------------------------------------

/// Drain pending `InboundFrame`s from the bridge channel. Reads up to
/// `max` frames non-blockingly, then runs the full chain (inbound_bytes
/// dedupe insert + observation + chain) on each inside a single batch
/// transaction. On poison row the batch is rolled back and we fall
/// back to per-row commits so the rest make progress.
///
/// Returns `true` if at least one frame was processed.
fn drain_inbound(
    conn: &Connection,
    max: usize,
    inbound_rx: &mut mpsc::Receiver<InboundFrame>,
) -> bool {
    let mut frames: Vec<InboundFrame> = Vec::with_capacity(max);
    while frames.len() < max {
        match inbound_rx.try_recv() {
            Ok(frame) => frames.push(frame),
            Err(_) => break,
        }
    }
    if frames.is_empty() {
        return false;
    }
    let now_ms = now_ms();
    let batch_ok = run_inbound_frames_batch(conn, &frames, now_ms);
    if !batch_ok {
        // Per-row fallback.
        for frame in &frames {
            if conn.execute("BEGIN IMMEDIATE", []).is_err() {
                continue;
            }
            match crate::runtime::control_loop::inbound_step::handle_inbound_bytes(
                &frame.bytes,
                frame.origin.clone(),
                conn,
                now_ms,
            ) {
                Ok(_) => {
                    // handle_inbound_bytes commits its own tx; we just
                    // need to make sure ours is closed. Since the
                    // inner function uses BEGIN IMMEDIATE on the same
                    // connection, the outer BEGIN we issued was a
                    // no-op (SQLite returns BUSY). Roll back our
                    // outer to be safe.
                    let _ = conn.execute("ROLLBACK", []);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "control_loop::dispatcher",
                        error = %e,
                        "inbound chain failed (per-row fallback)"
                    );
                    let _ = conn.execute("ROLLBACK", []);
                }
            }
        }
    }
    true
}

/// Run all collected inbound frames under a single `BEGIN IMMEDIATE`/
/// `COMMIT`: insert each into `inbound_bytes`, record the observation,
/// then run the chain body (unwrap + process inner events) on each.
/// On error the whole batch rolls back.
fn run_inbound_frames_batch(conn: &Connection, frames: &[InboundFrame], now_ms: i64) -> bool {
    if conn.execute("BEGIN IMMEDIATE", []).is_err() {
        return false;
    }
    for frame in frames {
        let wire_id =
            crate::runtime::control_loop::inbound_step::blake3_id(&frame.bytes);
        // INSERT OR IGNORE for dedupe.
        let inserted = match conn.execute(
            "INSERT OR IGNORE INTO inbound_bytes
                (wire_id, bytes, status, enqueued_at_ms)
             VALUES (?1, ?2, 'pending', ?3)",
            params![wire_id.to_vec(), &frame.bytes, now_ms],
        ) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    target: "control_loop::dispatcher",
                    error = %e,
                    "inbound INSERT failed; rolling back batch"
                );
                let _ = conn.execute("ROLLBACK", []);
                return false;
            }
        };
        if let Err(e) = crate::runtime::control_loop::inbound_step::record_observation(
            conn, &wire_id, &frame.origin, now_ms,
        ) {
            tracing::warn!(
                target: "control_loop::dispatcher",
                error = %e,
                "inbound observation failed; rolling back batch"
            );
            let _ = conn.execute("ROLLBACK", []);
            return false;
        }
        if inserted == 0 {
            // Duplicate wire_id; observation already bumped — skip
            // chain.
            continue;
        }
        match crate::runtime::control_loop::inbound_step::handle_inbound_bytes_for_claimed_in_tx(
            &wire_id, &frame.bytes, &frame.origin, conn, now_ms,
        ) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    target: "control_loop::dispatcher",
                    error = %e,
                    "inbound batch chain error; rolling back batch"
                );
                let _ = conn.execute("ROLLBACK", []);
                return false;
            }
        }
    }
    if let Err(e) = conn.execute("COMMIT", []) {
        tracing::warn!(
            target: "control_loop::dispatcher",
            error = %e,
            "inbound batch COMMIT failed"
        );
        let _ = conn.execute("ROLLBACK", []);
        return false;
    }
    true
}

/// Drain ready events. Single batch tx, copied from the legacy
/// `events_canonical_ready_worker` path so the on-disk semantics
/// (commit-once, per-event fallback on poison) carry over.
fn drain_ready(conn: &Connection, max: usize) -> bool {
    let claimed = match claim_ready_event_batch(conn, max) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                target: "control_loop::dispatcher",
                error = %e,
                "claim_ready_event_batch failed"
            );
            return false;
        }
    };
    if claimed.is_empty() {
        return false;
    }
    let now_ms = now_ms();
    let batch_ok = run_ready_event_batch(conn, &claimed, now_ms);
    if !batch_ok {
        for event_id in &claimed {
            if let Err(e) = crate::runtime::control_loop::inbound_step::handle_ready_event(
                event_id, conn, now_ms,
            ) {
                tracing::warn!(
                    target: "control_loop::dispatcher",
                    error = %e,
                    "ready_event per-event fallback failed"
                );
            }
        }
    }
    true
}

fn claim_ready_event_batch(conn: &Connection, max: usize) -> rusqlite::Result<Vec<BlakeId>> {
    let mut stmt = conn.prepare(
        "SELECT event_id FROM events_canonical
            WHERE status = 'ready'
            ORDER BY created_at_ms ASC
            LIMIT ?1",
    )?;
    let mut rows = stmt.query(params![max as i64])?;
    let mut out = Vec::with_capacity(max);
    while let Some(r) = rows.next()? {
        let id_blob: Vec<u8> = r.get(0)?;
        if id_blob.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_blob);
            out.push(id);
        }
    }
    Ok(out)
}

fn run_ready_event_batch(conn: &Connection, claimed: &[BlakeId], now_ms: i64) -> bool {
    if conn.execute("BEGIN IMMEDIATE", []).is_err() {
        return false;
    }
    for event_id in claimed {
        match crate::runtime::control_loop::inbound_step::handle_ready_event_in_tx(
            event_id, conn, now_ms,
        ) {
            Ok(_disposition) => {}
            Err(e) => {
                tracing::warn!(
                    target: "control_loop::dispatcher",
                    error = %e,
                    "ready_event batch chain error; rolling back batch"
                );
                let _ = conn.execute("ROLLBACK", []);
                return false;
            }
        }
    }
    if let Err(e) = conn.execute("COMMIT", []) {
        tracing::warn!(
            target: "control_loop::dispatcher",
            error = %e,
            "ready_event batch COMMIT failed"
        );
        let _ = conn.execute("ROLLBACK", []);
        return false;
    }
    true
}

/// Drain step for the outbox: enumerate distinct `connection_id`s with
/// pending rows and notify the matching sender actor. The dispatcher
/// does NOT do any DB work here other than the SELECT — actual outbox
/// row deletes happen in the sender actor (per-connection DB connection).
fn drain_outbox(
    conn: &Connection,
    max: usize,
    senders: &mut SenderHandles,
    local_endpoint_id: EndpointId,
    socket_cache: &Arc<SocketCache>,
    address_book: &Arc<AddressBook>,
    db_path: &PathBuf,
) -> bool {
    let connections = match distinct_pending_connections(conn, max) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "control_loop::dispatcher",
                error = %e,
                "distinct_pending_connections failed"
            );
            return false;
        }
    };
    if connections.is_empty() {
        return false;
    }
    // Track whether we actually woke any actor that wasn't already
    // pending. If every actor's wake channel is already full, we made
    // NO observable progress and the dispatcher should fall through to
    // its idle wait — otherwise we'd busy-loop on `distinct_pending_
    // connections` while the sender actors slowly drain. The
    // `wakes.outbox` notification path is the right way to wake the
    // dispatcher when a new outbox row is enqueued.
    let mut woke_any = false;
    for conn_id in connections {
        let tx = senders.entry(conn_id).or_insert_with(|| {
            spawn_sender_actor(
                conn_id,
                local_endpoint_id,
                db_path.clone(),
                socket_cache.clone(),
                address_book.clone(),
            )
        });
        // Best-effort wake. If the channel is full a wake is already
        // pending; that's fine, the actor will see the latest outbox
        // state when it next refills.
        if tx.try_send(()).is_ok() {
            woke_any = true;
        }
    }
    woke_any
}

/// Recursive-CTE loose index scan over distinct `connection_id`s in
/// `outbox`. Same query as the legacy worker.
fn distinct_pending_connections(
    conn: &Connection,
    max: usize,
) -> rusqlite::Result<Vec<ConnectionId>> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE distinct_conns(connection_id) AS (
            SELECT (SELECT connection_id FROM outbox ORDER BY connection_id LIMIT 1)
            UNION ALL
            SELECT (
                SELECT connection_id FROM outbox
                 WHERE connection_id > distinct_conns.connection_id
                 ORDER BY connection_id LIMIT 1
            )
            FROM distinct_conns
            WHERE connection_id IS NOT NULL
         )
         SELECT connection_id FROM distinct_conns
          WHERE connection_id IS NOT NULL
          LIMIT ?1",
    )?;
    let mut rows = stmt.query(params![max as i64])?;
    let mut out = Vec::with_capacity(max);
    while let Some(r) = rows.next()? {
        let blob: Vec<u8> = r.get(0)?;
        if blob.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            out.push(id);
        }
    }
    Ok(out)
}

/// Drain due jobs. Same body as the legacy `job_schedules_worker` but
/// shares the dispatcher's connection.
fn drain_jobs(conn: &Connection, max: usize) -> bool {
    let now = now_ms();
    let due: Vec<(String, i64)> = match due_jobs(conn, now, max) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "control_loop::dispatcher",
                error = %e,
                "due_jobs failed"
            );
            return false;
        }
    };
    if due.is_empty() {
        return false;
    }
    for (job_name, every_ms) in due {
        // Dispatch by job_name into event-module job bodies. The
        // kernel keeps zero policy here — it just routes a name to
        // the registered handler in the event module. The job body
        // and schedule cadence are owned by the event module that
        // registers the schedule row at startup.
        //
        // Each job is run in its own short transaction so a failure
        // in one job doesn't roll back unrelated state. Schedule
        // bumping happens after the body runs (either way), so a
        // crashing job doesn't pin the schedule and starve others.
        if conn.execute("BEGIN IMMEDIATE", []).is_ok() {
            let body_ok = run_job_body(conn, &job_name, now);
            if body_ok {
                let _ = conn.execute("COMMIT", []);
            } else {
                let _ = conn.execute("ROLLBACK", []);
            }
        }
        if let Err(e) = bump_schedule(conn, &job_name, now, every_ms) {
            tracing::warn!(
                target: "control_loop::dispatcher",
                job_name = %job_name,
                error = %e,
                "bump_schedule failed"
            );
        }
    }
    true
}

/// Route a fired `(job_name, now_ms)` to the event-module-owned job
/// body. Returns `true` if the body completed without error so the
/// caller can commit; `false` otherwise.
///
/// The kernel's only role here is name → module dispatch; it owns no
/// job logic. New jobs add a name match and a call into their event
/// module.
fn run_job_body(conn: &Connection, job_name: &str, now_ms: i64) -> bool {
    match job_name {
        crate::event_modules::sync::job::SYNC_ROOT_COMPARE_JOB_NAME => {
            match crate::event_modules::sync::job::tick(conn, now_ms) {
                Ok(_report) => true,
                Err(e) => {
                    tracing::warn!(
                        target: "control_loop::dispatcher",
                        job_name = %job_name,
                        error = %e,
                        "sync_root_compare tick failed"
                    );
                    false
                }
            }
        }
        _ => {
            // Unknown job: treat as no-op success so the schedule
            // bumps and we don't busy-loop on a stale name.
            true
        }
    }
}

fn due_jobs(conn: &Connection, now_ms: i64, max: usize) -> rusqlite::Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT job_name, every_ms FROM job_schedules
            WHERE next_fire_at_ms <= ?1
            ORDER BY next_fire_at_ms ASC
            LIMIT ?2",
    )?;
    let mut rows = stmt.query(params![now_ms, max as i64])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?));
    }
    Ok(out)
}

fn bump_schedule(
    conn: &Connection,
    job_name: &str,
    fired_at_ms: i64,
    every_ms: i64,
) -> rusqlite::Result<()> {
    let next = fired_at_ms.saturating_add(every_ms.max(1));
    conn.execute(
        "UPDATE job_schedules
            SET last_fired_at_ms = ?1,
                next_fire_at_ms = ?2
          WHERE job_name = ?3",
        params![fired_at_ms, next, job_name],
    )?;
    Ok(())
}

/// Drain pending `local_event_intents` rows. CLI/RPC handlers insert
/// rows here for the dispatcher to pick up under the single-writer
/// rule. Today no `command_kind` is registered against a handler — the
/// drain logs and marks rows `unhandled` so they don't requeue. Each
/// command-kind migration registers a handler in subsequent phases.
///
/// Returns `true` if at least one row was processed.
fn drain_local_events(conn: &Connection, max: usize) -> bool {
    let claimed: Vec<(i64, String)> = match claim_local_event_batch(conn, max) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                target: "control_loop::dispatcher",
                error = %e,
                "claim_local_event_batch failed"
            );
            return false;
        }
    };
    if claimed.is_empty() {
        return false;
    }
    if conn.execute("BEGIN IMMEDIATE", []).is_err() {
        return false;
    }
    for (id, kind) in &claimed {
        // No registered handlers yet. Mark `unhandled` so the row is
        // visible in diagnostics but is no longer in the pending pool.
        // When a `command_kind` migrates to this path, replace this
        // arm with a dispatch into the registered handler.
        tracing::debug!(
            target: "control_loop::dispatcher",
            id = %id,
            kind = %kind,
            "local_event_intents row drained without registered handler"
        );
        if let Err(e) = conn.execute(
            "UPDATE local_event_intents
                SET status = 'unhandled'
              WHERE id = ?1",
            params![id],
        ) {
            tracing::warn!(
                target: "control_loop::dispatcher",
                error = %e,
                "local_event_intents UPDATE failed; rolling back batch"
            );
            let _ = conn.execute("ROLLBACK", []);
            return false;
        }
    }
    if let Err(e) = conn.execute("COMMIT", []) {
        tracing::warn!(
            target: "control_loop::dispatcher",
            error = %e,
            "local_event_intents COMMIT failed"
        );
        let _ = conn.execute("ROLLBACK", []);
        return false;
    }
    true
}

fn claim_local_event_batch(
    conn: &Connection,
    max: usize,
) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT id, command_kind FROM local_event_intents
            WHERE status = 'pending'
            ORDER BY enqueued_at_ms ASC, id ASC
            LIMIT ?1",
    )?;
    let mut rows = stmt.query(params![max as i64])?;
    let mut out = Vec::with_capacity(max);
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?));
    }
    Ok(out)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
