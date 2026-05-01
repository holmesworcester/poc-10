//! # WorkItem queue payloads
//!
//! ## Purpose
//! The `WorkItem` enum is the closed taxonomy of things the control loop can
//! claim and dispatch. It is the single boundary between "things produced by
//! the runtime substrate" (transport, scheduler, status flips) and "things
//! handlers act on" (`plan.md` lines 79-87).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the four-variant taxonomy ([`InboundBytes`], [`ReadyEvent`],
//!   [`OutboxWake`], [`JobTick`]),
//! - `WorkItemKind` discriminator strings used as the `kind` column in
//!   `work_queue` rows,
//! - `dedupe_key` policy used by the `UNIQUE(kind, dedupe_key)` index.
//!
//! Does NOT own:
//! - the canonical event bytes themselves — those live in
//!   [`crate::state::events_canonical`],
//! - the outbox row layout — see [`crate::state::outbox`],
//! - the chain logic for any of the four variants — see
//!   [`super::inbound_step`] and [`super::default_handlers`].
//!
//! ## Interfaces
//! - [`WorkItem`] — the enum; one variant per [`WorkItemKind`].
//! - [`WorkItem::kind`] / [`WorkItem::dedupe_key`] — used by the queue layer.
//! - [`WorkItemKind::as_str`] / [`WorkItemKind::parse`] — stable wire/db
//!   names; do not rename without a migration.
//!
//! ## State
//! Pure value type. State lives elsewhere:
//! - `work_queue` table (legacy) keys by `(kind, dedupe_key)`.
//! - `events_canonical.status = 'ready'` is the implicit queue for
//!   `ReadyEvent`.
//! - `outbox(connection_id, event_id)` is the implicit queue for
//!   `OutboxWake`.
//!
//! ## Invariants
//! - Exactly four variants. The chain step (`unwrap → parse → admit_event_id
//!   → context → project → apply`) is collapsed into the `InboundBytes`
//!   handler — there are no `CanonicalEventBytes`, `ParsedEvent`, or
//!   `BlockedEvent` queue items.
//! - `OutboxWake` carries only `connection_id`; the sender derives the rest
//!   from `outbox` (sorted by `queued_at_ms ASC, event_id ASC`).
//! - `OutboundFrame` is NOT a `WorkItem`. It is a transit-only opaque type
//!   minted by `event_modules::connection::wrap{,_bootstrap}`.
//!
//! ## Flow
//! ```text
//!   InboundBytes  -> chained inbound_step
//!   ReadyEvent    -> handle_ready_event (parse/context/project/apply tail)
//!   OutboxWake    -> ConnectionSender refill + drain
//!   JobTick       -> registered job module
//! ```
//!
//! ## Failure / restart behavior
//! - Dedupe is at the queue layer: a duplicate `OutboxWake(connection_id)`
//!   collapses into a single row (see [`WorkItem::dedupe_key`]). A slow
//!   peer cannot pile up infinite wake rows.
//! - `InboundBytes` and `ReadyEvent` dedupe by their content hash, so
//!   replay-safety is automatic at the queue layer.
//!
//! ## Performance notes
//! Tiny payloads. `OutboxWake` and `ReadyEvent` carry a single 32-byte id,
//! not the wire bytes — the handlers load bytes from `events_canonical`
//! when they run. This keeps queue rows small and lets the dispatcher
//! claim under tight latency.
//!
//! ## Testing hooks
//! Unit tests in this file cover kind round-trip and dedupe behavior. End-
//! to-end coverage lives in `tests/control_loop_*.rs`.

/// 32-byte BLAKE3 identifier. Used for wire-event dedupe (`wire_id`),
/// canonical event ids, etc.
pub type BlakeId = [u8; 32];

/// Daemon endpoint identifier (Ed25519 pubkey of the daemon).
pub type EndpointId = [u8; 32];

/// Workspace identifier (canonical event id of the `workspace` event).
pub type WorkspaceId = [u8; 32];

/// Connection identifier (canonical event id of the `connection` event).
pub type ConnectionId = [u8; 32];

/// Raw bytes pulled off a TCP socket, prior to any framing/parsing decisions
/// other than the `[u32 length][bytes]` strip the transport already did.
///
/// Per `plan.md` lines 102-114 the `InboundBytes` step is a chained pure
/// function — unwrap → parse → admit_event_id → context → project → apply.
/// The control loop dispatcher receives this payload and runs the chain in
/// one transactional block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundBytes {
    pub wire_id: BlakeId,
    pub bytes: Vec<u8>,
    pub remote_endpoint_id: Option<EndpointId>,
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub received_at_ms: i64,
}

/// An event row in `events` whose status has just transitioned to `ready`
/// (i.e. all prior blockers are gone). The control loop claims a bounded
/// batch of these per pass and re-runs the project/apply tail.
///
/// Carries only the canonical event id; the dispatcher loads the wire bytes
/// and metadata from the `events` table to keep this payload tiny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyEvent {
    pub event_id: BlakeId,
}

/// "Wake the sender for this connection." Per `plan.md` lines 178-185, each
/// connection has exactly one `ConnectionSender` owning a bounded hot queue.
/// On wake, the sender:
///
/// 1. refills its hot queue from `outbox` rows for `connection_id` if the
///    queue dropped below a low-water byte mark, skipping ids already
///    in-flight in `present`,
/// 2. wraps batches with `connection.wrap` (or `wrap_bootstrap`),
/// 3. writes the resulting `OutboundFrame` to TCP,
/// 4. on socket-accept: deletes the corresponding `outbox` rows and clears
///    the ids from `present`,
/// 5. on send failure: clears `present`, leaves `outbox` rows pending.
///
/// The wake carries only the connection id; the sender derives all other
/// state from the `outbox` table and its own in-memory queue. A slow peer
/// fills only its own hot queue — see `plan.md` line 211.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxWake {
    pub connection_id: ConnectionId,
}

/// Scheduled module work tick. The job module decides what state / boundary
/// writes (if any) to emit when its tick fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTick {
    pub job_name: String,
    pub fired_at_ms: i64,
}

/// All queueable work. One owning module per variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkItem {
    InboundBytes(InboundBytes),
    ReadyEvent(ReadyEvent),
    OutboxWake(OutboxWake),
    JobTick(JobTick),
}

/// Discriminator string used as the `kind` column in legacy `work_queue`
/// rows. Stable: do not rename without a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkItemKind {
    InboundBytes,
    ReadyEvent,
    OutboxWake,
    JobTick,
}

impl WorkItemKind {
    pub const ALL: &'static [WorkItemKind] = &[
        WorkItemKind::InboundBytes,
        WorkItemKind::ReadyEvent,
        WorkItemKind::OutboxWake,
        WorkItemKind::JobTick,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            WorkItemKind::InboundBytes => "InboundBytes",
            WorkItemKind::ReadyEvent => "ReadyEvent",
            WorkItemKind::OutboxWake => "OutboxWake",
            WorkItemKind::JobTick => "JobTick",
        }
    }

    pub fn parse(s: &str) -> Option<WorkItemKind> {
        Some(match s {
            "InboundBytes" => WorkItemKind::InboundBytes,
            "ReadyEvent" => WorkItemKind::ReadyEvent,
            "OutboxWake" => WorkItemKind::OutboxWake,
            "JobTick" => WorkItemKind::JobTick,
            _ => return None,
        })
    }
}

impl WorkItem {
    pub fn kind(&self) -> WorkItemKind {
        match self {
            WorkItem::InboundBytes(_) => WorkItemKind::InboundBytes,
            WorkItem::ReadyEvent(_) => WorkItemKind::ReadyEvent,
            WorkItem::OutboxWake(_) => WorkItemKind::OutboxWake,
            WorkItem::JobTick(_) => WorkItemKind::JobTick,
        }
    }

    /// Dedupe key used in legacy `work_queue` UNIQUE(kind, dedupe_key)
    /// constraints. `None` means: do not deduplicate at the queue layer.
    ///
    /// `OutboxWake` dedupes by `connection_id` — coalescing repeated wakes
    /// for the same connection into a single queue row is exactly what we
    /// want, since the sender drains the table when it runs.
    pub fn dedupe_key(&self) -> Option<String> {
        use base64::Engine;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        match self {
            WorkItem::InboundBytes(i) => Some(b64(&i.wire_id)),
            WorkItem::ReadyEvent(r) => Some(b64(&r.event_id)),
            WorkItem::OutboxWake(w) => Some(b64(&w.connection_id)),
            WorkItem::JobTick(j) => Some(format!("{}:{}", j.job_name, j.fired_at_ms)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trip() {
        for k in WorkItemKind::ALL {
            assert_eq!(WorkItemKind::parse(k.as_str()), Some(*k));
        }
    }

    #[test]
    fn work_item_kind_matches_variant() {
        let item = WorkItem::JobTick(JobTick {
            job_name: "compare".to_string(),
            fired_at_ms: 0,
        });
        assert_eq!(item.kind(), WorkItemKind::JobTick);
    }

    #[test]
    fn ready_event_dedupes_by_event_id() {
        let r = WorkItem::ReadyEvent(ReadyEvent {
            event_id: [7u8; 32],
        });
        assert!(r.dedupe_key().is_some());
    }

    #[test]
    fn outbox_wake_dedupes_by_connection_id() {
        let a = WorkItem::OutboxWake(OutboxWake {
            connection_id: [1u8; 32],
        });
        let b = WorkItem::OutboxWake(OutboxWake {
            connection_id: [1u8; 32],
        });
        let c = WorkItem::OutboxWake(OutboxWake {
            connection_id: [2u8; 32],
        });
        // Same connection coalesces — a slow peer can't pile up infinite
        // wake rows.
        assert_eq!(a.dedupe_key(), b.dedupe_key());
        assert_ne!(a.dedupe_key(), c.dedupe_key());
    }
}
