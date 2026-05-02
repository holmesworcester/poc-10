//! # Chained inbound-bytes step
//!
//! ## Purpose
//! Implements the `InboundBytes` work-item chain: a pure function from raw
//! bytes-off-the-socket to durable canonical-event state, run end-to-end
//! inside a single database transaction (`plan.md` lines 102-114). This is
//! the substrate entrypoint that replaces the legacy multi-stage
//! `state::pipeline`.
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the chain ordering and transactional envelope,
//! - `inbound_bytes` / `inbound_observations` upserts for wire-id dedupe and
//!   provenance,
//! - dispatch from `ParsedEvent::Encrypted` to decrypt-and-recurse,
//! - the `parse → context → project → apply` re-run for `ReadyEvent`.
//!
//! Does NOT own:
//! - the wire-frame layout — that's `event_modules::connection::wrap`,
//! - admission or `events_canonical` lifecycle math — see
//!   [`crate::state::admission`] and [`crate::state::events_canonical`],
//! - per-event-type projector logic — see `event_modules::*::project_pure`,
//! - context loading semantics — delegated to
//!   [`crate::state::generic_context::load_generic_context`], which reads
//!   the bounded `{event, deps, labels}` set from `events_canonical` +
//!   `labels` (plan.md lines 234-240). No per-event-type SQL.
//!
//! ## Interfaces
//! - [`handle_inbound_bytes`] — full chain entrypoint for `InboundBytes`.
//! - [`handle_ready_event`] — re-runs the parse/context/project/apply tail
//!   for an `events_canonical` row that just transitioned to `ready`.
//! - [`InboundOrigin`] — caller supplies remote endpoint id, IP, port for
//!   provenance.
//! - [`InboundOutcome`] — top-level chain result (Duplicate, UnwrappedFrameOnly,
//!   InnerEventsProcessed, UnwrapFailed).
//! - [`InnerEventDisposition`] / [`InnerEventResult`] — per-inner-event
//!   verdicts.
//! - [`ChainError`] — unrecoverable errors (DB, missing row, write_ops).
//!
//! ## State
//! Reads/writes the following tables in a single transaction:
//! - `inbound_bytes(wire_id, bytes, status, enqueued_at_ms)` — dedupe by
//!   `wire_id = BLAKE3(payload)`,
//! - `inbound_observations(wire_id, ...)` — provenance bump,
//! - `events_canonical` — admission row + lifecycle transitions,
//! - `blocked_by_event` — dependency edges on `Block { missing }`,
//! - projector-specific tables via `WriteOp`s.
//!
//! ## Invariants
//! - All chain effects commit atomically. On any unrecoverable error the
//!   transaction rolls back.
//! - Admission (`admit_event_id`) runs BEFORE parse + context. A `Known`
//!   event id stops the chain immediately.
//! - On parse failure the `events_canonical` row is marked `rejected`
//!   (terminal status; releases the `processing` claim).
//! - On `Block { missing }` the row is marked `blocked` and
//!   `blocked_by_event` rows are written; the chain does not recurse.
//! - `unblock_dependents` flips dependents to `ready` but does NOT recurse:
//!   they sit on the `events.status = 'ready'` queue and are later claimed
//!   as [`super::work_item::WorkItem::ReadyEvent`].
//! - Encrypted events never wrap encrypted events. Nested encryption is
//!   rejected.
//! - For decrypt-and-recurse: the inner `event_id` is `BLAKE3(plaintext)`,
//!   the outer is `BLAKE3(ciphertext)`. They are distinct rows in
//!   `events_canonical`.
//!
//! ## Flow
//! ```text
//!   InboundBytes(payload)
//!     -> wire_id = BLAKE3(payload)
//!     -> inbound_bytes INSERT OR IGNORE         (dedupe)
//!     -> inbound_observations bump              (provenance)
//!     -> connection.unwrap(payload)             (or bootstrap-mode)
//!     -> for each inner_event:
//!          event_id = BLAKE3(inner.bytes)
//!          admit_event_id(event_id)             [Known? STOP : claim row]
//!          parse(inner.bytes)                   [fail? mark rejected, STOP]
//!          finalize_admitted(event_id, bytes)
//!          if Encrypted: decrypt-and-recurse
//!          else:         project + apply
//!          on Valid:  set_status(applied) + unblock_dependents
//!          on Block:  add_blockers(missing)     [status=blocked]
//!          on Reject: set_status(rejected)
//! ```
//!
//! ## Failure / restart behavior
//! - DB error mid-chain → rollback; caller treats as transient.
//! - Crash mid-chain → no rows persist; on restart `startup_recovery` flips
//!   any leftover `processing` rows back to `ready` so the next claim
//!   re-runs.
//! - Encrypted event whose key is missing → outer marked `blocked` on the
//!   workspace `key_event_id`. When the key arrives, the standard
//!   `unblock_dependents` path flips the encrypted row to `ready` and
//!   `handle_ready_event` re-attempts decrypt.
//! - Inner ciphertext fails AEAD → outer marked `rejected`.
//!
//! ## Performance notes
//! - Single transaction per inbound payload bounds commit cost.
//! - `inbound_observations` is bumped via UPDATE + EXISTS probe rather than
//!   `INSERT OR IGNORE` because SQLite treats NULL as distinct in PRIMARY
//!   KEY uniqueness.
//! - Per-inner-event work is `O(payload_size + inner_events)`; no recursion
//!   on `unblock_dependents` keeps the worst case linear.
//!
//! ## Testing hooks
//! - Unit tests at the bottom of this file cover dedupe by wire_id.
//! - `tests/inbound_chain_*.rs` (when present) drive end-to-end inbound
//!   chains under in-memory SQLite.
//!
//! ## Future direction
//! The `parse → context → project → apply` chain is structured as a
//! pipeline of pure stages over deltas plus a context view, which keeps
//! it compatible with a dataflow lowering. See plan.md §"Timely /
//! Differential Proposal" for the dataflow direction this chain is
//! compatible with — projector families could later be expressed as
//! arrangements / consolidated deltas without changing the substrate
//! contract.

use rusqlite::{params, Connection, OptionalExtension};

use crate::event_modules::connection::local_signing_key;
use crate::event_modules::connection::wrap::{unwrap, UnwrapResult};
use crate::event_modules::parse_event;
use crate::state::events_canonical::{set_status, EventStatus};

use super::work_item::{BlakeId, EndpointId};

mod dispatch;
mod encrypted_recurse;
mod observation;
mod sync_maintenance;

pub use observation::record_observation;

use dispatch::{process_inner_events_batched, project_and_apply};

/// Origin metadata for an inbound payload — surfaced in
/// `inbound_observations` for diagnostics + dialing.
#[derive(Debug, Clone, Default)]
pub struct InboundOrigin {
    pub remote_endpoint_id: Option<EndpointId>,
    pub ip: Option<String>,
    pub port: Option<u16>,
}

/// Outcome of processing one inner canonical event inside a wrapped frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerEventDisposition {
    /// `admit_event_id` returned `Known` — admission stopped here.
    AlreadyKnown { status: EventStatus },
    /// Wire bytes failed to parse — events_canonical row was marked
    /// `rejected` to release the `processing` claim.
    ParseFailed { error: String },
    /// Projector returned `Valid`; write_ops applied; row marked `applied`.
    Applied,
    /// Projector returned `Block { missing }`; `blocked_by_event` rows
    /// written; row marked `blocked`.
    Blocked { missing_deps: Vec<BlakeId> },
    /// Projector returned `Reject` — row marked `rejected`.
    Rejected { reason: String },
}

/// Per-inner-event disposition record returned from a chain run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerEventResult {
    pub event_id: BlakeId,
    pub disposition: InnerEventDisposition,
}

/// Top-level outcome of `handle_inbound_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundOutcome {
    /// `wire_id` (BLAKE3 of the entire inbound payload) was already in
    /// `inbound_bytes`. We bumped `inbound_observations` and returned.
    /// Note: a fresh observation row counts as "added", a refresh as not.
    Duplicate {
        wire_id: BlakeId,
        observation_added: bool,
    },
    /// `unwrap` succeeded but produced no inner events (e.g. a bootstrap
    /// frame whose only effect was to mint a connection secret). The
    /// payload was deduped, an observation was logged, and we stopped.
    UnwrappedFrameOnly {
        wire_id: BlakeId,
        observation_added: bool,
    },
    /// `unwrap` produced one or more inner events. `results` carries the
    /// per-event disposition in arrival order.
    InnerEventsProcessed {
        wire_id: BlakeId,
        results: Vec<InnerEventResult>,
    },
    /// `unwrap` failed — the payload was deduped + observed, but we have
    /// no inner events to process. The `inbound_bytes` row's status was
    /// flipped to `invalid`.
    UnwrapFailed {
        wire_id: BlakeId,
        error: String,
    },
}

/// Run the full chained inbound-bytes step.
///
/// All side effects (inbound_bytes dedupe, inbound_observations bump,
/// events_canonical lifecycle, blocked_by_event, projector write_ops,
/// dependents unblocking) happen inside a single transaction held on the
/// passed `Connection`. On any unrecoverable error the transaction is
/// rolled back and an error returned to the caller.
pub fn handle_inbound_bytes(
    bytes: &[u8],
    origin: InboundOrigin,
    db: &Connection,
    now_ms: i64,
) -> Result<InboundOutcome, ChainError> {
    let wire_id = blake3_id(bytes);

    // Begin transaction. We use BEGIN/COMMIT directly because we want to
    // run the whole chain inside one tx and the db-level transaction()
    // helper would borrow `db` mutably and bar passing it down to
    // helpers expecting `&Connection`.
    db.execute("BEGIN IMMEDIATE", []).map_err(ChainError::Db)?;

    let result = (|| -> Result<InboundOutcome, ChainError> {
        // Step 1: dedupe by wire_id.
        let inserted = db
            .execute(
                "INSERT OR IGNORE INTO inbound_bytes
                    (wire_id, bytes, status, enqueued_at_ms)
                 VALUES (?1, ?2, 'pending', ?3)",
                params![wire_id.to_vec(), bytes, now_ms],
            )
            .map_err(ChainError::Db)?;
        let observation_added =
            record_observation(db, &wire_id, &origin, now_ms).map_err(ChainError::Db)?;
        if inserted == 0 {
            return Ok(InboundOutcome::Duplicate {
                wire_id,
                observation_added,
            });
        }
        process_inbound_bytes_after_dedupe(db, &wire_id, bytes, &origin, now_ms, observation_added)
    })();

    match result {
        Ok(outcome) => {
            db.execute("COMMIT", []).map_err(ChainError::Db)?;
            Ok(outcome)
        }
        Err(e) => {
            let _ = db.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// Run the chain on a row whose `inbound_bytes` entry already exists
/// (status `pending` or `processing`). Used by the dispatcher's batch
/// claim path: rows are inserted by the transport bridge, then claimed
/// + processed in a batch transaction by the dispatcher.
///
/// Caller MUST be inside a transaction. This function does NOT manage
/// BEGIN/COMMIT/ROLLBACK and does NOT update inbound_observations
/// (the bridge already recorded the observation when it inserted the
/// row).
pub fn handle_inbound_bytes_for_claimed_in_tx(
    wire_id: &BlakeId,
    bytes: &[u8],
    origin: &InboundOrigin,
    db: &Connection,
    now_ms: i64,
) -> Result<InboundOutcome, ChainError> {
    process_inbound_bytes_after_dedupe(db, wire_id, bytes, origin, now_ms, false)
}

/// Shared body of `handle_inbound_bytes` and the claimed-batch helper.
/// Caller has already ensured the row exists in `inbound_bytes` and is
/// inside a transaction. This runs unwrap → admit → parse → context →
/// project → apply for the inbound payload.
fn process_inbound_bytes_after_dedupe(
    db: &Connection,
    wire_id: &BlakeId,
    bytes: &[u8],
    origin: &InboundOrigin,
    now_ms: i64,
    observation_added: bool,
) -> Result<InboundOutcome, ChainError> {
    // Step 2: connection.unwrap (or raw frame parse for bootstrap frames).
    //
    // ECDH bootstrap-key derivation needs the daemon's PRIVATE signing
    // key, not just `local_endpoint_id`. We resolve it from the
    // sidecar `.<dbname>.signkey` file (same one the binary entry
    // point writes via `api::ensure_signing_key`) and cache it
    // process-wide in `local_signing_key::for_db`. This is the SOLE
    // kernel touch needed for real ECDH — we don't plumb the key
    // through the dispatcher / bridge / runtime; that would balloon
    // the substrate touch into half a dozen files.
    //
    // `origin.remote_endpoint_id` retains its original meaning (the
    // peer endpoint id, when known); it's no longer overloaded as
    // "the local endpoint id" the way the previous blake3-only
    // bootstrap key derivation needed. It's kept on the function
    // signature so the bridge / dispatcher don't have to change.
    let _ = origin;
    let local_signing = local_signing_key::for_db(db);
    let unwrap_res = unwrap(bytes, &local_signing, db);
    let unwrapped: UnwrapResult = match unwrap_res {
        Ok(u) => u,
        Err(e) => {
            db.execute(
                "UPDATE inbound_bytes SET status = 'invalid' WHERE wire_id = ?1",
                params![wire_id.to_vec()],
            )
            .map_err(ChainError::Db)?;
            return Ok(InboundOutcome::UnwrapFailed {
                wire_id: *wire_id,
                error: e.to_string(),
            });
        }
    };

    // Round-state quiet detector: bump last_inbound for this
    // connection so the periodic round-driver tick (run from the
    // sync event-module) suppresses fresh root Compares while
    // traffic is flowing. Bootstrap frames have no connection_id
    // yet — no-op for those, the post_apply path will create the
    // round_state row on first Connection apply.
    if let Some(cid) = unwrapped.connection_id {
        let _ = crate::event_modules::sync::round_state::mark_inbound(db, &cid, now_ms);
    }

    // Bootstrap-mode frames carry the sender's listen addr in the
    // clear so the responder can dial back. Promote that hint into
    // `endpoint_addresses` immediately, before we touch the chain.
    // Best-effort — failures don't block the chain.
    if let (Some(sender), Some(addr_str)) = (
        unwrapped.sender_endpoint_id,
        unwrapped.sender_listen_addr.clone(),
    ) {
        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            let _ =
                crate::runtime::transport_v2::upsert_endpoint_address(db, &sender, &addr);
            // Also seed the in-memory book so the resolution is hot.
            if let Some(ctx) = crate::runtime::control_loop::OutboxWakeContext::current() {
                ctx.address_book.insert(sender, addr);
            }
        }
    }

    if unwrapped.inner_events.is_empty() {
        db.execute(
            "UPDATE inbound_bytes SET status = 'unwrapped_no_inner' WHERE wire_id = ?1",
            params![wire_id.to_vec()],
        )
        .map_err(ChainError::Db)?;
        return Ok(InboundOutcome::UnwrappedFrameOnly {
            wire_id: *wire_id,
            observation_added,
        });
    }

    // Step 3: per-inner-event chain. Two phases:
    //
    //   A. Batched admit+finalize: prefilter inner events for which
    //      `events_canonical` has no row yet, parse their bytes, and
    //      issue ONE multi-row INSERT covering the (event_id, bytes,
    //      workspace_id, scope, status) tuples. Replaces the
    //      `admit_event_id` SELECT+INSERT and the `finalize_admitted`
    //      UPDATE that previously ran per event (3 statements per event
    //      → 1 statement per batch in the common case).
    //
    //   B. Per-event project + apply: still iterates over events one at
    //      a time because the projector dispatch is per-event. The
    //      events_canonical row already carries the bytes/workspace/scope
    //      from the batched INSERT, so project_and_apply only writes a
    //      status UPDATE (and any projector-emitted write_ops).
    //
    // The per-batch ceiling is `MULTI_INSERT_MAX_ROWS` (500). The chain's
    // typical batch size is `DEFAULT_FRAME_BATCH = 32`, well under the
    // cap. Larger batches must chunk in advance — this code splits at the
    // cap defensively and runs the multi-row INSERT once per chunk.
    let mut results: Vec<InnerEventResult> = Vec::with_capacity(unwrapped.inner_events.len());
    process_inner_events_batched(db, &unwrapped.inner_events, now_ms, &mut results)?;

    db.execute(
        "UPDATE inbound_bytes SET status = 'processed' WHERE wire_id = ?1",
        params![wire_id.to_vec()],
    )
    .map_err(ChainError::Db)?;

    let _ = unwrapped.kind; // typed — silence unused warning
    Ok(InboundOutcome::InnerEventsProcessed {
        wire_id: *wire_id,
        results,
    })
}

/// Re-run the parse → context → project → apply tail for an
/// `events_canonical` row that has just transitioned to `ready`.
///
/// Used by `WorkItem::ReadyEvent` dispatch. The events row is loaded by
/// `event_id`, then the tail mirrors the inner-event branch of
/// `handle_inbound_bytes`. Wraps everything in one transaction.
pub fn handle_ready_event(
    event_id: &BlakeId,
    db: &Connection,
    now_ms: i64,
) -> Result<InnerEventDisposition, ChainError> {
    db.execute("BEGIN IMMEDIATE", []).map_err(ChainError::Db)?;
    let result = handle_ready_event_in_tx(event_id, db, now_ms);
    match result {
        Ok(d) => {
            db.execute("COMMIT", []).map_err(ChainError::Db)?;
            Ok(d)
        }
        Err(e) => {
            let _ = db.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// Transaction-aware variant of [`handle_ready_event`]. Runs the parse →
/// context → project → apply tail without managing its own
/// `BEGIN`/`COMMIT`/`ROLLBACK`. The caller MUST have already opened a
/// transaction on the connection and is responsible for the commit /
/// rollback.
///
/// This is used by the batch worker in
/// [`crate::runtime::control_loop::runtime`] so that an entire claim
/// batch (up to MAX_BATCH events) commits in a single SQLite transaction
/// instead of paying a fsync per event. See plan-A in the perf brief.
pub fn handle_ready_event_in_tx(
    event_id: &BlakeId,
    db: &Connection,
    now_ms: i64,
) -> Result<InnerEventDisposition, ChainError> {
    let row: Option<(Vec<u8>, String)> = db
        .query_row(
            "SELECT canonical_event_bytes, status FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(ChainError::Db)?;
    let (canonical_event_bytes, status_str) = match row {
        Some(r) => r,
        None => return Err(ChainError::EventNotFound(*event_id)),
    };
    let status = EventStatus::parse(&status_str).unwrap_or(EventStatus::Processing);
    if status != EventStatus::Ready {
        // Defensive: caller should only enqueue ReadyEvent for ready
        // rows. If somehow not ready, treat as a no-op (Applied if
        // already done, Rejected if rejected, etc.).
        return Ok(match status {
            EventStatus::Applied => InnerEventDisposition::AlreadyKnown { status },
            EventStatus::Rejected => InnerEventDisposition::AlreadyKnown { status },
            EventStatus::Blocked => InnerEventDisposition::AlreadyKnown { status },
            _ => InnerEventDisposition::AlreadyKnown { status },
        });
    }
    // Run parse → context → project → apply.
    let parsed = match parse_event(&canonical_event_bytes) {
        Ok(p) => p,
        Err(e) => {
            set_status(db, event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            let _ = now_ms;
            return Ok(InnerEventDisposition::ParseFailed {
                error: format!("{:?}", e),
            });
        }
    };
    // ReadyEvent has no caller-supplied workspace_id; the helper
    // reads it directly from `events_canonical.workspace_id`
    // populated by `finalize_admitted` when the row was first
    // admitted via `process_inner_event`.
    project_and_apply(db, event_id, &parsed, None)
}

pub fn blake3_id(bytes: &[u8]) -> BlakeId {
    let h = blake3::hash(bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(h.as_bytes());
    id
}

#[allow(dead_code)]
pub(super) fn base64_id(id: &BlakeId) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(id)
}

/// Errors raised by the chain when an unrecoverable condition is hit
/// (DB error, missing row in handle_ready_event, etc.). Per-inner-event
/// dispositions (parse failure, projector reject) are not errors —
/// they're carried in `InnerEventDisposition`.
#[derive(Debug)]
pub enum ChainError {
    Db(rusqlite::Error),
    EventNotFound(BlakeId),
    WriteOps(rusqlite::Error),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Db(e) => write!(f, "db error: {}", e),
            ChainError::EventNotFound(id) => {
                write!(f, "event_id not found in events_canonical: {:?}", id)
            }
            ChainError::WriteOps(e) => write!(f, "write_ops apply: {}", e),
        }
    }
}

impl std::error::Error for ChainError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::connection::local_signing_key;
    use crate::event_modules::connection::wrap::{wrap_bootstrap, InnerCanonicalEvent};
    use crate::state::db::control_loop_tables::ensure_schema as ensure_substrate_schema;
    use ed25519_dalek::SigningKey;

    fn open() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_substrate_schema(&c).unwrap();
        // Tenant projector schema (the test's projector target).
        crate::event_modules::tenant::ensure_schema(&c).unwrap();
        c
    }

    fn tenant_blob() -> Vec<u8> {
        use crate::event_modules::{ParsedEvent, TenantEvent};
        let e = TenantEvent {
            created_at_ms: 1234,
            public_key: [0xABu8; 32],
        };
        crate::event_modules::encode_event(&ParsedEvent::Tenant(e)).unwrap()
    }

    fn wrap_bootstrap_payload(
        blob: Vec<u8>,
        sender_sk: &SigningKey,
        recipient_eid: EndpointId,
    ) -> (Vec<u8>, BlakeId) {
        // Use bootstrap-mode wrap so connection_secrets aren't required.
        let inner = vec![InnerCanonicalEvent {
            workspace_id: [0u8; 32],
            bytes: blob,
        }];
        let frame = wrap_bootstrap(sender_sk, recipient_eid, &inner).unwrap();
        let bytes = frame.as_bytes().to_vec();
        let mut id = [0u8; 32];
        id.copy_from_slice(blake3::hash(&bytes).as_bytes());
        (bytes, id)
    }

    #[test]
    fn dedupes_by_wire_id() {
        let c = open();
        let sender_sk = SigningKey::from_bytes(&[0x11; 32]);
        let recipient_sk = SigningKey::from_bytes(&[0x22; 32]);
        let recipient_eid = recipient_sk.verifying_key().to_bytes();
        // Install the recipient's signing key for this in-memory db so
        // the inbound chain's unwrap can do real ECDH.
        let path = c.path().unwrap_or("").to_string();
        local_signing_key::install_for_path(&path, recipient_sk.clone());
        let (frame, _wire_id) = wrap_bootstrap_payload(tenant_blob(), &sender_sk, recipient_eid);
        let origin = InboundOrigin {
            remote_endpoint_id: Some(sender_sk.verifying_key().to_bytes()),
            ..Default::default()
        };
        // First call: full chain.
        let r1 = handle_inbound_bytes(&frame, origin.clone(), &c, 100).unwrap();
        match r1 {
            InboundOutcome::InnerEventsProcessed { .. } => {}
            other => panic!("expected InnerEventsProcessed, got {:?}", other),
        }
        // Second call with same bytes: dedupe.
        let r2 = handle_inbound_bytes(&frame, origin, &c, 200).unwrap();
        match r2 {
            InboundOutcome::Duplicate { .. } => {}
            other => panic!("expected Duplicate, got {:?}", other),
        }
    }
}
