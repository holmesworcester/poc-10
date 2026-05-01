//! # Admission (admit_event_id)
//!
//! ## Purpose
//! Re-exports the `admit_event_id` contract from
//! [`crate::state::events_canonical`] under the name the inbound chain
//! reads with. Admission is the BLAKE3-keyed gate that runs BEFORE parse
//! and context for every inner event in the chain (`plan.md` line 43).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the contract name. The implementation is one re-export — see
//!   [`admit_event_id`].
//!
//! Does NOT own:
//! - the row layout, lifecycle, or unblock semantics — those live in
//!   [`crate::state::events_canonical`],
//! - observation recording or sync `suppress_received(id)` — those are the
//!   caller's responsibility on a `Known` result.
//!
//! ## Interfaces
//! - [`admit_event_id`] — claim or recognise an event id.
//! - [`AdmissionResult::Known`] / [`AdmissionResult::NewlyClaimed`] — the
//!   two outcomes; `Known` carries the existing row's [`EventStatus`].
//!
//! ## State
//! Reads/writes one row of `events_canonical` per call.
//!
//! ## Invariants
//! - Admission happens BEFORE parse + context.
//! - Known event ids cover all four terminal-or-pending statuses
//!   (`processing`, `applied`, `blocked`, `rejected`, `ready`) — the chain
//!   stops on every one.
//! - On `NewlyClaimed`, the row is inserted with `status = 'processing'`,
//!   `scope = 'durable'`, empty `canonical_event_bytes`, and the current
//!   `created_at_ms`. The caller is expected to `finalize_admitted` after
//!   parse succeeds.
//!
//! ## Flow
//! ```text
//!   InboundBytes
//!     -> connection.unwrap / raw frame parse -> CanonicalEventBytes
//!     -> event_id = BLAKE3(CanonicalEventBytes)
//!     -> admit_event_id(event_id)             <-- this module
//!     -> [Known? STOP : claim row + continue]
//!     -> parse(CanonicalEventBytes)
//!     -> get_context(Event)
//!     -> project(EventWithContext)
//!     -> apply(StateUpdates)
//! ```
//!
//! ## Failure / restart behavior
//! - DB error propagates. Caller's transaction rolls back; the chain treats
//!   it as transient.
//! - On crash mid-admission, `startup_recovery` flips any leftover
//!   `processing` rows back to `ready` so the next claim re-runs.
//!
//! ## Performance notes
//! - One `SELECT status` + at most one `INSERT` per call. Both indexed by
//!   `event_id`.
//!
//! ## Testing hooks
//! Tests live alongside the implementation in
//! [`crate::state::events_canonical`].

pub use crate::state::events_canonical::{admit_event_id, AdmissionResult, EventStatus};
