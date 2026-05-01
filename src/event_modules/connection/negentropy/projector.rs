//! Projector for `NegentropyEvent`.
//!
//! No durable state: per plan.md line 292-300 these messages are endpoint-
//! local sync hints. The control_loop work-queue picks up parsed events
//! and dispatches `Compare(v)` / `Have(id)` / `Need(id)` / `Send(id)`
//! intents according to range-tree projection. This projector is the
//! parse + project hook the pipeline calls; it intentionally writes
//! nothing and returns the parsed event unchanged so the control loop
//! can act on it.

use rusqlite::Connection;

use super::event::NegentropyEvent;

/// No-op projector. Wire-only event; the control_loop picks up these from
/// the parse stage via the work queue and emits intents directly.
///
/// Returns `Ok(())` always, including for malformed-but-parsed events,
/// because rejection of negentropy hints is the control_loop's call (it
/// may, e.g., drop hints for unknown connections).
pub fn project(_db: &Connection, _ev: &NegentropyEvent) -> rusqlite::Result<()> {
    Ok(())
}
