//! `sync` event-module family.
//!
//! Per `plan.md` line 21 ("Sync is an event-module family, not a separate sync
//! engine") and lines 295-430 (Appendix: negentropy / dependencies / dedupe),
//! sync facts flow through the same event pipeline as everything else:
//!
//! - `compare` — the negentropy compare-this-node hint (`(connection, workspace,
//!   node_id, fingerprint)`); replaces what earlier phases called `negentropy`.
//! - `have`    — "I have this id" hint emitted when a leaf compare detects a
//!   remote-claimed id we may need.
//! - `need`    — "I need this id" hint; the receiving projector (when local
//!   has it) writes `outbox(connection_id, event_id)` to send the actual event
//!   (per `plan.md` line 379).
//!
//! Plus two projected materialized state tables that feed the comparison:
//!
//! - `negentropy_tree` — per-node `(R_v, X_v∩P)` materialized hashes (plan.md
//!   lines 343-361). Updated incrementally as roots and deps land.
//! - `dep_cache`       — flattened transitive dependency closure `D(r)` per
//!   root event (plan.md lines 324-328). Computed on root insert.
//!
//! The compare/have/need projectors are **stubs** in this scaffold: they
//! register with the registry and write a single placeholder row each, with
//! the real algorithm specified in doc-comments and a TODO for the next
//! phase. The negentropy_tree maintenance routine and dep_cache transitive
//! closure helpers ARE real (the algorithm is small enough).

pub mod compare;
pub mod dep_cache;
pub mod have;
pub mod job;
pub mod maintenance;
pub mod need;
pub mod negentropy_tree;
pub mod round_state;

pub use compare::{CompareEvent, COMPARE_TYPE_CODE};
pub use have::{HaveEvent, HAVE_TYPE_CODE};
pub use maintenance::{after_durable_apply, deps_of_event};
pub use need::{NeedEvent, NEED_TYPE_CODE};

use rusqlite::Connection;

/// Create every table owned by the sync family. Idempotent.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    compare::ensure_schema(conn)?;
    have::ensure_schema(conn)?;
    need::ensure_schema(conn)?;
    negentropy_tree::ensure_schema(conn)?;
    dep_cache::ensure_schema(conn)?;
    round_state::ensure_schema(conn)?;
    Ok(())
}
