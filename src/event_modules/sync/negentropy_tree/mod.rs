//! `sync::negentropy_tree`: projected materialized state for the dep-aware
//! negentropy fingerprint per `plan.md` lines 343-361.
//!
//! Three tables:
//!
//! - `negentropy_root_membership(workspace_id, node_id, event_id)` — which
//!   root events sit inside which range-tree node `v` (`R_v`).
//! - `negentropy_dep_refcount(workspace_id, node_id, dep_event_id, refcount,
//!   present_locally)` — the external-dep requirement set `X_v` minus the
//!   roots inside `v`. Refcounts handle multiple roots sharing the same dep
//!   so 0→1 transitions add to `dep_hash` and 1→0 transitions remove.
//! - `negentropy_node_hash(workspace_id, node_id, root_hash, dep_hash)` —
//!   the two domain-separated XOR hashes whose combination is the per-node
//!   fingerprint `F_v`.
//!
//! The maintenance routine (`update.rs`) runs incrementally on root insert
//! and on dep-presence transitions.

pub mod query;
pub mod schema;
pub mod state;
pub mod update;

#[cfg(test)]
pub mod mod_test;

pub use query::node_fingerprint;
pub use update::{on_event_present, on_root_inserted};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    schema::ensure_schema(conn)
}
