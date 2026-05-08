//! Local-only `expired_minute` event module.
//!
//! Scope: one `expired_minute` event per `(workspace_id,
//! removal_frontier_id, unix_minute)` whose authored-time TTL has elapsed
//! past the local logical clock. The `disappearing_minute_expiry` worker
//! emits these events; both peers derive byte-identical canonical bytes
//! from shared workspace + frontier state, so the event id and the
//! projector output converge across peers without crossing the wire.
//!
//! Dependencies: the `removal_frontier` event for the named frontier and
//! the `local_history_node_secret` event for the retired minute_node.
//! Both must be `Applied` before this event projects.
//!
//! Projection writes one tombstone row in
//! `LOCAL_HISTORY_NODE_TOMBSTONES` and exact-row-deletes the minute_node
//! row in `LOCAL_HISTORY_NODE_SECRETS`. Cleanup of the leaves under the
//! minute, the read-model and sealed message rows, and canonical message
//! bytes is the worker's job — projectors are row-only by RULES.md and
//! must not perform retention or canonical-bytes purges.
//!
//! Non-responsibilities: this module does NOT own the workspace TTL
//! setting (slice 1 sources it from the workspace event; slice 2 will
//! add a shared admin-signed setting event), it does NOT decide which
//! minutes are expired (the `disappearing_minute_expiry` worker reads
//! `logical_clock::logical_time` for that), and it does NOT define a
//! per-minute summary distinct from the existing retained `cover_summary`
//! (slice 3 "deletion summary monotonicity" is the place for that work).

pub mod codec;
pub mod commands;
pub mod projector;
pub mod types;
