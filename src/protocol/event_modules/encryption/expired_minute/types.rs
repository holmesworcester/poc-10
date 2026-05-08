//! Local-only `expired_minute` event.
//!
//! When a workspace's TTL elapses past a `unix_minute` boundary, the
//! `disappearing_minute_expiry` daemon-step worker emits one
//! `expired_minute` event per `(workspace_id, removal_frontier_id, unix_minute)`
//! coordinate. The event id is `BLAKE3(canonical bytes)`; both peers reach
//! the same id deterministically because every byte of the canonical input
//! is shared workspace state.
//!
//! Slice 1 sources the TTL from the workspace event's
//! `disappearing_ttl_minutes` field. Slice 2 will introduce a shared
//! admin-signed `disappearing_messages_setting` event whose id can be
//! threaded into `source_setting_id` here without changing the wire shape
//! beyond a field rename.

use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredMinuteEvent {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub unix_minute: u64,
    /// Local id of the minute_node row being retired. Both peers compute
    /// the same id deterministically from the shared frontier secret, so
    /// including it in canonical bytes keeps the event id deterministic
    /// across peers and lets the projector write a tombstone row without
    /// querying storage.
    pub retired_minute_node_id: EventId,
}
