//! Content-event fact shape for the poc-10 target tree.
//!
//! Content events carry an opaque payload used for storage and sync throughput
//! testing. The payload's bytes are not interpreted; only the byte count is
//! surfaced through the projection row.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentEventFact {
    pub workspace_id: WorkspaceId,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}
