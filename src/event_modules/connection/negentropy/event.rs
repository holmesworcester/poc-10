//! `NegentropyEvent`: sync-compare message scoped to (connection, workspace).
//!
//! Per plan.md line 292-300: not signed; the connection itself authenticates
//! the endpoint pair, and the message is only a hint.

use crate::runtime::control_loop::work_item::{ConnectionId, WorkspaceId};

/// Wire type code (per plan.md line: `negentropy = 39`).
pub const NEGENTROPY_TYPE_CODE: u8 = 39;

/// Compare-this-node fragment. `node_id` is the range-tree path (variable
/// length); `fingerprint` is a 32-byte digest the remote computed for that
/// node's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegentropyEvent {
    pub connection_id: ConnectionId,
    pub workspace_id: WorkspaceId,
    pub node_id: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub created_at_ms: u64,
}

impl crate::event_modules::Describe for NegentropyEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "connection_id",
                crate::event_modules::short_id_b64(&self.connection_id),
            ),
            (
                "workspace_id",
                crate::event_modules::short_id_b64(&self.workspace_id),
            ),
            ("node_id_len", self.node_id.len().to_string()),
        ]
    }
}
