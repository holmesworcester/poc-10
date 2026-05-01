//! `CompareEvent`: negentropy compare-this-node hint.
//!
//! Per `plan.md` lines 308-316 + 365-369: scoped to a `(connection_id,
//! workspace_id)` pair, addressed at a specific `node_id` (range-tree path
//! identifier), carrying the remote-computed 32-byte `fingerprint` for that
//! node. Not signed — the connection itself authenticates the endpoint pair.

use crate::runtime::control_loop::work_item::{ConnectionId, WorkspaceId};

/// Wire type code (sync compare).
pub const COMPARE_TYPE_CODE: u8 = 41;

/// Compare-this-node fragment.
///
/// `node_id` is the variable-length range-tree path identifier; `fingerprint`
/// is the 32-byte digest the remote computed for that node's contents
/// (`F_v = Hset("root", R_v) + Hset("dep", X_v ∩ P)` per plan.md lines
/// 332-345).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub connection_id: ConnectionId,
    pub workspace_id: WorkspaceId,
    pub node_id: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub created_at_ms: u64,
}

impl crate::event_modules::Describe for CompareEvent {
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

impl CompareEvent {
    /// Bytes that would be signed if this event were ever endpoint-scoped
    /// signed. Provided for consistency with other event modules; sync
    /// events are normally unsigned (plan.md line 365).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 2 + self.node_id.len() + 32 + 8);
        out.extend_from_slice(&self.connection_id);
        out.extend_from_slice(&self.workspace_id);
        out.extend_from_slice(&(self.node_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.fingerprint);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out
    }
}
