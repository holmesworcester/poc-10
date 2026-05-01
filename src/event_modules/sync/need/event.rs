//! `NeedEvent`: "I need this event_id, please send it" hint.
//!
//! Endpoint-local sync hint scoped to `(connection_id, workspace_id)`. Not
//! signed: the surrounding connection authenticates the endpoint pair.

use crate::runtime::control_loop::work_item::{BlakeId, ConnectionId, WorkspaceId};

pub const NEED_TYPE_CODE: u8 = 43;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedEvent {
    pub connection_id: ConnectionId,
    pub workspace_id: WorkspaceId,
    pub event_id: BlakeId,
    pub created_at_ms: u64,
}

impl crate::event_modules::Describe for NeedEvent {
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
            ("event_id", crate::event_modules::short_id_b64(&self.event_id)),
        ]
    }
}

impl NeedEvent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 8);
        out.extend_from_slice(&self.connection_id);
        out.extend_from_slice(&self.workspace_id);
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out
    }
}
