//! `SyncWindowEvent`: per-workspace range/window selector.

use crate::runtime::control_loop::work_item::{ConnectionId, WorkspaceId};

/// Wire type code (per plan.md line: `sync_window = 40`).
pub const SYNC_WINDOW_TYPE_CODE: u8 = 40;

/// Pre-defined window kinds; encoded as a u8 on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowKind {
    LastDay,
    LastWeek,
    Recent,
    Full,
}

impl SyncWindowKind {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::LastDay => 1,
            Self::LastWeek => 2,
            Self::Recent => 3,
            Self::Full => 4,
        }
    }

    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::LastDay),
            2 => Some(Self::LastWeek),
            3 => Some(Self::Recent),
            4 => Some(Self::Full),
            _ => None,
        }
    }
}

/// Sync-window selector. `(begin_ms, end_ms)` are inclusive bounds; the
/// `kind` is a redundant tag for human-readable diagnostics. Both are
/// validated together by the consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncWindowEvent {
    pub connection_id: ConnectionId,
    pub workspace_id: WorkspaceId,
    pub kind: SyncWindowKind,
    pub begin_ms: u64,
    pub end_ms: u64,
    pub created_at_ms: u64,
}

impl crate::event_modules::Describe for SyncWindowEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let kind_s = match self.kind {
            SyncWindowKind::LastDay => "last_day",
            SyncWindowKind::LastWeek => "last_week",
            SyncWindowKind::Recent => "recent",
            SyncWindowKind::Full => "full",
        };
        vec![
            (
                "connection_id",
                crate::event_modules::short_id_b64(&self.connection_id),
            ),
            (
                "workspace_id",
                crate::event_modules::short_id_b64(&self.workspace_id),
            ),
            ("kind", kind_s.to_string()),
        ]
    }
}
