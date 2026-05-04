//! Need-id event type.
//!
//! The item is connection-scoped so duplicate requests from different peers do
//! not collapse into one route-level response.

use crate::protocol::event_modules::sync::types::SyncDirection;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedIdEvent {
    pub direction: SyncDirection,
    pub connection_id: EventId,
    pub id: EventId,
}
