//! Need-id event type.
//!
//! The item is connection-scoped so duplicate requests from different peers do
//! not collapse into one route-level response.

use crate::legacy::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedIdEvent {
    pub connection_id: EventId,
    pub id: EventId,
}
