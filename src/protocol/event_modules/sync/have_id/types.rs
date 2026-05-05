//! Have-id event type.
//!
//! The timestamp is the sync key used by the range compare that exposed this
//! id. Receivers still verify presence by event id before asking for bytes.

use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaveIdEvent {
    pub connection_id: EventId,
    pub timestamp: u64,
    pub id: EventId,
}
