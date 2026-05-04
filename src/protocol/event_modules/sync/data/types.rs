//! Sync data item type.
//!
//! `items` are raw canonical event bytes scoped to one connection. They are not
//! trusted as applied state until admitted by the common worker.

use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataEvent {
    pub connection_id: EventId,
    pub items: Vec<Vec<u8>>,
}
