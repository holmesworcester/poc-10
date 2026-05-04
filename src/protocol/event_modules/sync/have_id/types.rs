//! Have-id event type.
//!
//! The bucket is included so receivers can relate an advertised id to the
//! compare summary that caused it, while still verifying presence by event id.

use crate::protocol::event_modules::sync::types::SyncDirection;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaveIdEvent {
    pub direction: SyncDirection,
    pub connection_id: EventId,
    pub bucket: u8,
    pub id: EventId,
}
