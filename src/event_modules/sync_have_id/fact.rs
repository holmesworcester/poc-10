//! Sync have-id fact shape for the poc-10 target tree.
//!
//! A have-id advertises one durable event id at the timestamp used by the
//! range compare that exposed it. Receivers verify presence by event id
//! before asking for bytes, so this fact is cheap to duplicate and dedupe.
//!
//! Transit wrapping (routing on a connection) is owned by a transit handler;
//! this module owns only the fact shape and projection row.

use crate::core::facts::FactId;

pub type ConnectionId = FactId;
pub type EventId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncHaveIdFact {
    pub connection_id: ConnectionId,
    pub timestamp: u64,
    pub event_id: EventId,
}
