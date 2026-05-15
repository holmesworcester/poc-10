//! Sync need-id fact shape for the poc-10 target tree.
//!
//! A need-id asks the peer to send bytes for exactly one event id. The fact
//! is connection-scoped so duplicate requests from different peers do not
//! collapse into one route-level response.
//!
//! Transit wrapping (delivering the request on a connection and answering
//! it by queuing the requested event) is owned by transit handlers; this
//! module owns only the fact shape and projection row.

use crate::core::facts::FactId;

pub type ConnectionId = FactId;
pub type EventId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncNeedIdFact {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
}
