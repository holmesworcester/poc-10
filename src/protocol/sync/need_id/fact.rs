//! Sync need-id fact shape for the poc-10 target tree.
//!
//! A need-id asks the peer to send bytes for exactly one fact id. The fact
//! is connection-scoped so duplicate requests from different peers do not
//! collapse into one route-level response.
//!
//! Connection-frame wrapping (delivering the request on a connection and answering
//! it by queuing the requested fact) is owned by connection::frame handlers; this
//! module owns only the fact shape and projection row.

use crate::core::facts::FactId;

pub type ConnectionId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncNeedIdFact {
    pub connection_id: ConnectionId,
    pub fact_id: FactId,
}
