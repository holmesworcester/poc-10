//! Received connection-frame observation payload.

use crate::core::facts::FactId;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameObservationFact {
    pub frame_fact_id: FactId,
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
}
