use crate::core::facts::FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionResponseReceivedFact {
    pub response_id: FactId,
    pub request_id: FactId,
    pub receive_id: FactId,
    pub received_at_local_ms: u64,
}
