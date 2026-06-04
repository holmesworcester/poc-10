use crate::core::facts::FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestReceivedFact {
    pub request_id: FactId,
    pub receive_id: FactId,
    pub received_at_local_ms: u64,
}
