use crate::core::store::EventId;

pub const MAX_DEPS: usize = 10;
pub const PAYLOAD_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDeps {
    pub timestamp: u64,
    pub dependencies: Vec<EventId>,
    pub payload: [u8; PAYLOAD_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEventWithDeps {
    pub index: u64,
    pub inner_bytes: Vec<u8>,
}
