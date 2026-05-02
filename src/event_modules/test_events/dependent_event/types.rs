use crate::store::EventId;

pub const MAX_DEPS: usize = 10;
pub const PAYLOAD_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentEvent {
    pub timestamp: u64,
    pub dependencies: Vec<EventId>,
    pub payload: [u8; PAYLOAD_BYTES],
}
