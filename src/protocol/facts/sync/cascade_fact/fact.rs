use crate::core::facts::FactId;

pub const MAX_DEPS: usize = 10;
pub const PAYLOAD_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeFact {
    pub timestamp: u64,
    pub dependencies: Vec<FactId>,
    pub payload: [u8; PAYLOAD_BYTES],
}
