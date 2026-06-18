//! Typed value carried by local protocol update facts.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateFact {
    pub protocol_version: u32,
    pub applied_at_ms: u64,
}
