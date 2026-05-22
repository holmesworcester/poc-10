//! Transient transport::transit projection input facts.
//!
//! A `TransitInputFact` is the projectable shape for one inbound transit frame.
//! It records the normalized origin, local receive time, and raw frame bytes so
//! the transit projector can unwrap the frame using durable context. Core keeps
//! these inputs in ephemeral projection storage; successful projection emits the
//! durable protocol facts carried by the frame plus transit-received provenance.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitInputFact {
    pub origin_addr: Vec<u8>,
    pub received_at_local_ms: u64,
    pub frame: Vec<u8>,
}
