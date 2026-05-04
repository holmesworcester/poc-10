//! Content event type.
//!
//! The timestamp orders generated events for repeatable tests; the payload is
//! opaque shared data used to exercise storage and sync throughput.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentEvent {
    pub timestamp: u64,
    pub payload: Vec<u8>,
}
