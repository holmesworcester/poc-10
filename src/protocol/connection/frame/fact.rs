//! Ephemeral encrypted connection-frame facts.
//!
//! A connection frame is already classified by its public size-class byte when
//! it enters the fact pipeline. The small and large fact types carry the same
//! local receive metadata and raw encrypted frame bytes; the type tag records
//! which fixed outer shape was observed. Projection uses durable connection
//! context to open the frame and emits durable child facts plus connection fact
//! receipts.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameSmallFact {
    pub origin_addr: Vec<u8>,
    pub received_at_local_ms: u64,
    pub frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameLargeFact {
    pub origin_addr: Vec<u8>,
    pub received_at_local_ms: u64,
    pub frame: Vec<u8>,
}
