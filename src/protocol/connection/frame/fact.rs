//! Ephemeral connection-frame projection inputs.
//!
//! Small and large frame facts store the same local receive metadata and raw
//! encrypted frame bytes. The public size-class byte chooses which fact tag is
//! emitted before projection, so the projector can decode the expected fixed
//! outer frame shape without durable storage of the raw network input.
//!
//! These facts are local and ephemeral. They may use durable connection context
//! to open the frame, but they must not publish standing durable context
//! themselves; opened child facts and receipts carry the durable result.

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
