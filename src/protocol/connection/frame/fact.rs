//! Ephemeral connection-frame projection inputs.
//!
//! Small, file-slice, and bundle frame facts store the same local receive
//! metadata and raw encrypted frame bytes. The public size-class byte chooses
//! which fact tag is emitted before projection, so the projector can decode the
//! expected fixed outer frame shape without durable storage of the raw network
//! input.
//!
//! These facts are local and ephemeral. They may use durable connection context
//! to open the frame, but they must not publish standing durable context
//! themselves; opened child facts and receipts carry the durable result.

use crate::core::wire::FixedSlot;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

use super::layout::{
    CONNECTION_FRAME_BUNDLE_WIRE_BYTES, CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES,
    CONNECTION_FRAME_SMALL_WIRE_BYTES,
};

pub type ConnectionFrameSmallBytes = FixedSlot<CONNECTION_FRAME_SMALL_WIRE_BYTES>;
pub type ConnectionFrameFileSliceBytes = FixedSlot<CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES>;
pub type ConnectionFrameBundleBytes = FixedSlot<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameSmallFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub frame: ConnectionFrameSmallBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameFileSliceFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub frame: ConnectionFrameFileSliceBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameBundleFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub frame: ConnectionFrameBundleBytes,
}
