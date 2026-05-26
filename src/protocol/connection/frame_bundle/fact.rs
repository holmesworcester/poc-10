//! Bundled connection-frame receive fact payload.

use crate::core::wire::FixedSlot;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;
use crate::protocol::connection::frame::wire::CONNECTION_FRAME_BUNDLE_WIRE_BYTES;

pub type ConnectionFrameBundleBytes = FixedSlot<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameBundleFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub frame: ConnectionFrameBundleBytes,
}
