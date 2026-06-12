//! Bundled connection-frame wire fact payload.

use crate::core::wire::FixedSlot;
use crate::protocol::connection::frame_bundle::encode::CONNECTION_FRAME_BUNDLE_WIRE_BYTES;

pub type ConnectionFrameBundleBytes = FixedSlot<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameBundleFact {
    pub frame: ConnectionFrameBundleBytes,
}
