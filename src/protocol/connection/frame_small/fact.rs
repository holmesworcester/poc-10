//! Small connection-frame wire fact payload.

use crate::core::wire::FixedSlot;
use crate::protocol::connection_frame_wire::CONNECTION_FRAME_SMALL_WIRE_BYTES;

pub type ConnectionFrameSmallBytes = FixedSlot<CONNECTION_FRAME_SMALL_WIRE_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameSmallFact {
    pub frame: ConnectionFrameSmallBytes,
}
