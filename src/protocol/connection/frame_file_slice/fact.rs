//! File-slice connection-frame wire fact payload.

use crate::core::wire::FixedSlot;
use crate::protocol::connection_frame_wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES;

pub type ConnectionFrameFileSliceBytes = FixedSlot<CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameFileSliceFact {
    pub frame: ConnectionFrameFileSliceBytes,
}
