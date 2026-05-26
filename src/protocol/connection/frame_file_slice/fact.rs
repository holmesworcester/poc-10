//! File-slice connection-frame receive fact payload.

use crate::core::wire::FixedSlot;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;
use crate::protocol::connection_frame_wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES;

pub type ConnectionFrameFileSliceBytes = FixedSlot<CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameFileSliceFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub frame: ConnectionFrameFileSliceBytes,
}
