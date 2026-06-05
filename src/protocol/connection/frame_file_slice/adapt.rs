//! File-slice connection-frame semantic adapter.
//!
//! The current frame_file_slice wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionFrameFileSliceFact;

pub(crate) struct ConnectionFrameFileSliceAdapter;

impl Adapter for ConnectionFrameFileSliceAdapter {
    type Source = ConnectionFrameFileSliceFact;
    type Semantic = ConnectionFrameFileSliceFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
