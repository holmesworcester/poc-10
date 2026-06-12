//! File-slice connection-frame semantic adapter.
//!
//! The current frame_file_slice wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::ConnectionFrameFileSliceFact;

pub(crate) fn adapt(
    source: ConnectionFrameFileSliceFact,
) -> Result<ConnectionFrameFileSliceFact, String> {
    Ok(source)
}
