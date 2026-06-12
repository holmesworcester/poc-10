//! Small connection-frame semantic adapter.
//!
//! The current frame_small wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ConnectionFrameSmallFact;

pub(crate) fn adapt(source: ConnectionFrameSmallFact) -> Result<ConnectionFrameSmallFact, String> {
    Ok(source)
}
