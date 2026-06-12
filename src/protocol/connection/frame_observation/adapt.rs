//! Connection-frame observation semantic adapter.
//!
//! The current frame_observation wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::ConnectionFrameObservationFact;

pub(crate) fn adapt(
    source: ConnectionFrameObservationFact,
) -> Result<ConnectionFrameObservationFact, String> {
    Ok(source)
}
