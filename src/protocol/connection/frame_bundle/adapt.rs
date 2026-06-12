//! Bundled connection-frame semantic adapter.
//!
//! The current frame_bundle wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ConnectionFrameBundleFact;

pub(crate) fn adapt(
    source: ConnectionFrameBundleFact,
) -> Result<ConnectionFrameBundleFact, String> {
    Ok(source)
}
