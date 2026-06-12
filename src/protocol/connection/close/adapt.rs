//! Connection-close semantic adapter.
//!
//! The current close wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ConnectionCloseFact;

pub(crate) fn adapt(source: ConnectionCloseFact) -> Result<ConnectionCloseFact, String> {
    Ok(source)
}
