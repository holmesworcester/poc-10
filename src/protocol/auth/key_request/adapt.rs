//! Key-request semantic adapter.
//!
//! The current key_request wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::KeyRequestFact;

pub(crate) fn adapt(source: KeyRequestFact) -> Result<KeyRequestFact, String> {
    Ok(source)
}
