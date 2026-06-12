//! Key-wrap semantic adapter.
//!
//! The current key_wrap wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::KeyWrapFact;

pub(crate) fn adapt(source: KeyWrapFact) -> Result<KeyWrapFact, String> {
    Ok(source)
}
