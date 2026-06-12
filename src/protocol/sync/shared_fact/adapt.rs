//! Sync shared-fact semantic adapter.
//!
//! The current shared_fact wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::SharedFact;

pub(crate) fn adapt(source: SharedFact) -> Result<SharedFact, String> {
    Ok(source)
}
