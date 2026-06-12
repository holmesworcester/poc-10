//! Sync have-id semantic adapter.
//!
//! The current have_id wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::SyncHaveIdFact;

pub(crate) fn adapt(source: SyncHaveIdFact) -> Result<SyncHaveIdFact, String> {
    Ok(source)
}
