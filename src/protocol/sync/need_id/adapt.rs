//! Sync need-id semantic adapter.
//!
//! The current need_id wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::SyncNeedIdFact;

pub(crate) fn adapt(source: SyncNeedIdFact) -> Result<SyncNeedIdFact, String> {
    Ok(source)
}
