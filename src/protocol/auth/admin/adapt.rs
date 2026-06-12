//! Admin-grant semantic adapter.
//!
//! The current admin wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::AdminFact;

pub(crate) fn adapt(source: AdminFact) -> Result<AdminFact, String> {
    Ok(source)
}
