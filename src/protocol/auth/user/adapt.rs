//! User semantic adapter.
//!
//! The current user wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::UserFact;

pub(crate) fn adapt(source: UserFact) -> Result<UserFact, String> {
    Ok(source)
}
