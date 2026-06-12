//! Invite-secret semantic adapter.
//!
//! The current invite wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::InviteSecretFact;

pub(crate) fn adapt(source: InviteSecretFact) -> Result<InviteSecretFact, String> {
    Ok(source)
}
