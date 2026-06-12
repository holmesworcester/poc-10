//! User-invite semantic adapter.
//!
//! The current user_invite wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::UserInviteFact;

pub(crate) fn adapt(source: UserInviteFact) -> Result<UserInviteFact, String> {
    Ok(source)
}
