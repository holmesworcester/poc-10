//! Invite-accepted semantic adapter.
//!
//! The current invite_accepted wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::InviteAcceptedFact;

pub(crate) fn adapt(source: InviteAcceptedFact) -> Result<InviteAcceptedFact, String> {
    Ok(source)
}
