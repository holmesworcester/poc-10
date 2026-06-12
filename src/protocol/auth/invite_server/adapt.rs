//! Invite-server semantic adapter.
//!
//! The current invite_server wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::InviteServerFact;

pub(crate) fn adapt(source: InviteServerFact) -> Result<InviteServerFact, String> {
    Ok(source)
}
