//! Device-invite semantic adapter.
//!
//! The current device_invite wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::DeviceInviteFact;

pub(crate) fn adapt(source: DeviceInviteFact) -> Result<DeviceInviteFact, String> {
    Ok(source)
}
