//! Device-invite semantic adapter.
//!
//! The current device_invite wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::DeviceInviteFact;

pub(crate) struct DeviceInviteAdapter;

impl Adapter for DeviceInviteAdapter {
    type Source = DeviceInviteFact;
    type Semantic = DeviceInviteFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
