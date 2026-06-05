//! User-invite semantic adapter.
//!
//! The current user_invite wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::UserInviteFact;

pub(crate) struct UserInviteAdapter;

impl Adapter for UserInviteAdapter {
    type Source = UserInviteFact;
    type Semantic = UserInviteFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
