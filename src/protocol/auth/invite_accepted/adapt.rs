//! Invite-accepted semantic adapter.
//!
//! The current invite_accepted wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::InviteAcceptedFact;

pub(crate) struct InviteAcceptedAdapter;

impl Adapter for InviteAcceptedAdapter {
    type Source = InviteAcceptedFact;
    type Semantic = InviteAcceptedFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
