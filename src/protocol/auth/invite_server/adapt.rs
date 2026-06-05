//! Invite-server semantic adapter.
//!
//! The current invite_server wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::InviteServerFact;

pub(crate) struct InviteServerAdapter;

impl Adapter for InviteServerAdapter {
    type Source = InviteServerFact;
    type Semantic = InviteServerFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
