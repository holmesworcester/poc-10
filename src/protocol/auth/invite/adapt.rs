//! Invite-secret semantic adapter.
//!
//! The current invite wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::InviteSecretFact;

pub(crate) struct InviteSecretAdapter;

impl Adapter for InviteSecretAdapter {
    type Source = InviteSecretFact;
    type Semantic = InviteSecretFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
