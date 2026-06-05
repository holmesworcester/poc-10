//! Local recipient key semantic adapter.
//!
//! The current local_recipient_key wire shape is already the active semantic
//! shape. This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::LocalRecipientKeyFact;

pub(crate) struct LocalRecipientKeyAdapter;

impl Adapter for LocalRecipientKeyAdapter {
    type Source = LocalRecipientKeyFact;
    type Semantic = LocalRecipientKeyFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
