//! Recipient key semantic adapter.
//!
//! The current recipient_key wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::RecipientKeyFact;

pub(crate) struct RecipientKeyAdapter;

impl Adapter for RecipientKeyAdapter {
    type Source = RecipientKeyFact;
    type Semantic = RecipientKeyFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
