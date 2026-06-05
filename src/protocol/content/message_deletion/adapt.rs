//! Content-message-deletion semantic adapter.
//!
//! The current message_deletion wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ContentMessageDeletionFact;

pub(crate) struct ContentMessageDeletionAdapter;

impl Adapter for ContentMessageDeletionAdapter {
    type Source = ContentMessageDeletionFact;
    type Semantic = ContentMessageDeletionFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
