//! Content-message semantic adapter.
//!
//! The current content-message wire shape is already the active semantic
//! shape. This identity adapter keeps the staged route explicit and gives
//! future versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ContentMessageFact;

pub(crate) struct ContentMessageAdapter;

impl Adapter for ContentMessageAdapter {
    type Source = ContentMessageFact;
    type Semantic = ContentMessageFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
