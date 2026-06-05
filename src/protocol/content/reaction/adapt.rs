//! Content-reaction semantic adapter.
//!
//! The current reaction wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ContentReactionFact;

pub(crate) struct ContentReactionAdapter;

impl Adapter for ContentReactionAdapter {
    type Source = ContentReactionFact;
    type Semantic = ContentReactionFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
