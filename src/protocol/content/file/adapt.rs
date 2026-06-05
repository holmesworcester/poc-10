//! Content-file semantic adapter.
//!
//! The current file wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ContentFileFact;

pub(crate) struct ContentFileAdapter;

impl Adapter for ContentFileAdapter {
    type Source = ContentFileFact;
    type Semantic = ContentFileFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
