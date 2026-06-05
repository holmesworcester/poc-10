//! Content-file-deletion semantic adapter.
//!
//! The current file_deletion wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ContentFileDeletionFact;

pub(crate) struct ContentFileDeletionAdapter;

impl Adapter for ContentFileDeletionAdapter {
    type Source = ContentFileDeletionFact;
    type Semantic = ContentFileDeletionFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
