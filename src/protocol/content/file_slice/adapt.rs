//! Content-file-slice semantic adapter.
//!
//! The current file_slice wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ContentFileSliceFact;

pub(crate) struct ContentFileSliceAdapter;

impl Adapter for ContentFileSliceAdapter {
    type Source = ContentFileSliceFact;
    type Semantic = ContentFileSliceFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
