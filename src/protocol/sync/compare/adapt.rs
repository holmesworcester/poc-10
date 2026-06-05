//! Sync compare semantic adapter.
//!
//! The current compare wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::SyncCompareFact;

pub(crate) struct SyncCompareAdapter;

impl Adapter for SyncCompareAdapter {
    type Source = SyncCompareFact;
    type Semantic = SyncCompareFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
