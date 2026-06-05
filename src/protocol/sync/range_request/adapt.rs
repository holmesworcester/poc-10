//! Sync range-request semantic adapter.
//!
//! The current range_request wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::SyncRangeRequestFact;

pub(crate) struct SyncRangeRequestAdapter;

impl Adapter for SyncRangeRequestAdapter {
    type Source = SyncRangeRequestFact;
    type Semantic = SyncRangeRequestFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
