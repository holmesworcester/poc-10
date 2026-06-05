//! Sync shared-fact semantic adapter.
//!
//! The current shared_fact wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::SharedFact;

pub(crate) struct SyncSharedFactAdapter;

impl Adapter for SyncSharedFactAdapter {
    type Source = SharedFact;
    type Semantic = SharedFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
