//! Sync need-id semantic adapter.
//!
//! The current need_id wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::SyncNeedIdFact;

pub(crate) struct SyncNeedIdAdapter;

impl Adapter for SyncNeedIdAdapter {
    type Source = SyncNeedIdFact;
    type Semantic = SyncNeedIdFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
