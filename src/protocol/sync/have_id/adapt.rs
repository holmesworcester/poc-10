//! Sync have-id semantic adapter.
//!
//! The current have_id wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::SyncHaveIdFact;

pub(crate) struct SyncHaveIdAdapter;

impl Adapter for SyncHaveIdAdapter {
    type Source = SyncHaveIdFact;
    type Semantic = SyncHaveIdFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
