//! Removal-frontier semantic adapter.
//!
//! The current removal_frontier wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::RemovalFrontierFact;

pub(crate) struct RemovalFrontierAdapter;

impl Adapter for RemovalFrontierAdapter {
    type Source = RemovalFrontierFact;
    type Semantic = RemovalFrontierFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
