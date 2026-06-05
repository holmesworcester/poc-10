//! Local history-node secret semantic adapter.
//!
//! The current local_history_node_secret wire shape is already the active
//! semantic shape. This identity adapter keeps the staged route explicit and
//! gives future versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::LocalHistoryNodeSecretFact;

pub(crate) struct LocalHistoryNodeSecretAdapter;

impl Adapter for LocalHistoryNodeSecretAdapter {
    type Source = LocalHistoryNodeSecretFact;
    type Semantic = LocalHistoryNodeSecretFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
