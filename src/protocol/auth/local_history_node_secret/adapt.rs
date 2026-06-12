//! Local history-node secret semantic adapter.
//!
//! The current local_history_node_secret wire shape is already the active
//! semantic shape. This identity adapter keeps the staged route explicit and
//! gives future versioned facts a dedicated conversion point.

use super::fact::LocalHistoryNodeSecretFact;

pub(crate) fn adapt(
    source: LocalHistoryNodeSecretFact,
) -> Result<LocalHistoryNodeSecretFact, String> {
    Ok(source)
}
