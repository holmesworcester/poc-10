//! Local history-node secret fact construction helpers.

use crate::core::crypto::XChaCha20Poly1305Key;
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::LocalHistoryNodeSecretFact;

#[allow(clippy::too_many_arguments)]
pub fn history_node_secret_fact(
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    source_secret_id: FactId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
    tombstone_node_id: FactId,
    node_secret: XChaCha20Poly1305Key,
    created_at_ms: u64,
) -> Result<(LocalHistoryNodeSecretFact, Fact), String> {
    let secret = LocalHistoryNodeSecretFact {
        workspace_id,
        frontier_id,
        owner_endpoint_id,
        source_secret_id,
        range_start,
        range_width,
        bit_depth,
        fact_id_prefix,
        tombstone_node_id,
        node_secret,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_local_history_node_secret(&secret)?,
    );
    Ok((secret, fact))
}
