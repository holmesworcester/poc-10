//! Local history-node secret fact family.
//!
//! These local-only facts carry derived key material for a minute tree or trie
//! leaf below a removal frontier. Projection validates the source chain and
//! publishes wrap-source and secret-coverage offers. This family also owns the
//! secret-coverage coordinate scheme consumed by content-message projection.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::store::TableName;

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = encode::TYPE_LOCAL_HISTORY_NODE_SECRET;

pub const LOCAL_HISTORY_NODE_SECRET_ROWS: TableName =
    TableName::new("local_history_node_secret_rows");
pub const LOCAL_HISTORY_NODE_TOMBSTONE_ROWS: TableName =
    TableName::new("local_history_node_tombstone_rows");

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalHistoryNodeSecretFact, String> {
    project::decode::decode_local_history_node_secret(bytes)
}
