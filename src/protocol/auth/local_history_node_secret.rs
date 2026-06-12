//! Local history-node secret fact family.
//!
//! These local-only facts carry derived key material for a minute tree or trie
//! leaf below a removal frontier. Projection validates the source chain and
//! publishes wrap-source and secret-coverage offers. This family also owns the
//! secret-coverage coordinate scheme consumed by content-message projection.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = encode::TYPE_LOCAL_HISTORY_NODE_SECRET;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalHistoryNodeSecretFact, String> {
    decode::decode_local_history_node_secret(bytes)
}
