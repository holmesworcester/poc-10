//! Local history-node secret fact family.
//!
//! These local-only facts represent derived key material for a minute tree or
//! trie leaf below a removal frontier. Projection validates the source secret,
//! optional tombstone source, and frontier context before publishing wrap-source
//! and secret-coverage offers. The module is local material plumbing, not a
//! shared protocol payload family.

pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = layout::TYPE_LOCAL_HISTORY_NODE_SECRET;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalHistoryNodeSecretFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::LocalHistoryNodeSecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
