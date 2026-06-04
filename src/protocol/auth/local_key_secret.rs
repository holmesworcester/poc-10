//! Local key secret fact family.
//!
//! A local key secret is private store material for a removal frontier's root
//! key. Projection ties it to its frontier and publishes wrap-source and
//! secret-coverage offers.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_LOCAL_KEY_SECRET: u8 = layout::TYPE_LOCAL_KEY_SECRET;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalKeySecretFact, String> {
    layout::decode_local_key_secret(bytes)
}

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = fact::LocalKeySecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
