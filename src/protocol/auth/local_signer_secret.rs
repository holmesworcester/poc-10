//! Local signer-secret fact family.
//!
//! A local signer secret is private key material that lets this node produce
//! signed envelopes for one workspace signer. It is a local fact, never a
//! shareable envelope, and its only projection output is local signer context
//! for commands and projectors that need signing authority.

pub mod fact;
pub mod layout;
pub mod project;

pub use fact::*;

pub const TYPE_LOCAL_SIGNER_SECRET: u8 = layout::TYPE_LOCAL_SIGNER_SECRET;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalSignerSecretFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::LocalSignerSecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
