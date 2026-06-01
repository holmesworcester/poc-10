//! Key request fact family.
//!
//! A key request asks a frontier owner to produce a wrap for a requester
//! recipient key. Projection validates requester/responder context and emits
//! create-key-wrap work.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_KEY_REQUEST: u8 = layout::TYPE_KEY_REQUEST;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::KeyRequestFact, String> {
    layout::decode_key_request(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::KeyRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
