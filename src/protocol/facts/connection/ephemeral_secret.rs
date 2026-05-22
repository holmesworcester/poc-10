//! Local connection handshake secret fact.
//!
//! This fact is local-only material used while creating a connection request or
//! response. Projection publishes context that lets the matching request or
//! response prove it can use the secret; the bytes themselves should not become
//! shared protocol state. Change this module when the handshake secret layout,
//! row materialization, or context offer changes.

pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionEphemeralSecretFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionEphemeralSecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
