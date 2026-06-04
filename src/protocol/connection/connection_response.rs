//! Membership connection response family.
//!
//! A response completes a membership handshake and is the local connection
//! fact: its fact id is the connection id and its body carries the
//! `connection_secret`. It writes the shared connection row (the same table
//! bootstrap connections use, keyed by connection id) so established frames and
//! sync treat both connection kinds identically, and publishes the
//! `connection_response` context other modules rely on. The secret is derived
//! from Diffie-Hellman only; no invite material is involved.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionResponseFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionResponseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
