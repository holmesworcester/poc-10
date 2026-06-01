//! Local connection handshake secret family.
//!
//! An ephemeral secret is private X25519 material created for one handshake
//! leg. It exists as a local fact so request and response projectors can prove
//! that the public key they reference is backed by local private material, while
//! the secret bytes never become shared protocol state.
//!
//! Projection validates the keypair, writes a local row keyed by the secret
//! fact id, and publishes exact local context for the matching request or
//! response. Change this family when handshake secret bytes, row storage, or
//! context offers change; connection requests and responses own how the secret
//! is consumed.

pub mod authenticate;
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
