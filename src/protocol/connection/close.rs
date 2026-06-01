//! Connection close fact family.
//!
//! A close fact is the local fact that retires a materialized connection. It
//! names a connection-response fact id, waits for exact local connection
//! context, then publishes close context for that connection and for the
//! initiator/responder ephemeral-secret fact ids referenced by the response.
//!
//! The close fact does not delete material itself. The target fact families keep
//! standing close needs, then delete their own rows and purge their own fact
//! bytes after close context arrives. Change this family for close fact bytes or
//! close-context coordinates; change the target projectors for target-specific
//! cleanup.

pub mod authenticate;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;

pub use project::{
    connection_closed_need, connection_closed_offer, ephemeral_secret_closed_need,
    ephemeral_secret_closed_offer,
};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionCloseFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionCloseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
