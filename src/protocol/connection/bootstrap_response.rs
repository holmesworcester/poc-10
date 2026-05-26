//! Bootstrap-response fact family.
//!
//! A bootstrap response is a local ephemeral fact for one sealed
//! pre-connection response frame observed at the socket boundary. Projection
//! opens the sealed bytes with the daemon endpoint secret context, then emits
//! the canonical `connection::response` fact plus its receive receipt. It has
//! one fixed payload shape.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use layout::{
    open_connection_response, seal_connection_response, SEALED_CONNECTION_RESPONSE_BYTES,
    TYPE_CONNECTION_BOOTSTRAP_RESPONSE, TYPE_SEALED_CONNECTION_RESPONSE,
};

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionBootstrapResponseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
