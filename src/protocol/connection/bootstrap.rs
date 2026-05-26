//! Bootstrap connection-frame fact family.
//!
//! Bootstrap facts are local ephemeral wrappers around sealed pre-connection
//! network bytes. Projection opens the sealed request or response with the
//! daemon's local endpoint secret context, then emits the canonical
//! `connection::request` or `connection::response` fact plus its receive
//! receipt. The request and response facts remain the semantic handshake state;
//! this family owns only the receive-side carrier used before a connection
//! secret exists.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use layout::{
    open_connection_request, open_connection_response, seal_connection_request,
    seal_connection_response, SEALED_CONNECTION_REQUEST_BYTES, SEALED_CONNECTION_RESPONSE_BYTES,
    TYPE_CONNECTION_BOOTSTRAP, TYPE_SEALED_CONNECTION_REQUEST, TYPE_SEALED_CONNECTION_RESPONSE,
};

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionBootstrapFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
