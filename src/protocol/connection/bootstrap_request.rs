//! Bootstrap-request fact family.
//!
//! A bootstrap request is a local ephemeral fact for one sealed pre-connection
//! request frame observed at the socket boundary. Projection opens the sealed
//! bytes with the daemon endpoint secret context, then emits the canonical
//! `connection::request` fact plus its receive receipt. It has one fixed
//! payload shape.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use layout::{
    open_connection_request, seal_connection_request, SEALED_CONNECTION_REQUEST_BYTES,
    TYPE_CONNECTION_BOOTSTRAP_REQUEST, TYPE_SEALED_CONNECTION_REQUEST,
};

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionBootstrapRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
