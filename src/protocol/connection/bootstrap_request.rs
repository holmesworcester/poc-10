//! Connection request family.
//!
//! A request starts a connection handshake from one endpoint to another using
//! invite-backed authorization and initiator ephemeral material. Local commands
//! construct request facts, received network bytes can become durable request
//! facts, and projection validates the branch-specific context before writing a
//! request row or scheduling response work.
//!
//! This family owns request payload bytes, optional listen-address encoding,
//! request row materialization, and request admission policy. Response creation,
//! frame sending, and socket IO belong to the downstream connection modules.

pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;
pub mod transit;

pub use project::{connection_response_for_request_need, connection_response_for_request_offer};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::BootstrapRequestFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::BootstrapRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
