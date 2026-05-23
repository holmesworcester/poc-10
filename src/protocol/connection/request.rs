//! Connection request fact family.
//!
//! Requests start a peer handshake from a local endpoint to an invite or known
//! endpoint. Commands and constructors build the request, `layout` fixes its
//! wire bytes, and projection waits for invite/receipt plus local ephemeral
//! context before materializing a request row and emitting response work.
//! Change this root when the request family gains a new submodule; change
//! `project.rs` for handshake admission policy.

pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionRequestFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
