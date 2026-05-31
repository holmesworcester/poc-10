//! Membership connection request family.
//!
//! A membership connection request is first contact with an endpoint that
//! already knows us: it is authorized by `endpoint_shared` membership, not an
//! invite. Local commands construct request facts, received network bytes can
//! become durable request facts, and projection validates the endpoint
//! signature against the initiator's membership signing key and a shared
//! workspace before offering request context or scheduling response work.
//!
//! This family owns request payload bytes, the endpoint signing transcript, and
//! request admission policy. It carries no invite material. Response creation,
//! frame sending, and socket IO belong to the downstream connection modules.

pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod transit;

pub use project::{
    connection_request_need, connection_request_offer, connection_response_for_request_need,
    connection_response_for_request_offer, peer_retry_timeline,
};

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
