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
pub mod rows;

const CONNECTION_RESPONSE_FOR_REQUEST_ROLE: &str = "connection_response_for_request";

pub fn peer_retry_timeline() -> crate::core::projectors::Timeline {
    crate::core::projectors::Timeline::new("connection_peer_retry")
        .expect("valid connection peer-retry timeline")
}

pub fn connection_response_for_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn connection_response_for_request_offer(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

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
