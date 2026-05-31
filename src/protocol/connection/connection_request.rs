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

const MEMBERSHIP_CONNECTION_REQUEST_ROLE: &str = "membership_connection_request";
const MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE: &str =
    "membership_connection_response_for_request";

/// Peer-retry timeline shared with bootstrap: it is keyed per request fact, so
/// reusing the constant does not cross requests.
pub fn peer_retry_timeline() -> crate::core::projectors::Timeline {
    crate::protocol::connection::bootstrap_request::peer_retry_timeline()
}

pub fn connection_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_REQUEST_ROLE),
        crate::core::facts::FactScope::Global,
        request_id,
        request_id,
    )
}

pub fn connection_request_offer(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_REQUEST_ROLE),
        crate::core::facts::FactScope::Global,
        request_id,
        request_id,
    )
}

pub fn connection_response_for_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
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
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
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
