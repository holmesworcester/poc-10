//! Local membership request-sent fact family.
//!
//! A `connection_request_sent` fact records the local outbound membership
//! request attempt. It is not sent to peers. It stores the exact sealed
//! `connection_request` bytes that were put on the wire, the semantic plaintext
//! request we authored, the initiator ephemeral secret id, and the peer address
//! used for retry routing.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionRequestSentFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionRequestSentFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
