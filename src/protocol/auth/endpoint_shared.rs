//! Shared endpoint identity fact family.
//!
//! Endpoint-shared facts are the signed, shareable proof that an endpoint name,
//! role, and public signing key belong in a workspace. Projection validates the
//! signature and workspace/user context, then publishes endpoint rows and
//! signer context that content, admin, connection, and auth projectors
//! rely on.

pub mod cli;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_ENDPOINT_SHARED: u8 = layout::TYPE_ENDPOINT_SHARED;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointSharedFact, String> {
    layout::decode_fact(bytes)
}

pub fn decode_raw_or_signed_payload(
    fact: &crate::core::facts::Fact,
) -> Result<fact::EndpointSharedFact, String> {
    if fact.bytes.first().copied()
        != Some(crate::protocol::auth::signed_envelope::TYPE_SIGNED_ENVELOPE)
    {
        return decode_fact_payload(fact.body());
    }
    let signed = crate::protocol::auth::signed_envelope::decode_signed_payload(
        fact,
        layout::TYPE_ENDPOINT_SHARED,
        "endpoint_shared",
        decode_fact_payload,
    )?;
    Ok(signed.payload)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = crate::protocol::auth::signed_envelope::SignedPayload<fact::EndpointSharedFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::auth::signed_envelope::decode_signed_payload(
            fact,
            layout::TYPE_ENDPOINT_SHARED,
            "endpoint_shared",
            decode_fact_payload,
        )
    }
}
