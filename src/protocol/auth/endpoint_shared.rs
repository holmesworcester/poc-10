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

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::EndpointSharedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
