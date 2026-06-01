//! Local endpoint fact family.
//!
//! Endpoint facts describe this store's local identity material: endpoint id,
//! signing keys, and local secret rows used by command capabilities and
//! projection context. These facts are local authority, not shared identity
//! proofs. Shared endpoint visibility lives in `endpoint_shared`.

pub mod authenticate;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_LOCAL_ENDPOINT: u8 = layout::TYPE_LOCAL_ENDPOINT;

pub use project::{daemon_endpoint_need, daemon_endpoint_offer};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::EndpointFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
