//! Disappearing-message retention policy fact family.
//!
//! Retention policies define the TTL and monotonic floor applied to message
//! minutes in a workspace scope. Projection validates authority, supersession,
//! and floor tightening, publishes the active policy row, and offers
//! retention-floor context for messages in the workspace. Commands and queries
//! here keep the `disappearing-*` CLI surface while message projection consumes
//! the resulting policy and self-purges expired facts.

pub mod authenticate;
pub mod cli;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_RETENTION_POLICY: u8 = layout::TYPE_RETENTION_POLICY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RetentionPolicyFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::RetentionPolicyFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
