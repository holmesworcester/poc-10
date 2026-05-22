//! Cascade fact family for dependency replay tests and tooling.
//!
//! Cascade facts model explicit dependencies between facts so sync and
//! projection behavior can be exercised with controlled graphs. They are not a
//! general protocol authority layer. Commands generate and replay them; rows
//! stage dependency state; projection publishes completion context.

pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CASCADE_FACT: u8 = layout::TYPE_CASCADE_FACT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::CascadeFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::CascadeFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
