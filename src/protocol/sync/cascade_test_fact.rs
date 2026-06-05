//! Cascade fact family for dependency replay tests and tooling.
//!
//! Cascade facts model explicit dependencies between facts so sync and
//! projection behavior can be exercised with controlled graphs. They are not a
//! general protocol authority layer. Commands generate and replay them; rows
//! stage dependency state; projection publishes completion context.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod cli;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod staging;

pub(crate) use decode::Codec;

pub const TYPE_CASCADE_TEST_FACT: u8 = encode::TYPE_CASCADE_TEST_FACT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::CascadeTestFact, String> {
    decode::decode_fact(bytes)
}
