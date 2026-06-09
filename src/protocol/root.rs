//! Generic root fact envelope.
//!
//! Roots carry durable public context: a semantic family/version, creator
//! asserted time, and a fixed set of exact refs. They deliberately do not carry
//! family-owned payload bytes.

pub mod adapt;
pub mod authenticate;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod roles;

pub const TYPE_ROOT: u8 = encode::TYPE_ROOT;

pub(crate) use decode::Codec;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RootFact, String> {
    decode::decode_fact(bytes)
}
