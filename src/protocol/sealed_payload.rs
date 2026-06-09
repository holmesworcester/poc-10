//! Generic sealed content payload fact.
//!
//! A sealed payload is opaque bytes. It does not materialize user-visible rows
//! by itself; content roots decide whether and how a referenced payload opens.

pub mod adapt;
pub mod authenticate;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub const TYPE_SEALED_PAYLOAD: u8 = encode::TYPE_SEALED_PAYLOAD;

pub(crate) use decode::Codec;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SealedPayloadFact, String> {
    decode::decode_fact(bytes)
}
