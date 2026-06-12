//! Key request fact family.
//!
//! A key request asks a frontier owner to produce a wrap for a requester
//! recipient key. Projection validates requester/responder context and emits
//! create-key-wrap work.

pub mod adapt;
pub mod authenticate;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub const TYPE_KEY_REQUEST: u8 = encode::TYPE_KEY_REQUEST;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::KeyRequestFact, String> {
    decode::decode_key_request(bytes)
}
