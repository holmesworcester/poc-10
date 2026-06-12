//! Recipient key fact family.
//!
//! A recipient key names an endpoint public key eligible to receive workspace
//! auth key material. Projection validates supersession and emits proactive
//! key-wrap work.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub const TYPE_RECIPIENT_KEY: u8 = encode::TYPE_RECIPIENT_KEY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RecipientKeyFact, String> {
    decode::decode_recipient_key(bytes)
}
