//! Local recipient key fact family.
//!
//! A local recipient key holds private material that lets this store unwrap key
//! wraps. Projection proves it matches the shared recipient fact and self-purges
//! when the recipient key is superseded.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub(crate) use decode::Codec;

pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = encode::TYPE_LOCAL_RECIPIENT_KEY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalRecipientKeyFact, String> {
    decode::decode_local_recipient_key(bytes)
}
