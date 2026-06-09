//! Generic local-only secret payload fact.
//!
//! A local secret payload contains only family/version plus opaque secret bytes.
//! Context roots explain what the secret is for through ordinary refs.

pub mod adapt;
pub mod authenticate;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub const TYPE_LOCAL_SECRET_PAYLOAD: u8 = encode::TYPE_LOCAL_SECRET_PAYLOAD;

pub(crate) use decode::Codec;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalSecretPayloadFact, String> {
    decode::decode_fact(bytes)
}
