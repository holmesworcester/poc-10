pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_ENCRYPTED_ROOT: u8 = layout::TYPE_ENCRYPTED_ROOT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EncryptedRootFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::EncryptedRootFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
