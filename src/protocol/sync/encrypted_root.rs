//! Encrypted root sync fact family.
//!
//! Encrypted-root facts advertise encrypted state roots that may lead peers to
//! request key material. Projection validates the layout and emits context for
//! sync/auth key-material flows without interpreting the encrypted payload itself.

pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_ENCRYPTED_ROOT: u8 = layout::TYPE_ENCRYPTED_ROOT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EncryptedRootFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::EncryptedRootFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
