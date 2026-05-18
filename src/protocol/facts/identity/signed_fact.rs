pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use create::*;
pub use fact::*;

pub const TYPE_SIGNED_FACT: u8 = layout::TYPE_SIGNED_FACT;
pub const SIGNED_FACT_BYTES: usize = layout::SIGNED_FACT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload<T> {
    pub envelope: fact::SignedFactEnvelope,
    pub payload: T,
}

pub fn decode_envelope(bytes: &[u8]) -> Result<fact::SignedFactEnvelope, String> {
    layout::decode_signed_fact(bytes)
}

pub fn verify_envelope(envelope: &fact::SignedFactEnvelope) -> Result<(), String> {
    layout::verify_signed_fact(envelope)
}

pub fn decode_local_signer_secret_payload(
    bytes: &[u8],
) -> Result<fact::LocalSignerSecretFact, String> {
    layout::decode_local_signer_secret(bytes)
}

pub fn decode_signed_fact_payload<T>(
    fact: &crate::core::facts::Fact,
    expected_type: u8,
    label: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<SignedPayload<T>, String> {
    let envelope =
        decode_envelope(fact.body()).map_err(|_| format!("{label} fact must be signed"))?;
    if envelope.inner_type != expected_type {
        return Err(format!("signed fact does not contain {label}"));
    }
    let payload = decode(&envelope.payload)?;
    Ok(SignedPayload { envelope, payload })
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::LocalSignerSecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_local_signer_secret(fact.body())
    }
}
