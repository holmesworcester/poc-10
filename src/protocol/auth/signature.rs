//! Signature evidence fact family.
//!
//! Signature facts are protocol evidence about another fact id. Claims stay
//! signature-free; projectors that require a proof wait for the matching
//! `signature_proof` context offer and validate authority through their normal
//! signer/user/workspace context.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

pub const TYPE_SIGNATURE: u8 = encode::TYPE_SIGNATURE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SignatureFact, String> {
    project::decode::decode_fact(bytes)
}
