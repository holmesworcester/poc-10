//! Local signer-secret fact family.
//!
//! A local signer secret is private key material that lets this node produce
//! signature evidence for one workspace signer. It is a local fact, never a
//! shareable envelope, and its only projection output is local signer context
//! for commands and projectors that need signing authority.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

pub use fact::*;

pub const TYPE_LOCAL_SIGNER_SECRET: u8 = encode::TYPE_LOCAL_SIGNER_SECRET;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalSignerSecretFact, String> {
    project::decode::decode_fact(bytes)
}
