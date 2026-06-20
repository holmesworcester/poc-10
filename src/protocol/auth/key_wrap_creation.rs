//! Local key-wrap creation fact family.
//!
//! A key-wrap creation fact is local, deterministic work: it names the exact
//! recipient key, source secret, signer secret, and wrap-source coordinate that
//! projection already proved eligible. Its projector waits for those exact
//! facts and emits the shared `key_wrap` fact. The resulting wrap fact owns
//! sync visibility and remote interpretation.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

pub(crate) use author::key_wrap_creation_fact;

pub const TYPE_KEY_WRAP_CREATION: u8 = encode::TYPE_KEY_WRAP_CREATION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::KeyWrapCreationFact, String> {
    project::decode::decode_fact(bytes)
}
