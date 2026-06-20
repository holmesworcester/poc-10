//! Local key-wrap recovery fact family.
//!
//! A key-wrap recovery fact is local, deterministic work: it records that this
//! store has a specific local recipient key for a specific accepted key wrap.
//! Its projector waits for those exact facts and emits the recovered local
//! secret fact.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

pub(crate) use author::key_wrap_recovery_fact;

pub const TYPE_KEY_WRAP_RECOVERY: u8 = encode::TYPE_KEY_WRAP_RECOVERY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::KeyWrapRecoveryFact, String> {
    project::decode::decode_fact(bytes)
}
