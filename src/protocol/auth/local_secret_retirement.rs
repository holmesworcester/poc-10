//! Local secret-retirement fact family.
//!
//! A retirement fact is local context saying one local secret-source fact should
//! stop offering key material. The retirement fact does not purge the target by
//! itself; target secret projectors keep a standing retirement need and emit
//! self-purge after this context arrives.
//!
//! Change this family for retirement fact bytes or retirement-context
//! coordinates. Change the target secret projectors for target-specific cleanup
//! and validation.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

pub use project::{secret_retired_need, secret_retired_offer};

pub const TYPE_LOCAL_SECRET_RETIREMENT: u8 = encode::TYPE_LOCAL_SECRET_RETIREMENT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalSecretRetirementFact, String> {
    project::decode::decode_fact(bytes)
}
