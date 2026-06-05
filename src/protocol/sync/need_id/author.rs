//! Constructors for deterministic sync need-id facts.
//!
//! A need-id fact tells a peer which advertised fact id is missing locally. This
//! helper gives intent handlers one place to construct the canonical global
//! fact after they have decoded a matching have-id. Keep policy out of this
//! file; deciding whether a fact is missing belongs to the send-needed handler.

use crate::core::facts::{Fact, FactScope};

use super::fact::SyncNeedIdFact;

pub fn fact(body: SyncNeedIdFact, timestamp: u64) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Global,
        timestamp,
        super::encode::encode_fact(&body)?,
    ))
}
