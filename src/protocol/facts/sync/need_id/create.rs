//! Constructors for deterministic sync need-id facts.

use crate::core::facts::{Fact, FactScope};

use super::fact::SyncNeedIdFact;

pub fn fact(body: SyncNeedIdFact, timestamp: u64) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Global,
        timestamp,
        super::layout::encode_fact(&body)?,
    ))
}
