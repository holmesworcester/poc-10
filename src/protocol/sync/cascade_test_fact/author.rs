//! Cascade test fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::{CascadeDependencies, CascadeTestFact, PAYLOAD_BYTES};

pub fn fact_from_payload(
    timestamp: u64,
    dependencies: CascadeDependencies,
    payload: [u8; PAYLOAD_BYTES],
) -> Result<Fact, String> {
    let fact = CascadeTestFact {
        timestamp,
        dependencies,
        payload,
    };
    fact_from_body(&fact)
}

pub fn fact_from_body(fact: &CascadeTestFact) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Global,
        fact.timestamp,
        encode::encode_fact(fact)?,
    ))
}

pub fn fact_from_staged_bytes(timestamp: u64, bytes: Vec<u8>) -> Fact {
    Fact::new(FactScope::Global, timestamp, bytes)
}

pub fn completion_offer(fact_id: FactId, scope: FactScope) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(fact_id, "sync_exact_fact", scope, fact_id, fact_id)
}
