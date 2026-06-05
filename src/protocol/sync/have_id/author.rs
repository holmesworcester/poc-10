//! Sync have-id fact constructors.
//!
//! Builds have-id advertisements from already stored facts; it does not
//! validate the advertised fact's own protocol semantics.

use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::SyncHaveIdFact;

pub fn advertisement_fact(connection_id: FactId, fact: &Fact) -> Result<Fact, String> {
    let have = SyncHaveIdFact {
        connection_id,
        timestamp: fact.timestamp,
        fact_id: fact.id,
    };
    Ok(Fact::new(
        FactScope::Global,
        fact.timestamp,
        encode::encode_fact(&have)?,
    ))
}
