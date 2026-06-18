//! Command-facing API for local protocol update facts.
//!
//! Commands ask this module for authored update facts. The fact constructor
//! remains in `author.rs`; CLI text formatting remains in `cli.rs`.

use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::facts::FactId;

use super::super::CURRENT_PROTOCOL_VERSION;
use super::author::update_fact;
use super::fact::UpdateFact;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateReceipt {
    pub update_fact_id: FactId,
    pub protocol_version: u32,
    pub applied_at_ms: u64,
}

pub fn author_update(clock: &dyn CommandClock) -> Result<AuthoredFacts<UpdateReceipt>, String> {
    let applied_at_ms = clock.next_timestamp();
    let fact = update_fact(UpdateFact {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        applied_at_ms,
    })?;
    Ok(AuthoredFacts::new(UpdateReceipt {
        update_fact_id: fact.id,
        protocol_version: CURRENT_PROTOCOL_VERSION,
        applied_at_ms,
    })
    .with_facts(vec![fact]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::FnClock;
    use crate::core::facts::FactScope;
    use crate::protocol::versioning::update::encode::decode_update_fact;

    #[test]
    fn author_update_creates_local_fact() {
        let output = author_update(&FnClock(|| 44)).expect("author update");
        let (_receipt, facts) = output.into_parts();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].scope, FactScope::Local);
        assert_eq!(
            decode_update_fact(facts[0].body())
                .expect("decode")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
    }
}
