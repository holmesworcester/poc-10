//! Sync have-id authenticator.
//!
//! POLICY. Authenticating a `sync_have_id` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical have-id advertisement.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A have-id fact carries no fact-boundary signature;
//! whether the advertised id is already present is idempotent handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::SyncHaveIdFact;

pub(crate) fn authenticate(
    fact: &Fact,
    have: SyncHaveIdFact,
    _context: &ProjectionContext,
) -> Result<SyncHaveIdFact, String> {
    prove_decoded_have_id(fact, have)
}

fn prove_decoded_have_id(fact: &Fact, have: SyncHaveIdFact) -> Result<SyncHaveIdFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(have)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::sync::have_id::author::advertisement_fact;
    use crate::protocol::sync::have_id::fact::SyncHaveIdFact;

    fn canonical_fact() -> Fact {
        let advertised = Fact::new(FactScope::Global, 777, vec![42]);
        advertisement_fact([7; 32], &advertised).expect("have-id advertisement fact")
    }

    fn authenticate(fact: &Fact) -> Result<SyncHaveIdFact, String> {
        let decoded = super::super::decode::decode_fact(fact.body())?;
        super::authenticate(fact, decoded, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        authenticate(fact).is_err()
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(authenticate(&canonical_fact()).is_ok());
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_id_not_matching_bytes() {
        let canonical = canonical_fact();
        let forged = Fact {
            id: [0; 32],
            scope: canonical.scope.clone(),
            timestamp: canonical.timestamp,
            bytes: canonical.bytes.clone(),
        };
        assert!(is_invalid(&forged));
    }
}
