//! Local secret-retirement authenticator.
//!
//! POLICY. Authenticating a `local_secret_retirement` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical local secret-retirement fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only context facts, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the target
//! secret-source match, and materialization are all interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::LocalSecretRetirementFact;

pub(crate) fn authenticate(
    fact: &Fact,
    retirement: LocalSecretRetirementFact,
    _context: &ProjectionContext,
) -> Result<LocalSecretRetirementFact, String> {
    prove_decoded_local_secret_retirement(fact, retirement)
}

fn prove_decoded_local_secret_retirement(
    fact: &Fact,
    retirement: LocalSecretRetirementFact,
) -> Result<LocalSecretRetirementFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(retirement)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::local_secret_retirement::encode;
    use crate::protocol::auth::local_secret_retirement::fact::{
        LocalSecretRetirementFact, RETIRE_REASON_CHOP,
    };

    fn canonical_fact() -> Fact {
        let retirement = LocalSecretRetirementFact {
            workspace_id: [1; 32],
            target_secret_id: [2; 32],
            reason_kind: RETIRE_REASON_CHOP,
            floor_minute: 10,
            created_at_ms: 123,
        };
        let bytes = encode::encode_fact(&retirement).expect("encode local secret retirement");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Result<LocalSecretRetirementFact, String> {
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
