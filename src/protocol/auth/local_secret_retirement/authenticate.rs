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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalSecretRetirementFact;

pub(crate) struct LocalSecretRetirementAuthenticator;

impl Authenticator for LocalSecretRetirementAuthenticator {
    type Authenticated = LocalSecretRetirementFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_secret_retirement(fact))
    }
}

fn authenticate_local_secret_retirement(fact: &Fact) -> Result<LocalSecretRetirementFact, String> {
    // 1. Layout.
    let retirement = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(retirement)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::local_secret_retirement::fact::{
        LocalSecretRetirementFact, RETIRE_REASON_CHOP,
    };
    use crate::protocol::auth::local_secret_retirement::layout;

    use super::LocalSecretRetirementAuthenticator;

    fn canonical_fact() -> Fact {
        let retirement = LocalSecretRetirementFact {
            workspace_id: [1; 32],
            target_secret_id: [2; 32],
            reason_kind: RETIRE_REASON_CHOP,
            floor_minute: 10,
            created_at_ms: 123,
        };
        let bytes = layout::encode_fact(&retirement).expect("encode local secret retirement");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, LocalSecretRetirementFact> {
        LocalSecretRetirementAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(matches!(
            authenticate(&canonical_fact()),
            Authentication::Authenticated(_)
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
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
