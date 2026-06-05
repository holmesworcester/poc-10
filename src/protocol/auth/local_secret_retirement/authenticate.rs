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
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::LocalSecretRetirementFact;

pub(crate) struct LocalSecretRetirementAuthenticator;

impl DecodedAuthenticator<super::Codec> for LocalSecretRetirementAuthenticator {
    type Authenticated = LocalSecretRetirementFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        retirement: LocalSecretRetirementFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(
            fact,
            prove_decoded_local_secret_retirement(fact, retirement),
        )
    }
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
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::local_secret_retirement::encode;
    use crate::protocol::auth::local_secret_retirement::fact::{
        LocalSecretRetirementFact, RETIRE_REASON_CHOP,
    };

    use super::LocalSecretRetirementAuthenticator;

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

    fn authenticate(fact: &Fact) -> Authentication<'_, LocalSecretRetirementFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => LocalSecretRetirementAuthenticator::authenticate_decoded(
                fact,
                decoded,
                &ProjectionContext::default(),
            ),
            Err(error) => Authentication::Invalid(error),
        }
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
