//! Cascade test-fact authenticator.
//!
//! POLICY. Authenticating a `cascade_test_fact` proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical cascade test fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The body timestamp equals the outer fact timestamp.
//!
//! Cascade facts carry no fact-boundary signature; declared dependencies are
//! CONTEXT the projector proves from other facts, and publishing completion
//! context is interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::CascadeTestFact;

pub(crate) struct CascadeTestFactAuthenticator;

impl DecodedAuthenticator<super::Codec> for CascadeTestFactAuthenticator {
    type Authenticated = CascadeTestFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        decoded: CascadeTestFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_cascade_test_fact(fact, decoded))
    }
}

fn prove_decoded_cascade_test_fact(
    fact: &Fact,
    decoded: CascadeTestFact,
) -> Result<CascadeTestFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // FIELDS.
    if decoded.timestamp != fact.timestamp {
        return Err("cascade fact timestamp does not match fact timestamp".to_string());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::sync::cascade_test_fact::encode;
    use crate::protocol::sync::cascade_test_fact::fact::{
        CascadeDependencies, CascadeTestFact, PAYLOAD_BYTES,
    };

    use super::CascadeTestFactAuthenticator;

    const TIMESTAMP: u64 = 42;

    fn canonical_fact() -> Fact {
        let payload = CascadeTestFact {
            timestamp: TIMESTAMP,
            dependencies: CascadeDependencies::new(&[[1; 32], [2; 32]]).expect("dependencies"),
            payload: [7; PAYLOAD_BYTES],
        };
        // The authenticator proves the body timestamp equals the fact timestamp,
        // so both must agree for the canonical fact.
        Fact::new(
            FactScope::Global,
            TIMESTAMP,
            encode::encode_fact(&payload).expect("encode cascade test fact"),
        )
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, CascadeTestFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => CascadeTestFactAuthenticator::authenticate_decoded(
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
