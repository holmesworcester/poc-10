//! Sync-compare authenticator.
//!
//! POLICY. Authenticating a `sync_compare` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical sync-compare fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A compare is an unsigned peer summary; whether it
//! answers a request or continues a response round is deferred handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::SyncCompareFact;

pub(crate) struct SyncCompareAuthenticator;

impl DecodedAuthenticator<super::Codec> for SyncCompareAuthenticator {
    type Authenticated = SyncCompareFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        compare: SyncCompareFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_compare(fact, compare))
    }
}

fn prove_decoded_compare(fact: &Fact, compare: SyncCompareFact) -> Result<SyncCompareFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(compare)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::sync::compare::author::start_compare_fact_with_summary;
    use crate::protocol::sync::compare::fact::{RangeSummary, SyncCompareFact};

    use super::SyncCompareAuthenticator;

    fn canonical_fact() -> Fact {
        start_compare_fact_with_summary(
            [7; 32],
            RangeSummary {
                count: 2,
                fingerprint: [9; 32],
            },
        )
        .expect("start compare fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, SyncCompareFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => SyncCompareAuthenticator::authenticate_decoded(
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

    // Admission scope is interpretation, checked by the projector, not the
    // authenticator: a compare with a Local scope authenticates here and is
    // rejected downstream.
}
