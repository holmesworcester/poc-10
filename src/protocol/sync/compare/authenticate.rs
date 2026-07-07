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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncCompareFact;

pub(crate) struct SyncCompareAuthenticator;

impl Authenticator for SyncCompareAuthenticator {
    type Authenticated = SyncCompareFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_compare(fact))
    }
}

fn authenticate_compare(fact: &Fact) -> Result<SyncCompareFact, String> {
    // 1. Layout.
    let compare = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(compare)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::sync::compare::create::start_compare_fact_with_summary;
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
        SyncCompareAuthenticator::authenticate(fact, &ProjectionContext::default())
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
