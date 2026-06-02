//! Sync range-request authenticator.
//!
//! POLICY. Authenticating a `sync_range_request` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical range-request fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. Admission scope (the requested workspace) is unsigned
//! local metadata, so the workspace-scope check is interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncRangeRequestFact;

pub(crate) struct SyncRangeRequestAuthenticator;

impl Authenticator for SyncRangeRequestAuthenticator {
    type Authenticated = SyncRangeRequestFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_range_request(fact))
    }
}

fn authenticate_range_request(fact: &Fact) -> Result<SyncRangeRequestFact, String> {
    // 1. Layout.
    let request = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::sync::range_request::fact::SyncRangeRequestFact;
    use crate::protocol::sync::range_request::layout;

    use super::SyncRangeRequestAuthenticator;

    fn canonical_fact() -> Fact {
        let request = SyncRangeRequestFact {
            workspace_id: [1; 32],
            connection_id: [2; 32],
            start: 10,
            end: 20,
        };
        Fact::new(
            FactScope::Global,
            10,
            layout::encode_fact(&request).expect("encode sync range request"),
        )
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, SyncRangeRequestFact> {
        SyncRangeRequestAuthenticator::authenticate(fact, &ProjectionContext::default())
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

    // Admission scope is interpretation, checked by the projector, not the
    // authenticator: a range request with a Local scope authenticates here and
    // is rejected downstream.
}
