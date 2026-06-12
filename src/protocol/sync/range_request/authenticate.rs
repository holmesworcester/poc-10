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
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::SyncRangeRequestFact;

pub(crate) fn authenticate(
    fact: &Fact,
    request: SyncRangeRequestFact,
    _context: &ProjectionContext,
) -> Result<SyncRangeRequestFact, String> {
    prove_decoded_range_request(fact, request)
}

fn prove_decoded_range_request(
    fact: &Fact,
    request: SyncRangeRequestFact,
) -> Result<SyncRangeRequestFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::sync::range_request::encode;
    use crate::protocol::sync::range_request::fact::SyncRangeRequestFact;

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
            encode::encode_fact(&request).expect("encode sync range request"),
        )
    }

    fn authenticate(fact: &Fact) -> Result<SyncRangeRequestFact, String> {
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

    // Admission scope is interpretation, checked by the projector, not the
    // authenticator: a range request with a Local scope authenticates here and
    // is rejected downstream.
}
