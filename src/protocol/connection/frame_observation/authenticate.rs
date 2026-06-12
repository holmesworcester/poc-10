//! Connection-frame observation authenticator.
//!
//! POLICY. Authenticating a `connection_frame_observation` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical frame-observation payload.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! Observations are unsigned local metadata: there is no fact-boundary signature
//! and no intrinsic field rule. Admission scope (`Local`) is unsigned metadata,
//! so the local-scope check stays in the projector, as does publishing
//! observation context for the observed frame fact.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::ConnectionFrameObservationFact;

pub(crate) fn authenticate(
    fact: &Fact,
    observed: ConnectionFrameObservationFact,
    _context: &ProjectionContext,
) -> Result<ConnectionFrameObservationFact, String> {
    prove_decoded_frame_observation(fact, observed)
}

fn prove_decoded_frame_observation(
    fact: &Fact,
    observed: ConnectionFrameObservationFact,
) -> Result<ConnectionFrameObservationFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::connection::frame_observation::author::fact_from_observation;
    use crate::protocol::connection::frame_observation::fact::ConnectionFrameObservationFact;

    fn canonical_fact() -> Fact {
        fact_from_observation([1; 32], b"127.0.0.1:41001", 100)
            .expect("connection_frame_observation fact")
    }

    fn authenticate(fact: &Fact) -> Result<ConnectionFrameObservationFact, String> {
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
