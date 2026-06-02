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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionFrameObservationFact;

pub(crate) struct ConnectionFrameObservationAuthenticator;

impl Authenticator for ConnectionFrameObservationAuthenticator {
    type Authenticated = ConnectionFrameObservationFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_frame_observation(fact))
    }
}

fn authenticate_frame_observation(fact: &Fact) -> Result<ConnectionFrameObservationFact, String> {
    // 1. Layout.
    let observed = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::frame_observation::create::fact_from_observation;
    use crate::protocol::connection::frame_observation::fact::ConnectionFrameObservationFact;

    use super::ConnectionFrameObservationAuthenticator;

    fn canonical_fact() -> Fact {
        fact_from_observation([1; 32], b"127.0.0.1:41001", 100)
            .expect("connection_frame_observation fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionFrameObservationFact> {
        ConnectionFrameObservationAuthenticator::authenticate(fact, &ProjectionContext::default())
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
