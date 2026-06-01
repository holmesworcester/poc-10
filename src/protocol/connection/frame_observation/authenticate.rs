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
