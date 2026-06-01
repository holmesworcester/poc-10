//! Small connection-frame authenticator.
//!
//! POLICY. Authenticating a `connection_frame_small` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical small connection-frame payload.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! Frame facts carry only wire bytes; there is no fact-boundary signature and no
//! intrinsic field rule. Admission scope, the observation and response context,
//! decryption, and child materialization are all interpretation the projector
//! owns through `create::project_observed_frame`.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionFrameSmallFact;

pub(crate) struct ConnectionFrameSmallAuthenticator;

impl Authenticator for ConnectionFrameSmallAuthenticator {
    type Authenticated = ConnectionFrameSmallFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_frame_small(fact))
    }
}

fn authenticate_frame_small(fact: &Fact) -> Result<ConnectionFrameSmallFact, String> {
    // 1. Layout.
    let input = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(input)
}
