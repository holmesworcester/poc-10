//! Local-endpoint authenticator.
//!
//! POLICY. Authenticating a local `endpoint` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical endpoint fact — the layout
//!      re-derives both public keys from the stored private keys.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local identity secrets, not a signed shared proof, so there is no
//! fact-boundary signature. Admission scope (`Local`) is interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::EndpointFact;

pub(crate) struct EndpointAuthenticator;

impl Authenticator for EndpointAuthenticator {
    type Authenticated = EndpointFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_endpoint(fact))
    }
}

fn authenticate_endpoint(fact: &Fact) -> Result<EndpointFact, String> {
    // 1. Layout.
    let endpoint = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(endpoint)
}
