//! Removal-frontier authenticator.
//!
//! POLICY. Authenticating a `removal_frontier` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical removal-frontier fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Scope and owner-endpoint authority (an `endpoint_shared` signer or a local
//! signer secret) are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::RemovalFrontierFact;

pub(crate) struct RemovalFrontierAuthenticator;

impl Authenticator for RemovalFrontierAuthenticator {
    type Authenticated = RemovalFrontierFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_removal_frontier(fact))
    }
}

fn authenticate_removal_frontier(fact: &Fact) -> Result<RemovalFrontierFact, String> {
    // 1. Layout.
    let frontier = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&frontier)?;
    Ok(frontier)
}
