//! Local signer-secret authenticator.
//!
//! POLICY. Authenticating a `local_signer_secret` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical local signer-secret fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only private signing material, never shareable signed
//! envelopes, so there is no fact-boundary signature. Admission scope (`Local`)
//! and publishing local signer context are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalSignerSecretFact;

pub(crate) struct LocalSignerSecretAuthenticator;

impl Authenticator for LocalSignerSecretAuthenticator {
    type Authenticated = LocalSignerSecretFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_signer_secret(fact))
    }
}

fn authenticate_local_signer_secret(fact: &Fact) -> Result<LocalSignerSecretFact, String> {
    // 1. Layout.
    let secret = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(secret)
}
