//! Local key secret authenticator.
//!
//! POLICY. Authenticating a `local_key_secret` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical local key secret fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only secrets, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the removal-frontier
//! match, retirement, and materialization are all interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalKeySecretFact;

pub(crate) struct LocalKeySecretAuthenticator;

impl Authenticator for LocalKeySecretAuthenticator {
    type Authenticated = LocalKeySecretFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_key_secret(fact))
    }
}

fn authenticate_local_key_secret(fact: &Fact) -> Result<LocalKeySecretFact, String> {
    // 1. Layout.
    let secret = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(secret)
}
