//! Local secret-retirement authenticator.
//!
//! POLICY. Authenticating a `local_secret_retirement` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical local secret-retirement fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only context facts, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the target
//! secret-source match, and materialization are all interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalSecretRetirementFact;

pub(crate) struct LocalSecretRetirementAuthenticator;

impl Authenticator for LocalSecretRetirementAuthenticator {
    type Authenticated = LocalSecretRetirementFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_secret_retirement(fact))
    }
}

fn authenticate_local_secret_retirement(fact: &Fact) -> Result<LocalSecretRetirementFact, String> {
    // 1. Layout.
    let retirement = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(retirement)
}
