//! Sync have-id authenticator.
//!
//! POLICY. Authenticating a `sync_have_id` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical have-id advertisement.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A have-id fact carries no fact-boundary signature;
//! whether the advertised id is already present is idempotent handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncHaveIdFact;

pub(crate) struct SyncHaveIdAuthenticator;

impl Authenticator for SyncHaveIdAuthenticator {
    type Authenticated = SyncHaveIdFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_have_id(fact))
    }
}

fn authenticate_have_id(fact: &Fact) -> Result<SyncHaveIdFact, String> {
    // 1. Layout.
    let have = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(have)
}
