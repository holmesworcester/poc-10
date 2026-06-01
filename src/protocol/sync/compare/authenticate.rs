//! Sync-compare authenticator.
//!
//! POLICY. Authenticating a `sync_compare` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical sync-compare fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A compare is an unsigned peer summary; whether it
//! answers a request or continues a response round is deferred handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncCompareFact;

pub(crate) struct SyncCompareAuthenticator;

impl Authenticator for SyncCompareAuthenticator {
    type Authenticated = SyncCompareFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_compare(fact))
    }
}

fn authenticate_compare(fact: &Fact) -> Result<SyncCompareFact, String> {
    // 1. Layout.
    let compare = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(compare)
}
