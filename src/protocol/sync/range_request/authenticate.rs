//! Sync range-request authenticator.
//!
//! POLICY. Authenticating a `sync_range_request` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical range-request fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. Admission scope (the requested workspace) is unsigned
//! local metadata, so the workspace-scope check is interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncRangeRequestFact;

pub(crate) struct SyncRangeRequestAuthenticator;

impl Authenticator for SyncRangeRequestAuthenticator {
    type Authenticated = SyncRangeRequestFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_range_request(fact))
    }
}

fn authenticate_range_request(fact: &Fact) -> Result<SyncRangeRequestFact, String> {
    // 1. Layout.
    let request = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(request)
}
