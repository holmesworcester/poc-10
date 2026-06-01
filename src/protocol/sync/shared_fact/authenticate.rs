//! Sync shared-fact authenticator.
//!
//! POLICY. Authenticating a `sync shared_fact` proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical shared-fact offer.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. Admission scope (the offer's workspace) is unsigned
//! local metadata, so the workspace-scope check is interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SharedFact;

pub(crate) struct SyncSharedFactAuthenticator;

impl Authenticator for SyncSharedFactAuthenticator {
    type Authenticated = SharedFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_shared_fact(fact))
    }
}

fn authenticate_shared_fact(fact: &Fact) -> Result<SharedFact, String> {
    // 1. Layout.
    let shared = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(shared)
}
