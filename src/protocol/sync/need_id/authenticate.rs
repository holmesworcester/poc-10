//! Sync need-id authenticator.
//!
//! POLICY. Authenticating a `sync_need_id` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical need-id request.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A need-id fact carries no fact-boundary signature;
//! whether this store can answer the request is idempotent handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncNeedIdFact;

pub(crate) struct SyncNeedIdAuthenticator;

impl Authenticator for SyncNeedIdAuthenticator {
    type Authenticated = SyncNeedIdFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_need_id(fact))
    }
}

fn authenticate_need_id(fact: &Fact) -> Result<SyncNeedIdFact, String> {
    // 1. Layout.
    let need = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(need)
}
