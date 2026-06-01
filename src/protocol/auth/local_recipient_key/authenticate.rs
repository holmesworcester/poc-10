//! Local recipient key authenticator.
//!
//! POLICY. Authenticating a `local_recipient_key` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical local recipient key fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only facts, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the shared-recipient
//! match, supersession, and materialization are all interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalRecipientKeyFact;

pub(crate) struct LocalRecipientKeyAuthenticator;

impl Authenticator for LocalRecipientKeyAuthenticator {
    type Authenticated = LocalRecipientKeyFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_recipient_key(fact))
    }
}

fn authenticate_local_recipient_key(fact: &Fact) -> Result<LocalRecipientKeyFact, String> {
    // 1. Layout.
    let local = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(local)
}
