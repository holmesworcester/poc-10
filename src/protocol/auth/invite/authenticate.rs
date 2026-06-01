//! Invite-secret authenticator.
//!
//! POLICY. Authenticating an `invite_secret` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical invite-secret fact with
//!      internally consistent hash/scope fields.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local bootstrap secrets, not a signed shared proof, so there is no
//! fact-boundary signature. Admission scope (`Local`) is interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::InviteSecretFact;

pub(crate) struct InviteSecretAuthenticator;

impl Authenticator for InviteSecretAuthenticator {
    type Authenticated = InviteSecretFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_invite_secret(fact))
    }
}

fn authenticate_invite_secret(fact: &Fact) -> Result<InviteSecretFact, String> {
    // 1. Layout.
    let invite_secret = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(invite_secret)
}
