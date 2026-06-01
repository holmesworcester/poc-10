//! User-invite authenticator.
//!
//! POLICY. Authenticating a `user_invite` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical user_invite fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace, authority, and public-key selectors are non-zero.
//!
//! Admission scope (`Global`) is unsigned local metadata, so the projector
//! checks it. The authority path (bootstrap vs delegated grant) is proven from
//! other facts, also in the projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::UserInviteFact;

pub(crate) struct UserInviteAuthenticator;

impl Authenticator for UserInviteAuthenticator {
    type Authenticated = UserInviteFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_user_invite(fact))
    }
}

fn authenticate_user_invite(fact: &Fact) -> Result<UserInviteFact, String> {
    // 1. Layout.
    let user_invite = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&user_invite)?;
    // 4. Non-zero selector fields.
    if user_invite.workspace_id == [0; 32] {
        return Err("user_invite fact has empty workspace_id".to_string());
    }
    if user_invite.authority_fact_id == [0; 32] {
        return Err("user_invite fact has empty authority_fact_id".to_string());
    }
    if user_invite.public_key == [0; 32] {
        return Err("user_invite fact has empty public_key".to_string());
    }
    Ok(user_invite)
}
