//! User authenticator.
//!
//! POLICY. Authenticating a `user` fact proves, over its signed bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical user fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace and public-key selectors are non-empty and the
//!      username is non-blank.
//!
//! Admission scope (`Global`) is unsigned local metadata, so the projector
//! checks it. Inviter authority is proven from other facts, also in the
//! projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::UserFact;

pub(crate) struct UserAuthenticator;

impl Authenticator for UserAuthenticator {
    type Authenticated = UserFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_user(fact))
    }
}

fn authenticate_user(fact: &Fact) -> Result<UserFact, String> {
    // 1. Layout.
    let user = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&user)?;
    // 4. Intrinsic fields.
    if user.workspace_id == [0; 32] {
        return Err("user workspace_id must not be empty".to_string());
    }
    if user.public_key == [0; 32] {
        return Err("user public_key must not be empty".to_string());
    }
    if user.username.as_str().trim().is_empty() {
        return Err("username must not be empty".to_string());
    }
    Ok(user)
}
