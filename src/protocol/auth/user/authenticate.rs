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

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::user::create::signed_user_fact;
    use crate::protocol::auth::user::fact::UserFact;

    use super::UserAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_user_fact(100, [1; 32], [2; 32], "alice", [3; 32], SIGNER_KEY)
            .expect("signed user fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, UserFact> {
        UserAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(matches!(
            authenticate(&canonical_fact()),
            Authentication::Authenticated(_)
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_tampered_signature() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_id_not_matching_bytes() {
        let canonical = canonical_fact();
        let forged = Fact {
            id: [0; 32],
            scope: canonical.scope.clone(),
            timestamp: canonical.timestamp,
            bytes: canonical.bytes.clone(),
        };
        assert!(is_invalid(&forged));
    }
}
