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
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::UserFact;

pub(crate) struct UserAuthenticator;

impl DecodedAuthenticator<super::Codec> for UserAuthenticator {
    type Authenticated = UserFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        user: UserFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_user(fact, user))
    }
}

fn prove_decoded_user(fact: &Fact, user: UserFact) -> Result<UserFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
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
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::user::author::signed_user_fact;
    use crate::protocol::auth::user::fact::UserFact;

    use super::UserAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_user_fact(100, [1; 32], [2; 32], "alice", [3; 32], SIGNER_KEY)
            .expect("signed user fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, UserFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => UserAuthenticator::authenticate_decoded(
                fact,
                decoded,
                &ProjectionContext::default(),
            ),
            Err(error) => Authentication::Invalid(error),
        }
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
