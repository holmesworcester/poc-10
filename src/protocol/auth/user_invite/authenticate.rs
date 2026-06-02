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

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::user_invite::create::signed_user_invite_fact;
    use crate::protocol::auth::user_invite::fact::UserInviteFact;

    use super::UserInviteAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_user_invite_fact(100, [1; 32], [2; 32], [3; 32], [4; 32], SIGNER_KEY)
            .expect("signed user_invite fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, UserInviteFact> {
        UserInviteAuthenticator::authenticate(fact, &ProjectionContext::default())
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
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_tampered_signature() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
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
