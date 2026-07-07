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

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::invite::fact::InviteSecretFact;
    use crate::protocol::auth::invite::layout;

    use super::InviteSecretAuthenticator;

    fn canonical_fact() -> Fact {
        let invite_secret = InviteSecretFact::new([7; 32]);
        let bytes = layout::encode_fact(&invite_secret).expect("encode invite_secret");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, InviteSecretFact> {
        InviteSecretAuthenticator::authenticate(fact, &ProjectionContext::default())
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
