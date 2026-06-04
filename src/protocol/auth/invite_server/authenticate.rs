//! Invite-server authenticator.
//!
//! POLICY. Authenticating an `invite_server` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical invite-server fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace, authority, and public-key selectors are non-zero.
//!
//! Scope (`Global`) and the authority path (bootstrap vs delegated grant) are
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::InviteServerFact;

pub(crate) struct InviteServerAuthenticator;

impl Authenticator for InviteServerAuthenticator {
    type Authenticated = InviteServerFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_invite_server(fact))
    }
}

fn authenticate_invite_server(fact: &Fact) -> Result<InviteServerFact, String> {
    // 1. Layout.
    let invite_server = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&invite_server)?;
    // 4. Non-zero selector fields.
    if invite_server.workspace_id == [0; 32] {
        return Err("invite_server fact has empty workspace_id".to_string());
    }
    if invite_server.authority_fact_id == [0; 32] {
        return Err("invite_server fact has empty authority_fact_id".to_string());
    }
    if invite_server.public_key == [0; 32] {
        return Err("invite_server fact has empty public_key".to_string());
    }
    Ok(invite_server)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::pipeline::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::invite_server::create::signed_invite_server_fact;
    use crate::protocol::auth::invite_server::fact::InviteServerFact;

    use super::InviteServerAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_invite_server_fact(
            100,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            crypto::ed25519_public_key(&SIGNER_KEY),
            &SIGNER_KEY,
        )
        .expect("signed invite_server fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, InviteServerFact> {
        InviteServerAuthenticator::authenticate(fact, &ProjectionContext::default())
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
