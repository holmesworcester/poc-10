//! Admin-grant authenticator.
//!
//! POLICY. Authenticating an `admin` fact proves, over its signed bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical admin fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace, public-key, authority, and user selectors are
//!      non-zero.
//!
//! Scope (`Global`) and the authority path (bootstrap vs delegated grant) are
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::AdminFact;

pub(crate) struct AdminAuthenticator;

impl Authenticator for AdminAuthenticator {
    type Authenticated = AdminFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_admin(fact))
    }
}

fn authenticate_admin(fact: &Fact) -> Result<AdminFact, String> {
    // 1. Layout.
    let admin = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&admin)?;
    // 4. Non-zero selector fields.
    if admin.workspace_id == [0u8; 32] {
        return Err("admin workspace_id must not be zero".to_string());
    }
    if admin.public_key == [0u8; 32] {
        return Err("admin public_key must not be zero".to_string());
    }
    if admin.authority_fact_id == [0u8; 32] {
        return Err("admin authority_fact_id must not be zero".to_string());
    }
    if admin.user_fact_id == [0u8; 32] {
        return Err("admin user_fact_id must not be zero".to_string());
    }
    Ok(admin)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::admin::create::signed_admin_fact;
    use crate::protocol::auth::admin::fact::AdminFact;

    use super::AdminAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let grant = AdminFact {
            created_at_ms: 100,
            workspace_id: [1; 32],
            public_key: [2; 32],
            authority_fact_id: [3; 32],
            user_fact_id: [4; 32],
            signer_id: [3; 32],
            signer_public_key: [0; 32],
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        signed_admin_fact(100, [3; 32], SIGNER_KEY, grant).expect("signed admin fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, AdminFact> {
        AdminAuthenticator::authenticate(fact, &ProjectionContext::default())
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
