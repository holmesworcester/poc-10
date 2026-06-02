//! Local signer-secret authenticator.
//!
//! POLICY. Authenticating a `local_signer_secret` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical local signer-secret fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only private signing material, never shareable signed
//! envelopes, so there is no fact-boundary signature. Admission scope (`Local`)
//! and publishing local signer context are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalSignerSecretFact;

pub(crate) struct LocalSignerSecretAuthenticator;

impl Authenticator for LocalSignerSecretAuthenticator {
    type Authenticated = LocalSignerSecretFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_signer_secret(fact))
    }
}

fn authenticate_local_signer_secret(fact: &Fact) -> Result<LocalSignerSecretFact, String> {
    // 1. Layout.
    let secret = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::local_signer_secret::fact::LocalSignerSecretFact;
    use crate::protocol::auth::local_signer_secret::layout;

    use super::LocalSignerSecretAuthenticator;

    fn canonical_fact() -> Fact {
        let private_key = [9; 32];
        let public_key = crypto::ed25519_public_key(&private_key);
        let secret = LocalSignerSecretFact {
            workspace_id: [1; 32],
            signer_id: [2; 32],
            public_key,
            private_key,
        };
        let bytes = layout::encode_fact(&secret).expect("encode local signer secret");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, LocalSignerSecretFact> {
        LocalSignerSecretAuthenticator::authenticate(fact, &ProjectionContext::default())
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
