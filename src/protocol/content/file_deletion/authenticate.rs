//! Content-file-deletion authenticator.
//!
//! POLICY. Authenticating a `content_file_deletion` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical content-file-deletion fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope is unsigned local metadata, not part of these bytes, so the
//! workspace-scope check is interpretation the projector owns. The authority of
//! the signer, target file, and author user is proven from other facts, also in
//! the projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ContentFileDeletionFact;

pub(crate) struct ContentFileDeletionAuthenticator;

impl Authenticator for ContentFileDeletionAuthenticator {
    type Authenticated = ContentFileDeletionFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_file_deletion(fact))
    }
}

/// Prove a content-file-deletion fact authentic over its own bytes.
fn authenticate_file_deletion(fact: &Fact) -> Result<ContentFileDeletionFact, String> {
    // 1. Layout.
    let deletion = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&deletion)?;
    Ok(deletion)
}

#[cfg(test)]
mod tests {
    use crate::core::command_context::LocalSigningCapability;
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::content::file_deletion::create::delete_file;
    use crate::protocol::content::file_deletion::fact::ContentFileDeletionFact;

    use super::ContentFileDeletionAuthenticator;

    const PRIVATE_KEY: [u8; 32] = [7; 32];
    const WORKSPACE_ID: [u8; 32] = [1; 32];

    fn signing_capability() -> LocalSigningCapability {
        LocalSigningCapability {
            workspace_id: WORKSPACE_ID,
            signer_id: [2; 32],
            public_key: crypto::ed25519_public_key(&PRIVATE_KEY),
            private_key: PRIVATE_KEY,
        }
    }

    fn canonical_fact() -> Fact {
        delete_file(&signing_capability(), WORKSPACE_ID, 100, [3; 32], [4; 32])
            .expect("content file deletion fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ContentFileDeletionFact> {
        ContentFileDeletionAuthenticator::authenticate(fact, &ProjectionContext::default())
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
