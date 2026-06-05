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
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::ContentFileDeletionFact;

pub(crate) struct ContentFileDeletionAuthenticator;

impl DecodedAuthenticator<super::Codec> for ContentFileDeletionAuthenticator {
    type Authenticated = ContentFileDeletionFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        deletion: ContentFileDeletionFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_file_deletion(fact, deletion))
    }
}

fn prove_decoded_file_deletion(
    fact: &Fact,
    deletion: ContentFileDeletionFact,
) -> Result<ContentFileDeletionFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    verify_signature(&deletion)?;
    Ok(deletion)
}

/// Verify the file deletion's signature over its canonical envelope. The
/// verifier key is embedded in the fact, so this is a context-free fact-boundary
/// proof.
pub fn verify_signature(fact: &ContentFileDeletionFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &crate::core::wire::encode_with_zeroed_trailing_field(
            fact,
            super::encode::encode_fact,
            crate::core::crypto::ED25519_SIGNATURE_BYTES,
        )?,
        &fact.signature,
        "content file deletion",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::command_context::LocalSigningCapability;
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::content::file_deletion::author::delete_file;
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
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => ContentFileDeletionAuthenticator::authenticate_decoded(
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
