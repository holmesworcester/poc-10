//! Content-message authenticator.
//!
//! POLICY. Authenticating a `content_message` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical content-message envelope — right
//!      tag, fixed width, valid fields — through the family codec.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The author signature verifies over the canonical public
//!      envelope, which covers the ciphertext slot. The verifier key is embedded
//!      in the fact, so this needs no context.
//!
//! It proves nothing else. Admission scope is unsigned local metadata, not part
//! of these bytes, so the workspace-scope check is interpretation the projector
//! owns — that keeps the workspace-id format, its type, and the rule itself
//! behind the lens and the single ceiling projector, free to evolve. Decryption
//! of the message text likewise stays in the projector: the text key is secret
//! context and decryption yields read-model meaning. The authenticated payload
//! is the decoded fact; the projector proves scope, signer, author, deletion,
//! retention, and secret context and materializes rows.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ContentMessageFact;

pub(crate) struct ContentMessageAuthenticator;

impl Authenticator for ContentMessageAuthenticator {
    type Authenticated = ContentMessageFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_message(fact))
    }
}

/// Prove a content-message fact authentic over its own bytes.
///
/// Context-free, so the steps chain with `?`; `authenticate` maps the result to
/// an `Authentication` outcome.
fn authenticate_message(fact: &Fact) -> Result<ContentMessageFact, String> {
    // 1. Layout.
    let message = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&message)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::content::message::fact::{
        ContentMessageFact, MessageCiphertext, NONCE_BYTES,
    };
    use crate::protocol::content::message::layout;

    use super::ContentMessageAuthenticator;

    const PRIVATE_KEY: [u8; 32] = [7; 32];
    const WORKSPACE_ID: [u8; 32] = [1; 32];

    fn canonical_fact() -> Fact {
        let mut message = ContentMessageFact {
            workspace_id: WORKSPACE_ID,
            created_at_ms: 180_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            signer_public_key: crypto::ed25519_public_key(&PRIVATE_KEY),
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [6; 32],
            minute: 3,
            nonce: [8; NONCE_BYTES],
            ciphertext: MessageCiphertext::new(b"sealed").expect("ciphertext"),
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        let (_, signature) = crypto::ed25519_sign_canonical(
            &PRIVATE_KEY,
            &layout::signing_bytes(&message).expect("signing bytes"),
        );
        message.signature = signature;
        Fact::new(
            crate::protocol::auth::workspace::scope(WORKSPACE_ID),
            message.created_at_ms,
            layout::encode_fact(&message).expect("encode message"),
        )
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ContentMessageFact> {
        ContentMessageAuthenticator::authenticate(fact, &ProjectionContext::default())
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
