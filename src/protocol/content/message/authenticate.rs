//! Content-message authenticator.
//!
//! POLICY. Authenticating a `content_message` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical content-message envelope through
//!      `decode.rs`.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The author signature verifies over the canonical envelope
//!      (`encode::signing_bytes`), using the embedded verifier key, so it needs
//!      no context.
//!
//! It proves nothing else. Admission scope, decryption, authority, and
//! materialization are the projector's job. This authenticator is also the write
//! pipeline's exit gate (`authenticate_authored`) — `author` self-checks every
//! fact it builds through this same code.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, DecodedAuthenticator, FactCodec,
    ProjectionContext,
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

impl DecodedAuthenticator<super::decode::Codec> for ContentMessageAuthenticator {
    type Authenticated = ContentMessageFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        message: ContentMessageFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_message(fact, message))
    }
}

/// Prove a content-message fact authentic over its own bytes.
fn authenticate_message(fact: &Fact) -> Result<ContentMessageFact, String> {
    // 1. Layout.
    let message = super::decode::Codec::decode_fact(fact)?;
    prove_decoded_message(fact, message)
}

fn prove_decoded_message(
    fact: &Fact,
    message: ContentMessageFact,
) -> Result<ContentMessageFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (embedded verifier key).
    verify_signature(&message)?;
    Ok(message)
}

/// Verify the author signature over the canonical signing envelope.
pub fn verify_signature(message: &ContentMessageFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &message.signer_public_key,
        &super::encode::signing_bytes(message)?,
        &message.signature,
        "content message",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::content::message::encode;
    use crate::protocol::content::message::fact::{
        ContentMessageFact, MessageCiphertext, NONCE_BYTES,
    };

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
            &encode::signing_bytes(&message).expect("signing bytes"),
        );
        message.signature = signature;
        Fact::new(
            crate::protocol::auth::workspace::scope(WORKSPACE_ID),
            message.created_at_ms,
            encode::encode_fact(&message).expect("encode message"),
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
