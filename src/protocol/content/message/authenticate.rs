//! Content-message authenticator.
//!
//! POLICY. Authenticating a `content_message` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical content-message envelope — right
//!      tag, fixed width, valid fields — through the family codec.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. Admission scope is unsigned local metadata, not part
//! of these bytes, so the workspace-scope check is interpretation the projector
//! owns — that keeps the workspace-id format, its type, and the rule itself
//! behind the lens and the single ceiling projector, free to evolve. Decryption
//! of the message text likewise stays in the projector: the text key is secret
//! context and decryption yields read-model meaning. Signature evidence is a
//! separate fact and context dependency. The authenticated payload is the
//! decoded fact; the projector proves scope, signature evidence, signer, author,
//! deletion, retention, and secret context and materializes rows.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::ContentMessageFact;

pub(crate) struct ContentMessageAuthenticator;

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

fn prove_decoded_message(
    fact: &Fact,
    message: ContentMessageFact,
) -> Result<ContentMessageFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::content::message::encode;
    use crate::protocol::content::message::fact::{
        ContentMessageFact, MessageCiphertext, NONCE_BYTES,
    };

    use super::ContentMessageAuthenticator;

    const WORKSPACE_ID: [u8; 32] = [1; 32];

    fn canonical_fact() -> Fact {
        let message = ContentMessageFact {
            workspace_id: WORKSPACE_ID,
            created_at_ms: 180_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            signer_public_key: [7; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [6; 32],
            minute: 3,
            nonce: [8; NONCE_BYTES],
            ciphertext: MessageCiphertext::new(b"sealed").expect("ciphertext"),
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(WORKSPACE_ID),
            message.created_at_ms,
            encode::encode_fact(&message).expect("encode message"),
        )
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ContentMessageFact> {
        match super::super::decode::Codec::decode_fact(fact) {
            Ok(decoded) => ContentMessageAuthenticator::authenticate_decoded(
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
