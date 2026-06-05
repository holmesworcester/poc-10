//! Recipient-key authenticator.
//!
//! POLICY. Authenticating a `recipient_key` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical recipient-key fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. A recipient key cannot supersede itself
//!      (`previous_recipient_key_id != fact_id`).
//!
//! Admission scope is unsigned local metadata, so the workspace-scope check is
//! interpretation the projector owns. Supersession against an earlier key and
//! signer matching are proven from other facts, also in the projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::RecipientKeyFact;

pub(crate) struct RecipientKeyAuthenticator;

impl DecodedAuthenticator<super::Codec> for RecipientKeyAuthenticator {
    type Authenticated = RecipientKeyFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        recipient: RecipientKeyFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_recipient_key(fact, recipient))
    }
}

fn prove_decoded_recipient_key(
    fact: &Fact,
    recipient: RecipientKeyFact,
) -> Result<RecipientKeyFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    verify_signature(&recipient)?;
    // 4. A recipient key cannot supersede itself.
    if recipient.previous_recipient_key_id == fact.id {
        return Err(
            "recipient key cannot supersede itself (previous_recipient_key_id == fact_id)"
                .to_string(),
        );
    }
    Ok(recipient)
}

/// Verify the recipient key's signature over its canonical envelope. The
/// verifier key is embedded in the fact, so this is a context-free fact-boundary
/// proof.
pub fn verify_signature(fact: &RecipientKeyFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &crate::core::wire::encode_with_zeroed_trailing_field(
            fact,
            super::encode::encode_recipient_key,
            crate::core::crypto::ED25519_SIGNATURE_BYTES,
        )?,
        &fact.signature,
        "recipient key",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::recipient_key::author::signed_recipient_key_fact;
    use crate::protocol::auth::recipient_key::fact::{RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY};

    use super::RecipientKeyAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let private_key = SIGNER_KEY;
        let signer_public_key = crypto::ed25519_public_key(&private_key);
        signed_recipient_key_fact(
            [1; 32],
            [2; 32],
            [3; 32],
            NO_PREVIOUS_RECIPIENT_KEY,
            100,
            signer_public_key,
            private_key,
        )
        .expect("signed recipient_key fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, RecipientKeyFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => RecipientKeyAuthenticator::authenticate_decoded(
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
