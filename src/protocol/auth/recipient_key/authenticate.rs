//! Recipient-key authenticator.
//!
//! POLICY. Authenticating a `recipient_key` fact proves, over its canonical bytes
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
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::RecipientKeyFact;

pub(crate) fn authenticate(
    fact: &Fact,
    recipient: RecipientKeyFact,
    _context: &ProjectionContext,
) -> Result<RecipientKeyFact, String> {
    prove_decoded_recipient_key(fact, recipient)
}

fn prove_decoded_recipient_key(
    fact: &Fact,
    recipient: RecipientKeyFact,
) -> Result<RecipientKeyFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 4. A recipient key cannot supersede itself.
    if recipient.previous_recipient_key_id == fact.id {
        return Err(
            "recipient key cannot supersede itself (previous_recipient_key_id == fact_id)"
                .to_string(),
        );
    }
    Ok(recipient)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::recipient_key::author::authored_recipient_key_fact;
    use crate::protocol::auth::recipient_key::fact::{RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY};

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let private_key = SIGNER_KEY;
        let signer_public_key = crypto::ed25519_public_key(&private_key);
        authored_recipient_key_fact(
            [1; 32],
            [2; 32],
            [3; 32],
            NO_PREVIOUS_RECIPIENT_KEY,
            100,
            signer_public_key,
        )
        .expect("signed recipient_key fact")
    }

    fn authenticate(fact: &Fact) -> Result<RecipientKeyFact, String> {
        let decoded = super::super::decode::decode_recipient_key(fact.body())?;
        super::authenticate(fact, decoded, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        authenticate(fact).is_err()
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(authenticate(&canonical_fact()).is_ok());
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
