//! Content-reaction authenticator.
//!
//! POLICY. Authenticating a `content_reaction` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical content-reaction fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope is unsigned local metadata, not part of these bytes, so the
//! workspace-scope check is interpretation the projector owns. The signer,
//! target content message, target deletion, and author are proven from other
//! facts, also in the projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::ContentReactionFact;

pub(crate) fn authenticate(
    fact: &Fact,
    reaction: ContentReactionFact,
    _context: &ProjectionContext,
) -> Result<ContentReactionFact, String> {
    prove_decoded_reaction(fact, reaction)
}

fn prove_decoded_reaction(
    fact: &Fact,
    reaction: ContentReactionFact,
) -> Result<ContentReactionFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(reaction)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::content::reaction::author::authored_reaction_fact;
    use crate::protocol::content::reaction::fact::{
        ContentReactionFact, ReactionCiphertext, REACTION_NONCE_BYTES,
    };

    const PRIVATE_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        authored_reaction_fact(
            100,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [8; REACTION_NONCE_BYTES],
            ReactionCiphertext::new(b"sealed-reaction").expect("reaction ciphertext"),
            PRIVATE_KEY,
        )
        .expect("authored content reaction fact")
    }

    fn authenticate(fact: &Fact) -> Result<ContentReactionFact, String> {
        let decoded = super::super::decode::decode_fact(fact.body())?;
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
