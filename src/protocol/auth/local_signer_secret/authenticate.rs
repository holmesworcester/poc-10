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
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::LocalSignerSecretFact;

pub(crate) fn authenticate(
    fact: &Fact,
    secret: LocalSignerSecretFact,
    _context: &ProjectionContext,
) -> Result<LocalSignerSecretFact, String> {
    prove_decoded_local_signer_secret(fact, secret)
}

fn prove_decoded_local_signer_secret(
    fact: &Fact,
    secret: LocalSignerSecretFact,
) -> Result<LocalSignerSecretFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::local_signer_secret::encode;
    use crate::protocol::auth::local_signer_secret::fact::LocalSignerSecretFact;

    fn canonical_fact() -> Fact {
        let private_key = [9; 32];
        let public_key = crypto::ed25519_public_key(&private_key);
        let secret = LocalSignerSecretFact {
            workspace_id: [1; 32],
            signer_id: [2; 32],
            public_key,
            private_key,
        };
        let bytes = encode::encode_fact(&secret).expect("encode local signer secret");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Result<LocalSignerSecretFact, String> {
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
