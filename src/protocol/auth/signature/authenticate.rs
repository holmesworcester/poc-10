//! Signature evidence authenticator.
//!
//! Authenticating a signature fact proves the evidence fact is canonically
//! addressed and that its embedded public key signed the target fact id. It does
//! not prove the signer has authority over the target; claim projectors own that
//! policy through their existing context checks.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::SignatureFact;

pub(crate) fn authenticate(
    fact: &Fact,
    signature: SignatureFact,
    _context: &ProjectionContext,
) -> Result<SignatureFact, String> {
    prove_decoded_signature(fact, signature)
}

fn prove_decoded_signature(fact: &Fact, signature: SignatureFact) -> Result<SignatureFact, String> {
    verify_fact_id(fact)?;
    verify_signature(&signature)?;
    Ok(signature)
}

pub fn verify_signature(fact: &SignatureFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &super::encode::signature_message(fact.workspace_id, fact.target_fact_id),
        &fact.signature,
        "signature evidence",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;

    const PRIVATE_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        super::super::author::create_signature([3; 32], [9; 32], &PRIVATE_KEY, 123)
            .expect("signature fact")
    }

    fn authenticate(fact: &Fact) -> Result<super::super::fact::SignatureFact, String> {
        let decoded = super::super::decode::decode_fact(fact.body())?;
        super::authenticate(fact, decoded, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        authenticate(fact).is_err()
    }

    #[test]
    fn authenticates_canonical_signature_fact() {
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
    fn rejects_tampered_target_id() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[41] ^= 0x01;
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
