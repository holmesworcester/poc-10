//! Proof predicates for the `protocol::auth::signature` fact family.
//!
//! Keep family-local proof work here: canonical layout, fact-boundary
//! authentication, context proof obligations, projection offers, and row
//! materialization. Cross-family or core substrate proofs belong outside this
//! fact-family module.

use crate::core::context::ContextOffer;
use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidSignatureProofOffer;

/// A `signature_proof` offer is valid for one target only when its owner payload
/// is a signature fact in the same workspace scope, the payload names the same
/// target and signer key, and the embedded signature verifies.
pub fn valid_signature_proof_offer(
    offer: &ContextOffer,
    payload: &Fact,
    workspace_id: FactId,
    target_fact_id: FactId,
    signer_public_key: Ed25519PublicKey,
) -> bool {
    let scope = crate::protocol::auth::workspace::scope(workspace_id);
    let expected_offer = match super::project::signature_proof_offer(
        payload.id,
        scope.clone(),
        target_fact_id,
        signer_public_key,
    ) {
        Ok(offer) => offer,
        Err(_) => return false,
    };
    if offer != &expected_offer || payload.scope != scope {
        return false;
    }
    let signature = match super::decode_fact_payload(payload.body()) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    signature.workspace_id == workspace_id
        && signature.target_fact_id == target_fact_id
        && signature.signer_public_key == signer_public_key
        && super::project::authenticate::prove_signature_evidence(&signature).is_ok()
}

pub fn theorem_valid_signature_proof_offer(
    offer: &ContextOffer,
    payload: &Fact,
    workspace_id: FactId,
    target_fact_id: FactId,
    signer_public_key: Ed25519PublicKey,
) -> Result<ValidSignatureProofOffer, String> {
    valid_signature_proof_offer(
        offer,
        payload,
        workspace_id,
        target_fact_id,
        signer_public_key,
    )
    .then_some(ValidSignatureProofOffer)
    .ok_or_else(|| "signature_proof offer is not valid for the requested target".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_offer_certificate_binds_workspace_target_and_signer() {
        let workspace_id = [3; 32];
        let target_fact_id = [9; 32];
        let private_key = [7; 32];
        let signer_public_key = crate::core::crypto::ed25519_public_key(&private_key);
        let payload =
            super::super::author::create_signature(workspace_id, target_fact_id, &private_key, 123)
                .expect("signature fact");
        let offer = super::super::project::signature_proof_offer(
            payload.id,
            crate::protocol::auth::workspace::scope(workspace_id),
            target_fact_id,
            signer_public_key,
        )
        .expect("signature offer");

        theorem_valid_signature_proof_offer(
            &offer,
            &payload,
            workspace_id,
            target_fact_id,
            signer_public_key,
        )
        .expect("valid signature offer");
        assert!(!valid_signature_proof_offer(
            &offer,
            &payload,
            [4; 32],
            target_fact_id,
            signer_public_key,
        ));
    }
}
