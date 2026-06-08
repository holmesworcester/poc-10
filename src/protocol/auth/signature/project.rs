//! Signature evidence projector.
//!
//! POLICY. A signature evidence fact is admitted iff:
//!   1. STRUCTURAL. The outer fact scope matches the workspace id carried in
//!      the signature evidence body.
//!   2. CONTEXT. No incoming context is required; authentication already proved
//!      the embedded public key signed the workspace-bound target fact id.
//!   3. MATERIALIZE. Publish a `signature_proof` offer keyed by target fact id
//!      and signer public key, then mark the evidence fact shareable in that
//!      workspace.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::sync::shared_fact::project::share_fact_with_sync;

use super::fact::SignatureFact;

pub const SIGNATURE_PROOF_ROLE: &str = "signature_proof";

pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::signature::Codec",
    authenticate: "auth::signature::authenticate::SignatureAuthenticator",
    adapt: "auth::signature::adapt::SignatureAdapter",
    project: "auth::signature::project::SignatureProjector",
};

#[derive(Debug, Clone, Default)]
pub struct SignatureProjector;

impl SignatureProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SignatureProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::SignatureAuthenticator,
            super::adapt::SignatureAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<SignatureFact> for SignatureProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        signature: SignatureFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(signature.workspace_id);
        if fact.scope != scope {
            return Err("signature fact scope does not match body workspace".to_string());
        }
        // 2. Context.

        // 3. Materialize.
        let output = ProjectionOutput::new().offer(signature_proof_offer(
            fact.id,
            scope,
            signature.target_fact_id,
            signature.signer_public_key,
        )?);
        Ok(share_fact_with_sync(
            output,
            signature.workspace_id,
            fact,
            Vec::new(),
        ))
    }
}

pub fn signature_proof_need(
    owner: FactId,
    scope: FactScope,
    target_fact_id: FactId,
    signer_public_key: Ed25519PublicKey,
) -> Result<ContextNeed, String> {
    ContextNeed::for_key_parts(
        owner,
        SIGNATURE_PROOF_ROLE,
        scope,
        [
            crate::core::context::ContextKeyPart::bytes(&target_fact_id),
            crate::core::context::ContextKeyPart::bytes(&signer_public_key),
        ],
    )
}

pub fn signature_proof_offer(
    owner: FactId,
    scope: FactScope,
    target_fact_id: FactId,
    signer_public_key: Ed25519PublicKey,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        SIGNATURE_PROOF_ROLE,
        scope,
        [
            crate::core::context::ContextKeyPart::bytes(&target_fact_id),
            crate::core::context::ContextKeyPart::bytes(&signer_public_key),
        ],
    )
}

pub fn validate_signature_proof_payload(
    payload: &Fact,
    need: &ContextNeed,
    workspace_id: FactId,
    target_fact_id: FactId,
    signer_public_key: Ed25519PublicKey,
    label: &str,
) -> Result<(), String> {
    if payload.scope != need.scope {
        return Err(format!(
            "{label} signature proof scope does not match target"
        ));
    }
    let proof = crate::protocol::auth::signature::decode_fact_payload(payload.body())
        .map_err(|_| format!("{label} signature proof is not a signature fact"))?;
    if proof.workspace_id != workspace_id {
        return Err(format!(
            "{label} signature proof workspace does not match target"
        ));
    }
    if proof.target_fact_id != target_fact_id {
        return Err(format!(
            "{label} signature proof target does not match target"
        ));
    }
    if proof.signer_public_key != signer_public_key {
        return Err(format!(
            "{label} signature proof key does not match target signer key"
        ));
    }
    Ok(())
}

pub fn signature_proof_ready(
    context: &ProjectionContext,
    need: &ContextNeed,
    workspace_id: FactId,
    target_fact_id: FactId,
    signer_public_key: Ed25519PublicKey,
    label: &str,
) -> Result<bool, String> {
    let Some(payload) = context.payload_for(need) else {
        return Ok(false);
    };
    validate_signature_proof_payload(
        payload,
        need,
        workspace_id,
        target_fact_id,
        signer_public_key,
        label,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::FactScope;
    use crate::core::pipeline::{ProjectionContext, Projector};

    use super::*;

    const PRIVATE_KEY: [u8; 32] = [7; 32];

    #[test]
    fn signature_fact_projects_proof_offer_for_target_and_public_key() {
        let target = [9; 32];
        let workspace_id = [3; 32];
        let fact = crate::protocol::auth::signature::author::create_signature(
            workspace_id,
            target,
            &PRIVATE_KEY,
            100,
        )
        .expect("signature fact");
        let signer_public_key = crate::core::crypto::ed25519_public_key(&PRIVATE_KEY);

        let output = SignatureProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project signature fact");

        assert!(output.needs.is_empty());
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, SIGNATURE_PROOF_ROLE);
        assert_eq!(
            output.offers[0],
            signature_proof_offer(
                fact.id,
                crate::protocol::auth::workspace::scope(workspace_id),
                target,
                signer_public_key
            )
            .expect("offer")
        );
        assert_eq!(output.effects.intents.len(), 1);
        let share = crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
            &output.effects.intents[0],
        )
        .expect("share intent");
        assert_eq!(share.workspace_id, workspace_id);
        assert_eq!(share.owner_fact_id, fact.id);
        assert!(share.context_have.is_empty());
    }

    #[test]
    fn proof_need_and_offer_use_the_same_exact_key() {
        let target = [9; 32];
        let signer_public_key = crate::core::crypto::ed25519_public_key(&PRIVATE_KEY);
        let need = signature_proof_need([1; 32], FactScope::Global, target, signer_public_key)
            .expect("need");
        let offer = signature_proof_offer([2; 32], FactScope::Global, target, signer_public_key)
            .expect("offer");

        assert_eq!(need.role, SIGNATURE_PROOF_ROLE);
        assert_eq!(need.start_key, offer.start_key);
        assert_eq!(need.end_key, offer.end_key);
    }
}
