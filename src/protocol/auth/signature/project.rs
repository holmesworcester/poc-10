pub mod decode {
    //! Byte decoding for signature evidence facts.

    use crate::core::wire;

    use super::super::encode::{SIGNATURE_FACT_BYTES, TYPE_SIGNATURE};
    use super::super::fact::SignatureFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<SignatureFact, String> {
        let mut reader = wire::Reader::new(bytes);
        reader.expect_len(SIGNATURE_FACT_BYTES).map_err(wire_err)?;
        let tag = reader.u8().map_err(wire_err)?;
        if tag != TYPE_SIGNATURE {
            return Err("expected signature fact".to_string());
        }
        let fact = SignatureFact {
            workspace_id: reader.array().map_err(wire_err)?,
            created_at_ms: reader.u64be().map_err(wire_err)?,
            target_fact_id: reader.array().map_err(wire_err)?,
            signer_public_key: reader.array().map_err(wire_err)?,
            signature: reader.array().map_err(wire_err)?,
        };
        reader.finish().map_err(wire_err)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn signature_fact() -> SignatureFact {
            SignatureFact {
                workspace_id: [4; 32],
                created_at_ms: 123,
                target_fact_id: [1; 32],
                signer_public_key: [2; 32],
                signature: [3; crate::core::crypto::ED25519_SIGNATURE_BYTES],
            }
        }

        #[test]
        fn signature_fact_roundtrips_fixed_width() {
            let encoded =
                super::super::super::encode::encode_fact(&signature_fact()).expect("encode");
            assert_eq!(encoded.len(), SIGNATURE_FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), signature_fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded =
                super::super::super::encode::encode_fact(&signature_fact()).expect("encode");
            encoded[0] = TYPE_SIGNATURE.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_wrong_length() {
            assert!(decode_fact(&[TYPE_SIGNATURE; 8]).is_err());
        }
    }
}
pub mod authenticate {
    //! Signature evidence authenticator.
    //!
    //! Authenticating a signature fact proves the evidence fact is canonically
    //! addressed and that its embedded public key signed the target fact id. It does
    //! not prove the signer has authority over the target; claim projectors own that
    //! policy through their existing context checks.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::SignatureFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        signature: SignatureFact,
        _context: &ProjectionContext,
    ) -> Result<SignatureFact, String> {
        prove_decoded_signature(fact, signature)
    }

    fn prove_decoded_signature(
        fact: &Fact,
        signature: SignatureFact,
    ) -> Result<SignatureFact, String> {
        verify_fact_id(fact)?;
        prove_signature_evidence(&signature)?;
        Ok(signature)
    }

    pub fn prove_signature_evidence(fact: &SignatureFact) -> Result<(), String> {
        crate::core::crypto::ed25519_verify_canonical(
            &fact.signer_public_key,
            &super::super::encode::signature_message(fact.workspace_id, fact.target_fact_id),
            &fact.signature,
            "signature evidence",
        )
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;

        const PRIVATE_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            super::super::super::author::create_signature([3; 32], [9; 32], &PRIVATE_KEY, 123)
                .expect("signature fact")
        }

        fn authenticate(fact: &Fact) -> Result<super::super::super::fact::SignatureFact, String> {
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
}
pub mod adapt {
    //! Signature evidence semantic adapter.

    use super::super::fact::SignatureFact;

    pub(crate) fn adapt(source: SignatureFact) -> Result<SignatureFact, String> {
        Ok(source)
    }
}

// Signature evidence projector.
//
// POLICY. A signature evidence fact is admitted iff:
//   1. STRUCTURAL. The outer fact scope matches the workspace id carried in
//      the signature evidence body.
//   2. CONTEXT. No incoming context is required; authentication already proved
//      the embedded public key signed the workspace-bound target fact id.
//   3. MATERIALIZE. Publish a `signature_proof` offer keyed by target fact id
//      and signer public key, then mark the evidence fact shareable in that
//      workspace.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::sync::shared_fact::project::share_fact_with_sync;

use super::fact::SignatureFact;

pub const SIGNATURE_PROOF_ROLE: &str = "signature_proof";

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::signature::project::SignatureProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::update::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl SignatureProjector {
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
    use crate::core::project_fact::{ProjectionContext, Projector};

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
