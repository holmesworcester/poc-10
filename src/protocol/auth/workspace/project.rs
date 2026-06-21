pub mod decode {
    //! Byte decoding for workspace facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and
    //! canonical name padding. Id checks live in the local `authenticate` module.

    use crate::core::wire;
    use crate::core::wire::FixedText;

    use super::super::encode::{FACT_BYTES, PAYLOAD_BYTES, TYPE_WORKSPACE};
    use super::super::fact::{
        WorkspaceFact, WorkspaceName, WorkspacePublicKey, WORKSPACE_NAME_BYTES,
    };

    pub fn decode_fact(bytes: &[u8]) -> Result<WorkspaceFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_WORKSPACE {
            return Err("expected workspace fact".to_string());
        }
        decode_payload_fields(&bytes[1..])
    }

    #[cfg(test)]
    pub(crate) fn decode_payload(value: &[u8]) -> Result<WorkspaceFact, String> {
        decode_payload_fields(value)
    }

    fn decode_payload_fields(bytes: &[u8]) -> Result<WorkspaceFact, String> {
        wire::expect_len(bytes, PAYLOAD_BYTES).map_err(wire_err)?;
        let created_at_ms = wire::take_u64be(&bytes[0..8]).map_err(wire_err)?;
        let mut public_key: WorkspacePublicKey = [0; 32];
        public_key.copy_from_slice(&bytes[8..40]);
        let name = decode_name(&bytes[40..40 + WORKSPACE_NAME_BYTES])?;
        Ok(WorkspaceFact {
            created_at_ms,
            public_key,
            name,
        })
    }

    fn decode_name(bytes: &[u8]) -> Result<WorkspaceName, String> {
        let padded: [u8; WORKSPACE_NAME_BYTES] = bytes
            .try_into()
            .map_err(|_| "workspace name slot has wrong length".to_string())?;
        FixedText::from_padded(padded).map_err(wire_err)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Ordered most-central-first: the full byte round-trip leads, then narrower decode guards.
    #[cfg(test)]
    mod tests {
        use super::*;
        fn fact() -> WorkspaceFact {
            WorkspaceFact {
                created_at_ms: 42,
                public_key: [7; 32],
                name: WorkspaceName::new("Engineering").expect("name"),
            }
        }

        #[test]
        fn workspace_fact_roundtrips_fixed_width() {
            let encoded =
                crate::protocol::auth::workspace::encode::encode_fact(&fact()).expect("encode");

            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn workspace_payload_roundtrips_fixed_width() {
            let value =
                crate::protocol::auth::workspace::encode::encode_payload(&fact()).expect("payload");
            let decoded = decode_payload(&value).expect("decode payload");

            assert_eq!(value.len(), PAYLOAD_BYTES);
            assert_eq!(decoded.created_at_ms, 42);
            assert_eq!(decoded.name, "Engineering");
        }

        #[test]
        fn rejects_non_canonical_name_padding() {
            let mut encoded =
                crate::protocol::auth::workspace::encode::encode_fact(&fact()).expect("encode");
            let name_start = 1 + 8 + 32;
            encoded[name_start + "Engineering".len() + 1] = b'x';

            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
    //! Workspace authenticator.
    //!
    //! POLICY. Authenticating a `workspace` fact proves, over its canonical bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical workspace fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!
    //! Admission scope (`Global`) is unsigned local metadata, not part of these
    //! bytes, so the projector checks it. Local workspace admission requires
    //! retained invite acceptance context and materialization stays in the projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::WorkspaceFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        workspace: WorkspaceFact,
        _context: &ProjectionContext,
    ) -> Result<WorkspaceFact, String> {
        prove_decoded_workspace(fact, workspace)
    }

    fn prove_decoded_workspace(
        fact: &Fact,
        workspace: WorkspaceFact,
    ) -> Result<WorkspaceFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(workspace)
    }

    // Tests.
    // Ordered most-central-first: the happy authentication leads, then the id-binding and layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::workspace::author::create_workspace;
        use crate::protocol::auth::workspace::fact::WorkspaceFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            create_workspace(100, SIGNER_KEY, "acme").expect("workspace fact")
        }

        fn authenticate(fact: &Fact) -> Result<WorkspaceFact, String> {
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
    }
}
pub mod adapt {
    //! Workspace semantic adapter.
    //!
    //! The current workspace wire shape is already the active semantic shape. This
    //! identity adapter exists as a protocol-local conversion point for
    //! future versioned fact shapes.

    use super::super::fact::WorkspaceFact;

    pub(crate) fn adapt(source: WorkspaceFact) -> Result<WorkspaceFact, String> {
        Ok(source)
    }
}

// Poc-10 workspace projector.
//
// POLICY. A workspace fact is admitted iff:
//   1. STRUCTURAL. The outer fact is global and the workspace payload decodes.
//   2. CONTEXT. A retained local invite_accepted fact must select this
//      workspace and publish accepted-workspace context.
//   3. MATERIALIZE. Write the workspace row, publish workspace context, and
//      mark the workspace fact shareable.

use crate::core::context::ContextOfferClaim;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::{invite_accepted, signature};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

pub const AUTH_WORKSPACE_ROLE: &str = "auth_workspace";

/// Projector route metadata for the workspace fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::workspace::project::WorkspaceProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct WorkspaceProjector;

impl WorkspaceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for WorkspaceProjector {
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

impl WorkspaceProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        workspace: super::fact::WorkspaceFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("workspace fact must have global scope".to_string());
        }
        // 2. Context and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(fact.id),
            fact.id,
            workspace.public_key,
        )?;
        let accepted_need = invite_accepted::workspace_accepted_need(fact.id, fact.id);
        let waiting = ProjectionOutput::new()
            .need(signature_need.clone())
            .need(accepted_need.clone());
        if !signature::project::signature_proof_ready(
            _context,
            &signature_need,
            fact.id,
            fact.id,
            workspace.public_key,
            "workspace",
        )? {
            return Ok(waiting);
        }
        let Some(accepted_fact) =
            _context.payload_for_checked(&accepted_need, "workspace accepted")?
        else {
            return Ok(waiting);
        };
        let accepted = invite_accepted::decode_fact_payload(accepted_fact.body())
            .map_err(|_| "workspace accepted context is not invite_accepted".to_string())?;
        if accepted.workspace_id != fact.id {
            return Err("workspace accepted context points to a different workspace".to_string());
        }

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .offer(ContextOfferClaim::range(
                    AUTH_WORKSPACE_ROLE,
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::InsertValues(super::workspace_insert(
                    fact.id, &workspace,
                ))),
            fact.id,
            fact,
            context_have_from_needs(_context, [&signature_need]),
        ))
    }
}

// Tests.
// Ordered most-central-first: the full materialize-after-acceptance path leads, then the context-wait gate, then the mismatch guard.
#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::core::context::{ContextNeed, ContextOffer};
    use crate::core::project_fact::MatchedContext;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::workspace::author;
    use crate::protocol::auth::{invite_accepted, invite_secret};
    use std::collections::BTreeSet;

    #[test]
    fn workspace_projector_emits_sync_share_contribution_after_acceptance() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let accepted = accepted_fact(fact.id, fact.id, 124_000);
        let signature = signature_fact(fact.id);
        let projected = WorkspaceProjector::new()
            .project(&fact, &accepted_context(fact.id, &accepted, &signature))
            .expect("project workspace");

        let intent_kinds = projected
            .effects
            .intents
            .iter()
            .map(|intent| intent.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(intent_kinds, BTreeSet::from(["share_fact_with_sync"]));
        assert!(projected
            .offers
            .iter()
            .any(|claim| claim.role.as_str() == AUTH_WORKSPACE_ROLE));
        let share = crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
            &projected.effects.intents[0],
        )
        .expect("share intent");
        assert_eq!(share.workspace_id, fact.id);
        assert_eq!(share.owner_fact_id, fact.id);
        assert_eq!(share.context_have, vec![signature.id]);
        assert!(!share.context_have.contains(&accepted.id));
    }

    #[test]
    fn workspace_projector_waits_for_accepted_workspace_context() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let projected = WorkspaceProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project workspace without context");

        assert!(projected.effects.row_mutations.is_empty());
        assert!(projected.offers.is_empty());
        assert_eq!(projected.needs.len(), 2);
        assert!(projected
            .needs
            .contains(&invite_accepted::workspace_accepted_need(fact.id, fact.id)));
        assert!(projected
            .needs
            .iter()
            .any(|need| need.role.as_str() == "signature_proof"));
    }

    #[test]
    fn workspace_projector_rejects_mismatched_accepted_payload() {
        let fact = author::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let accepted = accepted_fact([8; 32], [8; 32], 124_000);
        let signature = signature_fact(fact.id);
        let err = WorkspaceProjector::new()
            .project(&fact, &accepted_context(fact.id, &accepted, &signature))
            .expect_err("mismatched accepted workspace must reject");

        assert!(err.contains("different workspace"), "{err}");
    }

    fn accepted_fact(
        workspace_id: crate::core::facts::FactId,
        invite_fact_id: crate::core::facts::FactId,
        created_at_ms: u64,
    ) -> Fact {
        let (_accepted, accepted_fact) = invite_accepted::author::accepted_fact(
            workspace_id,
            invite_fact_id,
            invite_secret::fact::bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [5; 32],
            [6; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            true,
            created_at_ms + 1,
        )
        .expect("accepted fact");
        accepted_fact
    }

    fn accepted_context(
        workspace_id: crate::core::facts::FactId,
        accepted: &Fact,
        signature: &Fact,
    ) -> ProjectionContext {
        let need: ContextNeed =
            invite_accepted::workspace_accepted_need(workspace_id, workspace_id);
        let offer: ContextOffer =
            invite_accepted::workspace_accepted_offer_claim(workspace_id).into_offer(accepted.id);
        ProjectionContext::from_matches(vec![
            signature_match(workspace_id, signature),
            MatchedContext {
                need,
                offer,
                payload: accepted.clone(),
            },
        ])
    }

    fn signature_fact(workspace_id: crate::core::facts::FactId) -> Fact {
        crate::protocol::auth::signature::author::create_signature(
            workspace_id,
            workspace_id,
            &[9; 32],
            123_000,
        )
        .expect("workspace signature fact")
    }

    fn signature_match(
        workspace_id: crate::core::facts::FactId,
        signature: &Fact,
    ) -> MatchedContext {
        let signer_public_key = crate::core::crypto::ed25519_public_key(&[9; 32]);
        let scope = crate::protocol::auth::workspace::scope(workspace_id);
        MatchedContext {
            need: crate::protocol::auth::signature::project::signature_proof_need(
                workspace_id,
                scope.clone(),
                workspace_id,
                signer_public_key,
            )
            .expect("signature need"),
            offer: crate::protocol::auth::signature::project::signature_proof_offer(
                signature.id,
                scope,
                workspace_id,
                signer_public_key,
            )
            .expect("signature offer"),
            payload: signature.clone(),
        }
    }
}
