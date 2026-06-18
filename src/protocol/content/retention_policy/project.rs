pub mod decode {
    //! Byte decoding for retention policy facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, NO_PREVIOUS_POLICY_ID, TYPE_RETENTION_POLICY};
    use super::super::fact::RetentionPolicyFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<RetentionPolicyFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_RETENTION_POLICY {
            return Err("expected content::retention_policy fact".to_string());
        }
        let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
        let mut workspace_id = [0; 32];
        workspace_id.copy_from_slice(&bytes[9..41]);
        let scope_kind = wire::take_u8(&bytes[41..42]).map_err(wire_err)?;
        let mut scope_id = [0; 32];
        scope_id.copy_from_slice(&bytes[42..74]);
        let mut author_user_id = [0; 32];
        author_user_id.copy_from_slice(&bytes[74..106]);
        let mut signer_id = [0; 32];
        signer_id.copy_from_slice(&bytes[106..138]);
        let mut signer_public_key = [0; 32];
        signer_public_key.copy_from_slice(&bytes[138..170]);
        let ttl_minutes = wire::take_u32be(&bytes[170..174]).map_err(wire_err)?;
        let retire_minute = wire::take_u64be(&bytes[174..182]).map_err(wire_err)?;
        let mut supersedes_raw = [0; 32];
        supersedes_raw.copy_from_slice(&bytes[182..214]);
        let supersedes_policy_id = if supersedes_raw == NO_PREVIOUS_POLICY_ID {
            None
        } else {
            Some(supersedes_raw)
        };
        Ok(RetentionPolicyFact {
            workspace_id,
            supersedes_policy_id,
            ttl_minutes,
            retire_minute,
            scope_kind,
            scope_id,
            author_user_id,
            signer_id,
            signer_public_key,
            created_at_ms,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::content::retention_policy::encode::{
            encode_fact, FACT_BYTES, NO_PREVIOUS_POLICY_ID, TYPE_RETENTION_POLICY,
        };

        fn fact() -> RetentionPolicyFact {
            RetentionPolicyFact {
                workspace_id: [1; 32],
                supersedes_policy_id: Some([7; 32]),
                ttl_minutes: 60,
                retire_minute: 12_345,
                scope_kind: crate::protocol::content::retention_policy::fact::SCOPE_KIND_WORKSPACE,
                scope_id: [1; 32],
                author_user_id: [3; 32],
                signer_id: [9; 32],
                signer_public_key: [10; 32],
                created_at_ms: 6_000_000,
            }
        }

        #[test]
        fn retention_policy_fact_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn none_supersedes_uses_zero_sentinel() {
            let mut f = fact();
            f.supersedes_policy_id = None;
            let encoded = encode_fact(&f).expect("encode");
            assert_eq!(&encoded[182..214], &NO_PREVIOUS_POLICY_ID);
            assert_eq!(decode_fact(&encoded).expect("decode"), f);
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_RETENTION_POLICY.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_wrong_length() {
            assert!(decode_fact(&[TYPE_RETENTION_POLICY; 16]).is_err());
        }
    }
}
pub mod authenticate {
    //! Retention-policy authenticator.
    //!
    //! POLICY. Authenticating a `retention_policy` fact proves, over its signed
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical retention-policy fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The natural signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. TTL and created time are non-zero, and a workspace-scoped policy
    //!      names the workspace as its scope id.
    //!
    //! The authority path (root workspace bootstrap vs admin grant), supersession,
    //! and floor tightening are proven from other facts, so they stay in the
    //! projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::RetentionPolicyFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        policy: RetentionPolicyFact,
        _context: &ProjectionContext,
    ) -> Result<RetentionPolicyFact, String> {
        prove_decoded_retention_policy(fact, policy)
    }

    fn prove_decoded_retention_policy(
        fact: &Fact,
        policy: RetentionPolicyFact,
    ) -> Result<RetentionPolicyFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Intrinsic fields.
        if policy.ttl_minutes == 0 {
            return Err("retention policy ttl_minutes must be non-zero".to_string());
        }
        if policy.created_at_ms == 0 {
            return Err("retention policy created_at_ms must be non-zero".to_string());
        }
        if policy.scope_kind == super::super::fact::SCOPE_KIND_WORKSPACE
            && policy.scope_id != policy.workspace_id
        {
            return Err("retention policy workspace-scope id must match workspace_id".to_string());
        }
        Ok(policy)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::content::retention_policy::author::authored_retention_policy_fact;
        use crate::protocol::content::retention_policy::fact::{
            RetentionPolicyFact, SCOPE_KIND_WORKSPACE,
        };

        const PRIVATE_KEY: [u8; 32] = [7; 32];
        const WORKSPACE_ID: [u8; 32] = [1; 32];

        fn canonical_fact() -> Fact {
            authored_retention_policy_fact(
                WORKSPACE_ID,
                None,
                60,
                10,
                SCOPE_KIND_WORKSPACE,
                WORKSPACE_ID,
                [2; 32],
                [3; 32],
                100,
                PRIVATE_KEY,
            )
            .expect("signed retention policy fact")
        }

        fn authenticate(fact: &Fact) -> Result<RetentionPolicyFact, String> {
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
}
pub mod adapt {
    //! Retention-policy semantic adapter.
    //!
    //! The current retention_policy wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::RetentionPolicyFact;

    pub(crate) fn adapt(source: RetentionPolicyFact) -> Result<RetentionPolicyFact, String> {
        Ok(source)
    }
}

// Disappearing-messages retention policy projector (poc-10 target tree).
//
// POLICY. A retention_policy is admitted iff:
//   1. STRUCTURAL. The body decodes, TTL/created time are non-zero, the
//      natural signature verifies, and workspace-scoped policies name the
//      workspace as their scope id.
//   2. AUTHORITY. The authority context is either root workspace bootstrap or
//      an admin grant for the author; predecessor context must match scope.
//   3. MATERIALIZE. Once monotonicity is validated, write the retention
//      policy row, publish exact-fact context, and share the fact with the
//      workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth;
use crate::protocol::content::message;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, share_fact_with_sync,
};

use super::fact::RetentionPolicyFact;
use super::policy_row;

/// Projector route metadata for the retention_policy fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("content::retention_policy::project::RetentionPolicyProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::update::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct RetentionPolicyProjector;

impl RetentionPolicyProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RetentionPolicyProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, projection_context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, projection_context)
    }
}

impl RetentionPolicyProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        policy: RetentionPolicyFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 2. Authority, signature evidence, and predecessor context.
        let bootstrap_root =
            policy.supersedes_policy_id.is_none() && policy.author_user_id == policy.workspace_id;
        let signature_need = auth::signature::project::signature_proof_need(
            fact.id,
            auth::workspace::scope(policy.workspace_id),
            fact.id,
            policy.signer_public_key,
        )?;
        let authority_need = if bootstrap_root {
            crate::core::context::ContextNeed::range(
                fact.id,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                policy.workspace_id,
                policy.workspace_id,
            )
        } else {
            crate::core::context::ContextNeed::range(
                fact.id,
                "auth_admin",
                auth::workspace::scope(policy.workspace_id),
                policy.author_user_id,
                policy.author_user_id,
            )
        };
        let signer_need = (!bootstrap_root).then(|| {
            crate::core::context::ContextNeed::range(
                fact.id,
                "content_signer",
                auth::workspace::scope(policy.workspace_id),
                policy.signer_id,
                policy.signer_id,
            )
        });
        let previous_need = policy.supersedes_policy_id.map(|previous_id| {
            crate::core::context::ContextNeed::range(
                fact.id,
                "sync_exact_fact",
                FactScope::Global,
                previous_id,
                previous_id,
            )
        });
        let mut waiting = ProjectionOutput::new()
            .need(signature_need.clone())
            .need(authority_need.clone());
        if let Some(need) = &signer_need {
            waiting = waiting.need(need.clone());
        }
        if let Some(need) = &previous_need {
            waiting = waiting.need(need.clone());
        }

        if !auth::signature::project::signature_proof_ready(
            projection_context,
            &signature_need,
            policy.workspace_id,
            fact.id,
            policy.signer_public_key,
            "retention policy",
        )? {
            return Ok(waiting);
        }
        let Some(authority_fact) = projection_context.payload_for(&authority_need) else {
            return Ok(waiting);
        };
        let previous_fact = if let Some(need) = &previous_need {
            let Some(payload) = projection_context.payload_for(need) else {
                return Ok(waiting);
            };
            Some(payload)
        } else {
            None
        };
        let signer_fact = if let Some(need) = &signer_need {
            let Some(payload) = projection_context.payload_for(need) else {
                return Ok(waiting);
            };
            Some(payload)
        } else {
            None
        };

        validate_authority(authority_fact, &policy)?;
        if let Some(signer_fact) = signer_fact {
            validate_signer(signer_fact, &policy)?;
        } else if bootstrap_root {
            validate_workspace_bootstrap_signer(authority_fact, &policy)?;
        }
        if let Some(previous) = previous_fact {
            validate_previous(previous, &policy)?;
        }
        let context_have = context_have_from_optional_needs(
            projection_context,
            [
                Some(&signature_need),
                Some(&authority_need),
                signer_need.as_ref(),
                previous_need.as_ref(),
            ],
        );

        // 3. Materialize.
        let row = policy_row(fact.id, &policy);
        Ok(share_fact_with_sync(
            waiting
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "sync_exact_fact",
                    FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .offer(message::retention_floor_offer(fact.id, policy.workspace_id))
                .row_mutation(RowMutation::InsertValues(row)),
            policy.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn validate_authority(authority_fact: &Fact, policy: &RetentionPolicyFact) -> Result<(), String> {
    if let Ok(admin) = decode_admin_payload(authority_fact) {
        if admin.workspace_id != policy.workspace_id {
            return Err("retention policy authority admin workspace mismatch".to_string());
        }
        if admin.user_fact_id != policy.author_user_id {
            return Err("retention policy authority admin user mismatch".to_string());
        }
        return Ok(());
    }

    if policy.supersedes_policy_id.is_none()
        && authority_fact.id == policy.workspace_id
        && policy.author_user_id == policy.workspace_id
        && auth::workspace::decode_fact_payload(authority_fact.body()).is_ok()
    {
        return Ok(());
    }

    Err("retention policy authority context is not valid admin authority".to_string())
}

fn decode_admin_payload(fact: &Fact) -> Result<auth::admin::fact::AdminFact, String> {
    auth::admin::decode_fact_payload(fact.body())
}

fn validate_signer(signer_fact: &Fact, policy: &RetentionPolicyFact) -> Result<(), String> {
    let signer = auth::endpoint_shared::decode_fact_payload(signer_fact.body())
        .map_err(|_| "retention policy signer context must be endpoint_shared".to_string())?;
    if signer.workspace_id != policy.workspace_id {
        return Err("retention policy signer workspace mismatch".to_string());
    }
    if signer.endpoint_id != policy.signer_id {
        return Err("retention policy signer endpoint mismatch".to_string());
    }
    if signer.user_authority_fact_id != policy.author_user_id {
        return Err("retention policy signer user mismatch".to_string());
    }
    if signer.signing_public_key != policy.signer_public_key {
        return Err("retention policy signer public key mismatch".to_string());
    }
    Ok(())
}

fn validate_workspace_bootstrap_signer(
    workspace_fact: &Fact,
    policy: &RetentionPolicyFact,
) -> Result<(), String> {
    let workspace = auth::workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "retention policy bootstrap authority must be workspace".to_string())?;
    if workspace.public_key != policy.signer_public_key {
        return Err("retention policy bootstrap key does not match workspace".to_string());
    }
    if policy.signer_id != policy.workspace_id {
        return Err("retention policy bootstrap signer must be workspace id".to_string());
    }
    Ok(())
}

fn validate_previous(previous_fact: &Fact, policy: &RetentionPolicyFact) -> Result<(), String> {
    if Some(previous_fact.id) != policy.supersedes_policy_id {
        return Err("retention policy previous context payload id mismatch".to_string());
    }
    let previous = super::decode_fact_payload(&previous_fact.bytes).map_err(|_| {
        "retention policy previous context must be a retention policy fact".to_string()
    })?;
    if previous.workspace_id != policy.workspace_id
        || previous.scope_kind != policy.scope_kind
        || previous.scope_id != policy.scope_id
    {
        return Err("retention policy previous scope mismatch".to_string());
    }
    if policy.retire_minute < previous.retire_minute {
        return Err("retention policy retire_minute regresses previous policy".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::{RowMutation, Value};
    use topo::core::project_fact::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth;
    use topo::protocol::auth::admin;
    use topo::protocol::auth::admin::fact::AdminFact;
    use topo::protocol::content::retention_policy::fact::{
        RetentionPolicyFact, SCOPE_KIND_CHANNEL, SCOPE_KIND_WORKSPACE,
    };
    use topo::protocol::content::retention_policy::{
        encode, project, queries, RETENTION_POLICY_ROWS,
    };
    use topo::protocol::sync::share_fact_with_sync;

    fn workspace_policy() -> RetentionPolicyFact {
        let private_key = [9; 32];
        RetentionPolicyFact {
            workspace_id: [1; 32],
            supersedes_policy_id: None,
            ttl_minutes: 60,
            retire_minute: 12_345,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: [1; 32],
            author_user_id: [3; 32],
            signer_id: [3; 32],
            signer_public_key: crypto::ed25519_public_key(&private_key),
            created_at_ms: 6_000_000,
        }
    }

    #[test]
    fn policy_projector_waits_for_authority_then_materializes_row() {
        let policy = workspace_policy();
        let fact = policy_fact(&policy);
        let authority = admin_fact(policy.workspace_id, policy.author_user_id);
        let signer = signer_fact(&policy);
        let projector = project::RetentionPolicyProjector::new();

        let waiting = projector
            .project(&fact, &ProjectionContext::default())
            .expect("missing authority waits");
        assert!(waiting.effects.intents.is_empty());
        assert_eq!(waiting.needs.len(), 3);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(fact.id, &policy),
                    authority_match(fact.id, &policy, authority),
                    signer_match(fact.id, &policy, signer),
                ]),
            )
            .expect("project policy");
        assert_eq!(projected.effects.intents.len(), 1);
        assert_eq!(projected.effects.row_mutations.len(), 1);
        assert!(projected
            .offers
            .iter()
            .any(|offer| offer.role == "sync_exact_fact"));
        assert_share_intent(&projected.effects.intents, policy.workspace_id, fact.id);

        let row = decode_single_put_row(&projected.effects.row_mutations[0]);
        assert_eq!(row.workspace_id, policy.workspace_id);
        assert_eq!(row.policy_id, fact.id);
        assert_eq!(row.scope_kind, SCOPE_KIND_WORKSPACE);
        assert_eq!(row.scope_id, policy.workspace_id);
        assert_eq!(row.ttl_minutes, policy.ttl_minutes);
        assert_eq!(row.retire_minute, policy.retire_minute);
        assert_eq!(row.author_user_id, policy.author_user_id);
        assert_eq!(row.supersedes_policy_id, None);
        assert_eq!(row.created_at_ms, policy.created_at_ms);
    }

    #[test]
    fn policy_projector_requires_previous_policy_and_enforces_monotonic_retire_minute() {
        let previous = RetentionPolicyFact {
            scope_kind: SCOPE_KIND_CHANNEL,
            scope_id: [9; 32],
            retire_minute: 99_000,
            ..workspace_policy()
        };
        let previous_fact = policy_fact(&previous);
        let policy = RetentionPolicyFact {
            supersedes_policy_id: Some(previous_fact.id),
            retire_minute: 99_999,
            ..previous.clone()
        };
        let fact = policy_fact(&policy);
        let authority = admin_fact(policy.workspace_id, policy.author_user_id);
        let signer = signer_fact(&policy);
        let projector = project::RetentionPolicyProjector::new();

        let waiting = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(fact.id, &policy),
                    authority_match(fact.id, &policy, authority.clone()),
                    signer_match(fact.id, &policy, signer.clone()),
                ]),
            )
            .expect("missing previous waits");
        assert!(waiting.effects.intents.is_empty());
        assert_eq!(waiting.needs.len(), 4);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(fact.id, &policy),
                    authority_match(fact.id, &policy, authority.clone()),
                    signer_match(fact.id, &policy, signer.clone()),
                    previous_match(fact.id, previous_fact.clone()),
                ]),
            )
            .expect("matched previous projects");
        assert_share_intent(&projected.effects.intents, policy.workspace_id, fact.id);
        let row = decode_single_put_row(&projected.effects.row_mutations[0]);
        assert_eq!(row.scope_kind, SCOPE_KIND_CHANNEL);
        assert_eq!(row.scope_id, [9; 32]);
        assert_eq!(row.supersedes_policy_id, Some(previous_fact.id));
        assert_eq!(row.retire_minute, 99_999);

        let regressing = RetentionPolicyFact {
            retire_minute: 98_999,
            ..policy
        };
        let regressing_fact = policy_fact(&regressing);
        let err = projector
            .project(
                &regressing_fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(regressing_fact.id, &regressing),
                    authority_match(regressing_fact.id, &regressing, authority),
                    signer_match(regressing_fact.id, &regressing, signer),
                    previous_match(regressing_fact.id, previous_fact),
                ]),
            )
            .expect_err("retire_minute regression fails");
        assert!(err.contains("regresses"), "{err}");
    }

    #[test]
    fn policy_projector_rejects_zero_ttl() {
        let mut policy = workspace_policy();
        policy.ttl_minutes = 0;
        let fact = policy_fact(&policy);
        let err = project::RetentionPolicyProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("zero ttl must fail");
        assert!(err.to_lowercase().contains("ttl"), "{err}");
    }

    #[test]
    fn policy_projector_rejects_workspace_scope_with_mismatched_scope_id() {
        let mut policy = workspace_policy();
        policy.scope_id = [99; 32];
        let fact = policy_fact(&policy);
        let err = project::RetentionPolicyProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("workspace-scope mismatch must fail");
        assert!(err.to_lowercase().contains("workspace"), "{err}");
    }

    #[test]
    fn policy_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let err = project::RetentionPolicyProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("policy") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    fn policy_fact(policy: &RetentionPolicyFact) -> Fact {
        let private_key = [9; 32];
        let mut policy = policy.clone();
        policy.signer_public_key = crypto::ed25519_public_key(&private_key);
        Fact::new(
            FactScope::Global,
            policy.created_at_ms,
            encode::encode_fact(&policy).expect("encode policy"),
        )
    }

    fn admin_fact(workspace_id: [u8; 32], user_fact_id: [u8; 32]) -> Fact {
        let private_key = [9; 32];
        let admin = AdminFact {
            created_at_ms: 1,
            workspace_id,
            public_key: [8; 32],
            authority_fact_id: workspace_id,
            user_fact_id,
            signer_id: workspace_id,
            signer_public_key: crypto::ed25519_public_key(&private_key),
        };
        Fact::new(
            FactScope::Global,
            1,
            admin::encode_fact_payload(&admin).expect("encode admin"),
        )
    }

    fn signer_fact(policy: &RetentionPolicyFact) -> Fact {
        let private_key = [9; 32];
        let signer = auth::endpoint_shared::fact::EndpointSharedFact {
            created_at_ms: 1,
            workspace_id: policy.workspace_id,
            user_authority_fact_id: policy.author_user_id,
            endpoint_id: policy.signer_id,
            signing_public_key: crypto::ed25519_public_key(&private_key),
            endpoint_role: auth::endpoint_shared::fact::EndpointRole::Device,
            device_name: auth::endpoint_shared::fact::EndpointDeviceName::new("laptop")
                .expect("device name"),
            signer_id: [8; 32],
            signer_public_key: crypto::ed25519_public_key(&[8; 32]),
        };
        Fact::new(
            FactScope::Global,
            signer.created_at_ms,
            auth::endpoint_shared::encode::encode_fact(&signer).expect("encode signer"),
        )
    }

    fn authority_match(
        owner: [u8; 32],
        policy: &RetentionPolicyFact,
        authority: Fact,
    ) -> MatchedContext {
        matched(
            crate::core::context::ContextNeed::range(
                owner,
                "auth_admin",
                auth::workspace::scope(policy.workspace_id),
                policy.author_user_id,
                policy.author_user_id,
            ),
            crate::core::context::ContextOffer::range(
                authority.id,
                "auth_admin",
                auth::workspace::scope(policy.workspace_id),
                policy.author_user_id,
                policy.author_user_id,
            ),
            authority,
        )
    }

    fn signer_match(owner: [u8; 32], policy: &RetentionPolicyFact, signer: Fact) -> MatchedContext {
        matched(
            crate::core::context::ContextNeed::range(
                owner,
                "content_signer",
                auth::workspace::scope(policy.workspace_id),
                policy.signer_id,
                policy.signer_id,
            ),
            crate::core::context::ContextOffer::range(
                signer.id,
                "content_signer",
                auth::workspace::scope(policy.workspace_id),
                policy.signer_id,
                policy.signer_id,
            ),
            signer,
        )
    }

    fn previous_match(owner: [u8; 32], previous: Fact) -> MatchedContext {
        matched(
            crate::core::context::ContextNeed::range(
                owner,
                "sync_exact_fact",
                FactScope::Global,
                previous.id,
                previous.id,
            ),
            crate::core::context::ContextOffer::range(
                previous.id,
                "sync_exact_fact",
                FactScope::Global,
                previous.id,
                previous.id,
            ),
            previous,
        )
    }

    fn signature_match(owner: [u8; 32], policy: &RetentionPolicyFact) -> MatchedContext {
        let private_key = [9; 32];
        let signature = auth::signature::author::create_signature(
            policy.workspace_id,
            owner,
            &private_key,
            policy.created_at_ms,
        )
        .expect("signature evidence");
        let scope = auth::workspace::scope(policy.workspace_id);
        matched(
            auth::signature::project::signature_proof_need(
                owner,
                scope.clone(),
                owner,
                policy.signer_public_key,
            )
            .expect("signature need"),
            auth::signature::project::signature_proof_offer(
                signature.id,
                scope,
                owner,
                policy.signer_public_key,
            )
            .expect("signature offer"),
            signature,
        )
    }

    fn matched(
        need: topo::core::context::ContextNeed,
        offer: topo::core::context::ContextOffer,
        payload: Fact,
    ) -> MatchedContext {
        MatchedContext {
            need,
            offer,
            payload,
        }
    }

    fn decode_single_put_row(mutation: &RowMutation) -> queries::RetentionPolicyRow {
        match mutation {
            RowMutation::InsertValues(row) if row.table == RETENTION_POLICY_ROWS => {
                queries::RetentionPolicyRow {
                    workspace_id: bytes32(&row.values[0]),
                    scope_kind: u64_value(&row.values[1]) as u8,
                    scope_id: bytes32(&row.values[2]),
                    policy_id: bytes32(&row.values[3]),
                    created_at_ms: u64_value(&row.values[4]),
                    ttl_minutes: u64_value(&row.values[5]) as u32,
                    retire_minute: u64_value(&row.values[6]),
                    author_user_id: bytes32(&row.values[7]),
                    supersedes_policy_id: {
                        let value = bytes32(&row.values[8]);
                        (value != encode::NO_PREVIOUS_POLICY_ID).then_some(value)
                    },
                }
            }
            _ => panic!("expected retention policy insert"),
        }
    }

    fn bytes32(value: &Value) -> [u8; 32] {
        match value {
            Value::Bytes(bytes) => bytes.as_slice().try_into().expect("bytes32"),
            _ => panic!("expected bytes"),
        }
    }

    fn u64_value(value: &Value) -> u64 {
        match value {
            Value::U64(value) => *value,
            _ => panic!("expected u64"),
        }
    }

    fn assert_share_intent(
        intents: &[topo::core::intents::Intent],
        workspace_id: [u8; 32],
        fact_id: [u8; 32],
    ) {
        let found = intents.iter().any(|intent| {
            if intent.kind.as_str() != "share_fact_with_sync" {
                return false;
            }
            let Ok(input) = share_fact_with_sync::decode_share_fact_with_sync(intent) else {
                return false;
            };
            input.workspace_id == workspace_id && input.owner_fact_id == fact_id
        });
        assert!(found, "missing share_fact_with_sync intent");
    }
}
