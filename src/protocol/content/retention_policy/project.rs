//! Disappearing-messages retention policy projector (poc-10 target tree).
//!
//! POLICY. A retention_policy is admitted iff:
//!   1. STRUCTURAL. The body decodes, TTL/created time are non-zero, and
//!      workspace-scoped policies name the workspace as their scope id.
//!   2. AUTHORITY. The authority context is either root workspace bootstrap or
//!      an admin grant for the author; predecessor context must match scope.
//!   3. MATERIALIZE. Once monotonicity is validated, write the retention
//!      policy row, publish exact-fact context, and share the fact with the
//!      workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth;
use crate::protocol::content::message;
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::fact::RetentionPolicyFact;
use super::rows::policy_row;

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
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for RetentionPolicyProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        policy: RetentionPolicyFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if policy.ttl_minutes == 0 {
            return Err("retention policy ttl_minutes must be non-zero".to_string());
        }
        if policy.created_at_ms == 0 {
            return Err("retention policy created_at_ms must be non-zero".to_string());
        }
        if policy.scope_kind == super::fact::SCOPE_KIND_WORKSPACE
            && policy.scope_id != policy.workspace_id
        {
            return Err("retention policy workspace-scope id must match workspace_id".to_string());
        }

        // 2. Authority and predecessor context.
        let authority_need = if policy.supersedes_policy_id.is_none()
            && policy.author_user_id == policy.workspace_id
        {
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
        let previous_need = policy.supersedes_policy_id.map(|previous_id| {
            crate::core::context::ContextNeed::range(
                fact.id,
                "sync_exact_fact",
                FactScope::Global,
                previous_id,
                previous_id,
            )
        });
        let mut waiting = ProjectionOutput::new().need(authority_need.clone());
        if let Some(need) = &previous_need {
            waiting = waiting.need(need.clone());
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

        validate_authority(authority_fact, &policy)?;
        if let Some(previous) = previous_fact {
            validate_previous(previous, &policy)?;
        }

        // 3. Materialize.
        let row = policy_row(fact.id, &policy)?;
        Ok(waiting
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(message::retention_floor_offer(fact.id, policy.workspace_id))
            .row_mutation(RowMutation::PutRow(row))
            .intent(share_fact_with_workspace_intent_for_fact(
                policy.workspace_id,
                fact,
            )))
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
        && auth::workspace::decode_fact_payload(&authority_fact.bytes).is_ok()
    {
        return Ok(());
    }

    Err("retention policy authority context is not valid admin authority".to_string())
}

fn decode_admin_payload(fact: &Fact) -> Result<auth::admin::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(auth::admin::TYPE_ADMIN) => auth::admin::decode_fact_payload(fact.body()),
        Some(auth::signed_fact::TYPE_SIGNED_FACT) => {
            let envelope = auth::signed_fact::decode_envelope(fact.body())?;
            if envelope.inner_type != auth::admin::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            auth::admin::decode_fact_payload(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
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

    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth;
    use topo::protocol::auth::admin;
    use topo::protocol::auth::admin::fact::AdminFact;
    use topo::protocol::content::retention_policy::fact::{
        RetentionPolicyFact, SCOPE_KIND_CHANNEL, SCOPE_KIND_WORKSPACE,
    };
    use topo::protocol::content::retention_policy::{layout, project, rows};
    use topo::protocol::sync::share_fact_with_workspace;

    fn workspace_policy() -> RetentionPolicyFact {
        RetentionPolicyFact {
            workspace_id: [1; 32],
            supersedes_policy_id: None,
            ttl_minutes: 60,
            retire_minute: 12_345,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: [1; 32],
            author_user_id: [3; 32],
            created_at_ms: 6_000_000,
        }
    }

    #[test]
    fn policy_projector_waits_for_authority_then_materializes_row() {
        let policy = workspace_policy();
        let fact = policy_fact(&policy);
        let authority = admin_fact(policy.workspace_id, policy.author_user_id);
        let projector = project::RetentionPolicyProjector::new();

        let waiting = projector
            .project(&fact, &ProjectionContext::default())
            .expect("missing authority waits");
        assert!(waiting.effects.intents.is_empty());
        assert_eq!(waiting.needs.len(), 1);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![authority_match(
                    fact.id, &policy, authority,
                )]),
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
        let projector = project::RetentionPolicyProjector::new();

        let waiting = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![authority_match(
                    fact.id,
                    &policy,
                    authority.clone(),
                )]),
            )
            .expect("missing previous waits");
        assert!(waiting.effects.intents.is_empty());
        assert_eq!(waiting.needs.len(), 2);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    authority_match(fact.id, &policy, authority.clone()),
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
                    authority_match(regressing_fact.id, &regressing, authority),
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
        Fact::new(
            FactScope::Global,
            policy.created_at_ms,
            layout::encode_fact(policy).expect("encode policy"),
        )
    }

    fn admin_fact(workspace_id: [u8; 32], user_fact_id: [u8; 32]) -> Fact {
        Fact::new(
            FactScope::Global,
            1,
            admin::encode_fact_payload(&AdminFact {
                created_at_ms: 1,
                workspace_id,
                public_key: [8; 32],
                authority_fact_id: workspace_id,
                user_fact_id,
            })
            .expect("encode admin"),
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

    fn decode_single_put_row(mutation: &RowMutation) -> rows::RetentionPolicyRow {
        match mutation {
            RowMutation::PutRow(row) => {
                rows::decode_policy_row(&row.key, &row.value).expect("decode retention policy row")
            }
            _ => panic!("expected opaque put row"),
        }
    }

    fn assert_share_intent(
        intents: &[topo::core::intents::Intent],
        workspace_id: [u8; 32],
        fact_id: [u8; 32],
    ) {
        let found = intents.iter().any(|intent| {
            if intent.kind.as_str() != "share_fact_with_workspace" {
                return false;
            }
            let Ok(input) = share_fact_with_workspace::decode_share_fact_with_workspace(intent)
            else {
                return false;
            };
            input.workspace_id == workspace_id && input.fact_id == fact_id
        });
        assert!(found, "missing share_fact_with_workspace intent");
    }
}
