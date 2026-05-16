//! Poc-10 invite-accepted projector.
//!
//! Validates that no event id field in the fact is zero and emits a single
//! `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional): this validates the invite-secret context
//! that the target tree can request exactly, but it still does not perform any
//! broader legacy transit/bootstrap side effects.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::fact_modules::identity_invite::layout as invite_layout;

use super::layout;
use super::rows::invite_accepted_row;

#[derive(Debug, Clone, Default)]
pub struct InviteAcceptedProjector;

impl InviteAcceptedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteAcceptedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("invite_accepted fact must have local scope".to_string());
        }
        let accepted = layout::decode_fact(&fact.bytes)?;
        if accepted.workspace_id == [0; 32]
            || accepted.invite_event_id == [0; 32]
            || accepted.invite_secret_event_id == [0; 32]
            || accepted.bootstrap_hash == [0; 32]
            || accepted.accepted_endpoint_id == [0; 32]
        {
            return Err("invite_accepted fact has empty event id field".to_string());
        }

        let secret_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::invite_secret_role(),
            accepted.invite_secret_event_id,
        );
        let Some(secret_fact) = context.payload_for(&secret_need) else {
            return Ok(ProjectionOutput::new().need(secret_need));
        };
        if secret_fact.id != accepted.invite_secret_event_id {
            return Err("invite_accepted invite_secret context payload id mismatch".to_string());
        }
        if secret_fact.scope != FactScope::Local {
            return Err("invite_accepted invite_secret context must be local".to_string());
        }
        let secret = invite_layout::decode_fact(&secret_fact.bytes)
            .map_err(|_| "invite_accepted dependency is not an invite_secret fact".to_string())?;
        if secret.bootstrap_hash != accepted.bootstrap_hash {
            return Err("invite_accepted bootstrap hash does not match invite_secret".to_string());
        }
        if secret.workspace_id != Some(accepted.workspace_id)
            || secret.invite_event_id != Some(accepted.invite_event_id)
        {
            return Err(
                "invite_accepted invite_secret scope does not match acceptance".to_string(),
            );
        }
        Ok(ProjectionOutput::new()
            .need(secret_need)
            .intent(AtomicIntent::PutRow(invite_accepted_row(fact.id, &accepted)?).into_intent()))
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::FACT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::fact_modules::identity_invite::{
        fact::InviteSecretFact, layout as invite_layout,
    };
    use topo::protocol::fact_modules::identity_invite_accepted::fact::InviteAcceptedFact;
    use topo::protocol::fact_modules::identity_invite_accepted::{layout, project, rows};
    use topo::protocol::matchers as identity_context;

    fn sample_fact() -> InviteAcceptedFact {
        let secret = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        InviteAcceptedFact {
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
            invite_secret_event_id: [3; 32],
            bootstrap_hash: secret.bootstrap_hash,
            accepted_endpoint_id: [5; 32],
        }
    }

    #[test]
    fn invite_accepted_projector_materializes_row_through_atomic_intent() {
        let accepted = sample_fact();
        let fact = Fact::new(
            FactScope::Local,
            1,
            layout::encode_fact(&accepted).expect("encode invite_accepted"),
        );
        let secret = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        let secret_fact = Fact {
            id: accepted.invite_secret_event_id,
            scope: FactScope::Local,
            timestamp: 1,
            bytes: invite_layout::encode_fact(&secret).expect("encode secret"),
        };
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: identity_context::exact_need(
                fact.id,
                identity_context::invite_secret_role(),
                secret_fact.id,
            ),
            offer: identity_context::exact_offer(
                secret_fact.id,
                identity_context::invite_secret_role(),
            ),
            payload: secret_fact,
        }]);

        let output = project::InviteAcceptedProjector::new()
            .project(&fact, &context)
            .expect("project invite_accepted");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 1);
        let row_intent =
            AtomicIntent::from_intent(&output.intents[0], &[rows::INVITE_ACCEPTED_ROWS])
                .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_invite_accepted_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.accepted_endpoint_id, [5; 32]);
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.invite_event_id, [2; 32]);
        assert_eq!(row.invite_accepted_event_id, fact.id);
        assert_eq!(row.invite_secret_event_id, [3; 32]);
        assert_eq!(row.bootstrap_hash, accepted.bootstrap_hash);
    }

    #[test]
    fn invite_accepted_projector_waits_for_invite_secret_context() {
        let accepted = sample_fact();
        let fact = Fact::new(
            FactScope::Local,
            1,
            layout::encode_fact(&accepted).expect("encode invite_accepted"),
        );

        let output = project::InviteAcceptedProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::invite_secret_role());
        assert_eq!(
            output.needs[0].selector.as_bytes(),
            accepted.invite_secret_event_id
        );
    }

    #[test]
    fn invite_accepted_projector_rejects_zero_id_field() {
        let mut accepted = sample_fact();
        accepted.invite_secret_event_id = [0; 32];
        let fact = Fact::new(
            FactScope::Local,
            1,
            layout::encode_fact(&accepted).expect("encode"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::InviteAcceptedProjector::new(),
                &[],
                &store,
                &[rows::INVITE_ACCEPTED_ROWS],
                10,
            )
            .expect_err("zero id must fail");
        assert!(err.contains("empty event id"), "{err}");
    }

    #[test]
    fn invite_accepted_projector_rejects_global_scope() {
        let accepted = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            1,
            layout::encode_fact(&accepted).expect("encode"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::InviteAcceptedProjector::new(),
                &[],
                &store,
                &[rows::INVITE_ACCEPTED_ROWS],
                10,
            )
            .expect_err("global scope must fail");
        assert!(err.contains("local scope"), "{err}");
    }
}
