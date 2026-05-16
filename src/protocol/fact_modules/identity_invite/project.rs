//! Poc-10 invite-secret projector.
//!
//! Validates the invite-secret fact (hash matches secret, scope fields are
//! both present or both absent) and emits a single `PutRow` atomic intent
//! keyed by the bootstrap hash.
//!
//! Legacy parity gap (intentional, see commit message): the legacy invite
//! triplet also emitted a `SendBootstrapRequest` transit intent that consumed
//! the optional dial `SocketAddr` carried in the invite link. The target tree
//! omits the addr field and the bootstrap intent: the transit handlers and
//! signed-fact wiring needed to send a bootstrap request have not been ported
//! yet. This will be tightened once `transit` handlers and the
//! `SendBootstrapRequest` intent are real.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::invite_secret_row;

#[derive(Debug, Clone, Default)]
pub struct InviteSecretProjector;

impl InviteSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("invite_secret fact must have local scope".to_string());
        }
        let invite_secret = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .offer(crate::protocol::matchers::invite_secret_offer(fact.id))
            .offer(crate::protocol::matchers::connection_invite_secret_offer(
                fact.id, fact.id,
            ))
            .intent(AtomicIntent::PutRow(invite_secret_row(&invite_secret)?).into_intent()))
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::FACT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::fact_modules::identity_invite::fact::InviteSecretFact;
    use topo::protocol::fact_modules::identity_invite::{layout, project, rows};

    #[test]
    fn invite_secret_projector_materializes_row_through_atomic_intent() {
        let invite = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        let fact = Fact::new(
            FactScope::Local,
            1,
            layout::encode_fact(&invite).expect("encode invite_secret"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::InviteSecretProjector::new(),
                &[],
                &store,
                &[rows::INVITE_SECRET_ROWS],
                10,
            )
            .expect("project invite_secret");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 1);
        assert!(bus.intents().is_empty());

        let stored = store
            .table_rows(rows::INVITE_SECRET_ROWS)
            .expect("invite_secret rows");
        assert_eq!(stored.len(), 1);
        let row = rows::decode_invite_secret_row(&stored[0].0, &stored[0].1).expect("decode row");
        assert_eq!(row.bootstrap_hash, invite.bootstrap_hash);
        assert_eq!(row.bootstrap_secret, [7; 32]);
        assert_eq!(row.workspace_id, Some([1; 32]));
        assert_eq!(row.invite_event_id, Some([2; 32]));

        assert!(!bus.submit_fact(fact));
        let duplicate = bus
            .drain_applying_atomic_rows(
                &project::InviteSecretProjector::new(),
                &[],
                &store,
                &[rows::INVITE_SECRET_ROWS],
                10,
            )
            .expect("duplicate drain");
        assert_eq!(duplicate.projections, 0);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn invite_secret_projector_persists_unscoped_link_secret() {
        let invite = InviteSecretFact::new([7; 32]);
        let fact = Fact::new(
            FactScope::Local,
            1,
            layout::encode_fact(&invite).expect("encode"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        bus.drain_applying_atomic_rows(
            &project::InviteSecretProjector::new(),
            &[],
            &store,
            &[rows::INVITE_SECRET_ROWS],
            10,
        )
        .expect("project invite_secret");

        let stored = store.table_rows(rows::INVITE_SECRET_ROWS).expect("rows");
        let row = rows::decode_invite_secret_row(&stored[0].0, &stored[0].1).expect("decode row");
        assert_eq!(row.workspace_id, None);
        assert_eq!(row.invite_event_id, None);
    }

    #[test]
    fn invite_secret_projector_rejects_global_scope() {
        let invite = InviteSecretFact::new([7; 32]);
        let fact = Fact::new(
            FactScope::Global,
            1,
            layout::encode_fact(&invite).expect("encode"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::InviteSecretProjector::new(),
                &[],
                &store,
                &[rows::INVITE_SECRET_ROWS],
                10,
            )
            .expect_err("global scope must fail");
        assert!(err.contains("local scope"), "{err}");
    }
}
