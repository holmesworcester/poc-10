//! Poc-10 sync need-id projector.
//!
//! POLICY. A sync_need_id fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes.
//!   2. CONTEXT. No matched context is required; idempotent handler work decides
//!      whether this store can answer.
//!   3. MATERIALIZE. Write the need-id row and emit deferred send-requested-fact
//!      work.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::intents::sync::send_requested_fact::{
    send_requested_fact_intent, SendRequestedFact,
};

use super::layout;
use super::rows::sync_need_id_row;

#[derive(Debug, Clone, Default)]
pub struct SyncNeedIdProjector;

impl SyncNeedIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncNeedIdProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let need = layout::decode_fact(fact.body())?;
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_need_id_row(fact.id, &need)?).into_intent())
            .intent(send_requested_fact_intent(SendRequestedFact {
                need_fact_id: fact.id,
            })))
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::sync::need_id::fact::SyncNeedIdFact;
    use topo::protocol::facts::sync::need_id::{layout, project, rows};

    fn sample_fact() -> SyncNeedIdFact {
        SyncNeedIdFact {
            connection_id: [4; 32],
            fact_id: [8; 32],
        }
    }

    #[test]
    fn sync_need_id_projector_materializes_row_through_atomic_intent() {
        let need_id = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            0,
            layout::encode_fact(&need_id).expect("encode sync need-id"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::SyncNeedIdProjector::new(),
                &[],
                &store,
                &[rows::SYNC_NEED_ID_ROWS],
                10,
            )
            .expect("project sync need-id");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 2);
        assert_eq!(bus.intents().len(), 1);

        let table = store
            .table_rows(rows::SYNC_NEED_ID_ROWS)
            .expect("sync need-id rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_sync_need_id_row(&table[0].0, &table[0].1)
            .expect("decode sync need-id row");
        assert_eq!(row.connection_id, need_id.connection_id);
        assert_eq!(row.fact_id, fact.id);
        assert_eq!(row.requested_fact_id, need_id.fact_id);
    }

    #[test]
    fn sync_need_id_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::SyncNeedIdProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("sync need-id") || err.contains("WrongLength"),
            "{err}"
        );
    }
}
