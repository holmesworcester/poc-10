//! Poc-10 sync have-id projector.
//!
//! Decodes the have-id fact, records it, and asks the sync handler to request
//! the advertised fact if it is not already present locally.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::intents::sync::send_needed_fact_id::{
    send_needed_fact_id_intent, SendNeededFactId,
};

use super::layout;
use super::rows::sync_have_id_row;

#[derive(Debug, Clone, Default)]
pub struct SyncHaveIdProjector;

impl SyncHaveIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncHaveIdProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let have = layout::decode_fact(fact.body())?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_have_id_row(fact.id, &have)?).into_intent())
            .intent(send_needed_fact_id_intent(SendNeededFactId {
                have_fact_id: fact.id,
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
    use topo::protocol::facts::sync::have_id::fact::SyncHaveIdFact;
    use topo::protocol::facts::sync::have_id::{layout, project, rows};

    fn sample_fact() -> SyncHaveIdFact {
        SyncHaveIdFact {
            connection_id: [4; 32],
            timestamp: 777,
            fact_id: [8; 32],
        }
    }

    #[test]
    fn sync_have_id_projector_materializes_row_through_atomic_intent() {
        let have_id = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            0,
            layout::encode_fact(&have_id).expect("encode sync have-id"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::SyncHaveIdProjector::new(),
                &[],
                &store,
                &[rows::SYNC_HAVE_ID_ROWS],
                10,
            )
            .expect("project sync have-id");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 2);
        assert_eq!(bus.intents().len(), 1);

        let table = store
            .table_rows(rows::SYNC_HAVE_ID_ROWS)
            .expect("sync have-id rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_sync_have_id_row(&table[0].0, &table[0].1)
            .expect("decode sync have-id row");
        assert_eq!(row.connection_id, have_id.connection_id);
        assert_eq!(row.fact_id, fact.id);
        assert_eq!(row.timestamp, 777);
        assert_eq!(row.advertised_fact_id, have_id.fact_id);
    }

    #[test]
    fn sync_have_id_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::SyncHaveIdProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("sync have-id") || err.contains("WrongLength"),
            "{err}"
        );
    }
}
