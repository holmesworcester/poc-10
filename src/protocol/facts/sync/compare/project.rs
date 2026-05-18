//! Poc-10 sync compare projector.
//!
//! POLICY. A sync_compare fact is admitted iff:
//!   1. STRUCTURAL. The compare payload decodes with its range summary.
//!   2. CONTEXT. No matched context is required; this is a peer summary.
//!   3. MATERIALIZE. Write the compare row and emit deferred response work only
//!      when the peer explicitly requested an answer.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::intents::sync::send_compare_response::{
    send_sync_compare_response_intent, SendSyncCompareResponse,
};

use super::layout;
use super::rows::sync_compare_row;

#[derive(Debug, Clone, Default)]
pub struct SyncCompareProjector;

impl SyncCompareProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncCompareProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let compare = layout::decode_fact(fact.body())?;
        // 3. Materialize.
        let mut output = ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_compare_row(fact.id, &compare)?).into_intent());
        if compare.response_requested {
            output = output.intent(send_sync_compare_response_intent(SendSyncCompareResponse {
                compare_fact_id: fact.id,
            }));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::sync::compare::fact::{
        RangeSummary, SyncCompareFact, TimestampRange,
    };
    use topo::protocol::facts::sync::compare::{layout, project, rows};
    use topo::protocol::intents::sync::send_compare_response;

    fn sample_fact() -> SyncCompareFact {
        SyncCompareFact {
            connection_id: [4; 32],
            range: TimestampRange {
                start: 100,
                end: 200,
            },
            summary: RangeSummary {
                count: 5,
                fingerprint: [9; 32],
            },
            response_requested: true,
        }
    }

    #[test]
    fn sync_compare_projector_materializes_row_through_atomic_intent() {
        let compare = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            0,
            layout::encode_fact(&compare).expect("encode sync compare"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::SyncCompareProjector::new(),
                &[],
                &store,
                &[rows::SYNC_COMPARE_ROWS],
                10,
            )
            .expect("project sync compare");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 2);
        assert_eq!(bus.intents().len(), 1);
        let response = send_compare_response::decode_send_sync_compare_response(&bus.intents()[0])
            .expect("decode deferred response intent");
        assert_eq!(response.compare_fact_id, fact.id);

        let table = store
            .table_rows(rows::SYNC_COMPARE_ROWS)
            .expect("sync compare rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_sync_compare_row(&table[0].0, &table[0].1)
            .expect("decode sync compare row");
        assert_eq!(row.connection_id, compare.connection_id);
        assert_eq!(row.fact_id, fact.id);
        assert_eq!(row.range_start, 100);
        assert_eq!(row.range_end, 200);
        assert_eq!(row.count, 5);
        assert_eq!(row.fingerprint, [9; 32]);
        assert!(row.response_requested);
    }

    #[test]
    fn sync_compare_projector_does_not_emit_response_intent_when_not_requested() {
        let mut fact = sample_fact();
        fact.response_requested = false;
        let fact = Fact::new(
            FactScope::Global,
            0,
            layout::encode_fact(&fact).expect("encode sync compare"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::SyncCompareProjector::new(),
                &[],
                &store,
                &[rows::SYNC_COMPARE_ROWS],
                10,
            )
            .expect("project sync compare");

        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 1);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn sync_compare_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::SyncCompareProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("sync compare") || err.contains("WrongLength"),
            "{err}"
        );
    }
}
