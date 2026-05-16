use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{AtomicIntent, TableDelete};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::FACT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::fact_modules::sealed_message::rows::{
    decode_sealed_message_row, message_key, sealed_message_row, SealedMessageRow,
    SEALED_MESSAGE_ROWS,
};

#[test]
fn projection_drain_applies_atomic_put_and_delete_rows_without_queueing_them() {
    let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let fact = Fact::new(FactScope::Global, 1, b"sealed-row".to_vec());
    let mut bus = WakeLoop::new();

    bus.submit_fact(fact.clone());
    let report = bus
        .drain_applying_atomic_rows(
            &PutSealedRowProjector,
            &[],
            &store,
            &[SEALED_MESSAGE_ROWS],
            10,
        )
        .expect("drain atomic row");

    assert_eq!(report.projections, 1);
    assert_eq!(report.intents, 1);
    assert!(bus.intents().is_empty());
    assert_eq!(
        decode_sealed_message_row(
            &message_key([1; 32], fact.id),
            &store
                .table_row(SEALED_MESSAGE_ROWS, &message_key([1; 32], fact.id))
                .expect("read row")
                .expect("row should be written"),
        )
        .expect("decode row")
        .ciphertext,
        b"sealed".to_vec()
    );

    let delete_fact = Fact::new(FactScope::Global, 2, b"delete-sealed-row".to_vec());
    bus.submit_fact(delete_fact);
    let delete_report = bus
        .drain_applying_atomic_rows(
            &DeleteSealedRowProjector {
                message_id: fact.id,
            },
            &[],
            &store,
            &[SEALED_MESSAGE_ROWS],
            10,
        )
        .expect("drain atomic delete");

    assert_eq!(delete_report.projections, 1);
    assert_eq!(delete_report.intents, 1);
    assert!(bus.intents().is_empty());
    assert!(store
        .table_rows(SEALED_MESSAGE_ROWS)
        .expect("sealed rows after delete")
        .is_empty());
}

struct PutSealedRowProjector;

impl Projector for PutSealedRowProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(
                sealed_message_row(SealedMessageRow {
                    workspace_id: [1; 32],
                    message_id: fact.id,
                    created_at_ms: 42_000,
                    author_user_id: [3; 32],
                    signer_id: [9; 32],
                    frontier_id: [8; 32],
                    local_history_node_secret_id: [7; 32],
                    expires_at_minute: u64::MAX,
                    disappearing_setting_id: [6; 32],
                    minute: 42,
                    leaf_id: [5; 32],
                    nonce: [4; 24],
                    ciphertext: b"sealed".to_vec(),
                })
                .expect("sealed row"),
            )
            .into_intent(),
        ))
    }
}

struct DeleteSealedRowProjector {
    message_id: [u8; 32],
}

impl Projector for DeleteSealedRowProjector {
    fn project(
        &self,
        _fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::DeleteRow(TableDelete {
                table: SEALED_MESSAGE_ROWS,
                key: message_key([1; 32], self.message_id),
            })
            .into_intent(),
        ))
    }
}
