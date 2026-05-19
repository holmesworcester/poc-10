use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{AtomicIntent, TableDelete};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::content::message::fact::{ContentMessageFact, NONCE_BYTES};
use topo::protocol::facts::content::message::rows::{
    content_message_key, content_message_row, decode_content_message_row, CONTENT_MESSAGE_ROWS,
};

#[test]
fn projection_drain_applies_atomic_put_and_delete_rows_without_queueing_them() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("open target schema");
    let fact = Fact::new(FactScope::Global, 1, b"sealed-row".to_vec());
    let mut bus = WakeLoop::new();

    bus.submit_fact(fact.clone());
    let report = bus
        .drain_applying_atomic_rows(
            &PutContentMessageRowProjector,
            &[],
            &store,
            &[CONTENT_MESSAGE_ROWS],
            10,
        )
        .expect("drain atomic row");

    assert_eq!(report.projections, 1);
    assert_eq!(report.intents, 1);
    assert!(bus.intents().is_empty());
    bus.save_applying_atomic_rows(&store, &[CONTENT_MESSAGE_ROWS])
        .expect("commit atomic row with wake-loop state");
    assert_eq!(
        decode_content_message_row(
            &content_message_key([1; 32], fact.id),
            &store
                .table_row(CONTENT_MESSAGE_ROWS, &content_message_key([1; 32], fact.id))
                .expect("read row")
                .expect("row should be written"),
        )
        .expect("decode row")
        .frontier_id,
        [8; 32]
    );

    let delete_fact = Fact::new(FactScope::Global, 2, b"delete-sealed-row".to_vec());
    bus.submit_fact(delete_fact);
    let delete_report = bus
        .drain_applying_atomic_rows(
            &DeleteContentMessageRowProjector {
                message_id: fact.id,
            },
            &[],
            &store,
            &[CONTENT_MESSAGE_ROWS],
            10,
        )
        .expect("drain atomic delete");

    assert_eq!(delete_report.projections, 1);
    assert_eq!(delete_report.intents, 1);
    assert!(bus.intents().is_empty());
    bus.save_applying_atomic_rows(&store, &[CONTENT_MESSAGE_ROWS])
        .expect("commit atomic delete with wake-loop state");
    assert!(store
        .table_rows(CONTENT_MESSAGE_ROWS)
        .expect("sealed rows after delete")
        .is_empty());
}

struct PutContentMessageRowProjector;

impl Projector for PutContentMessageRowProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(content_message_row(
                fact.id,
                &ContentMessageFact {
                    workspace_id: [1; 32],
                    created_at_ms: 42_000,
                    author_user_id: [3; 32],
                    signer_id: [9; 32],
                    frontier_id: [8; 32],
                    local_history_node_secret_id: [7; 32],
                    expires_at_minute: u64::MAX,
                    disappearing_setting_id: [6; 32],
                    minute: 42,
                    leaf_id: [5; 32],
                    nonce: [4; NONCE_BYTES],
                    ciphertext: b"sealed".to_vec(),
                },
            ))
            .into_intent(),
        ))
    }
}

struct DeleteContentMessageRowProjector {
    message_id: [u8; 32],
}

impl Projector for DeleteContentMessageRowProjector {
    fn project(
        &self,
        _fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::DeleteRow(TableDelete {
                table: CONTENT_MESSAGE_ROWS,
                key: content_message_key([1; 32], self.message_id),
            })
            .into_intent(),
        ))
    }
}
