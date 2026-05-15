use topo::core::event_bus::EventBus;
use topo::core::handler_dispatch::{HandlerContext, RowIntentHandler};
use topo::core::intents::{AtomicIntent, TableDelete};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::sealed_message::rows::{
    decode_message_row, decode_sealed_message_row, message_key, message_row, sealed_message_row,
    MessageRow, SealedMessageRow, MESSAGE_ROWS, SEALED_MESSAGE_ROWS,
};

#[test]
fn row_handler_applies_projector_message_row_put_and_delete_intents() {
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let row_handler = RowIntentHandler::new(&store, &[MESSAGE_ROWS, SEALED_MESSAGE_ROWS]);
    let mut bus = EventBus::new();

    bus.submit_intent(
        AtomicIntent::PutRow(
            sealed_message_row(SealedMessageRow {
                workspace_id: [1; 32],
                message_id: [2; 32],
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
    )
    .expect("submit sealed row");
    bus.submit_intent(
        AtomicIntent::PutRow(message_row(MessageRow {
            workspace_id: [1; 32],
            message_id: [2; 32],
            created_at_ms: 42_000,
            author_user_id: [3; 32],
            signer_id: [9; 32],
            minute: 42,
            leaf_id: [5; 32],
        }))
        .into_intent(),
    )
    .expect("submit message row");
    let rows = bus
        .dispatch_intents(&row_handler, &HandlerContext::new(), 10)
        .expect("row handler");
    assert_eq!(rows.handled, 2);

    let sealed_rows = store.table_rows(SEALED_MESSAGE_ROWS).expect("sealed rows");
    assert_eq!(sealed_rows.len(), 1);
    assert_eq!(
        decode_sealed_message_row(&sealed_rows[0].0, &sealed_rows[0].1)
            .expect("decode sealed")
            .ciphertext,
        b"sealed".to_vec()
    );

    let message_rows = store.table_rows(MESSAGE_ROWS).expect("message rows");
    assert_eq!(message_rows.len(), 1);
    assert_eq!(
        decode_message_row(&message_rows[0].0, &message_rows[0].1)
            .expect("decode opened")
            .leaf_id,
        [5; 32]
    );

    bus.submit_intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: MESSAGE_ROWS,
            key: message_key([1; 32], [2; 32]),
        })
        .into_intent(),
    )
    .expect("submit message delete");
    bus.submit_intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: SEALED_MESSAGE_ROWS,
            key: message_key([1; 32], [2; 32]),
        })
        .into_intent(),
    )
    .expect("submit sealed delete");
    bus.dispatch_intents(&row_handler, &HandlerContext::new(), 10)
        .expect("delete row");

    assert!(store
        .table_rows(MESSAGE_ROWS)
        .expect("message rows after delete")
        .is_empty());
    assert!(store
        .table_rows(SEALED_MESSAGE_ROWS)
        .expect("sealed rows after delete")
        .is_empty());
}
