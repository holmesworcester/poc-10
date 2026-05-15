use topo::core::event_bus::EventBus;
use topo::core::handler_dispatch::{HandlerContext, RowIntentHandler};
use topo::core::intents::{AtomicIntent, TableDelete};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::sealed_message::opened_rows::{
    decode_opened_message_row, opened_message_row, OpenedContentRow, OPENED_CONTENT_ROWS,
};

#[test]
fn row_handler_applies_projector_opened_row_put_and_delete_intents() {
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let row_handler = RowIntentHandler::new(&store, &[OPENED_CONTENT_ROWS]);
    let mut bus = EventBus::new();

    bus.submit_intent(
        AtomicIntent::PutRow(opened_message_row(OpenedContentRow {
            message_id: [2; 32],
            minute: 42,
            leaf_id: [3; 32],
        }))
        .into_intent(),
    )
    .expect("submit opened row");
    let rows = bus
        .dispatch_intents(&row_handler, &HandlerContext, 10)
        .expect("row handler");
    assert_eq!(rows.handled, 1);

    let opened_rows = store.table_rows(OPENED_CONTENT_ROWS).expect("opened rows");
    assert_eq!(opened_rows.len(), 1);
    assert_eq!(
        decode_opened_message_row(&opened_rows[0].0, &opened_rows[0].1)
            .expect("decode opened")
            .leaf_id,
        [3; 32]
    );

    bus.submit_intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: OPENED_CONTENT_ROWS,
            key: [2; 32].to_vec(),
        })
        .into_intent(),
    )
    .expect("submit opened delete");
    bus.dispatch_intents(&row_handler, &HandlerContext, 10)
        .expect("delete row");

    assert!(store
        .table_rows(OPENED_CONTENT_ROWS)
        .expect("opened rows after delete")
        .is_empty());
}
