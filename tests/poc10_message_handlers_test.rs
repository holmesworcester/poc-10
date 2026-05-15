use topo::core::event_bus::EventBus;
use topo::core::handler_dispatch::{HandlerContext, RowIntentHandler};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::sealed_message::intent::{
    open_message_intent, purge_event_intent, OpenMessageIntent, PurgeEventIntent,
};
use topo::handlers::open_message::OpenMessageHandler;
use topo::handlers::opened_content_rows::{decode_opened_message_row, OPENED_CONTENT_ROWS};
use topo::handlers::purge_event::PurgeEventHandler;

#[test]
fn open_and_purge_handlers_emit_atomic_row_intents() {
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let row_handler = RowIntentHandler::new(&store, &[OPENED_CONTENT_ROWS]);
    let mut bus = EventBus::new();

    bus.submit_intent(open_message_intent(OpenMessageIntent {
        workspace_id: [1; 32],
        message_id: [2; 32],
        minute: 42,
        leaf_id: [3; 32],
    }))
    .expect("submit open");
    let opened = bus
        .dispatch_intents(&OpenMessageHandler::new(), &HandlerContext, 10)
        .expect("open handler");
    assert_eq!(opened.handled, 1);
    assert_eq!(opened.intents, 1);
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

    bus.submit_intent(purge_event_intent(PurgeEventIntent {
        workspace_id: [1; 32],
        message_id: [2; 32],
    }))
    .expect("submit purge");
    let purged = bus
        .dispatch_intents(&PurgeEventHandler::new(), &HandlerContext, 10)
        .expect("purge handler");
    assert_eq!(purged.handled, 1);
    assert_eq!(purged.intents, 1);
    bus.dispatch_intents(&row_handler, &HandlerContext, 10)
        .expect("delete row");

    assert!(store
        .table_rows(OPENED_CONTENT_ROWS)
        .expect("opened rows after purge")
        .is_empty());
}
