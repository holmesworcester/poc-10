//! Stub tests for the target `transit_send_on_connection` handler.
//!
//! The handler currently returns `NOT_YET_WIRED` after decoding its intent and
//! running the event-module sendability guard, because the real packaging code
//! (frame size selection, AEAD encryption, nonce derivation) belongs under
//! `src/event_modules/transit/`. These tests pin only the current boundary
//! contract.

use topo::core::facts::Fact;
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::event_modules::sync;
use topo::handlers::transit::{send_on_connection_intent, HandlerId, TransitSendOnConnection};
use topo::handlers::transit::{TransitSendOnConnectionHandler, NOT_YET_WIRED};

#[test]
fn well_formed_send_intent_is_decoded_then_stops_at_packaging_stub() {
    let fact = Fact::new(
        sync::context::workspace_scope([7; 32]),
        1,
        sync::layout::encode_shared_event(&sync::fact::SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = send_on_connection_intent(TransitSendOnConnection {
        connection_id: [1u8; 32] as HandlerId,
        fact_ids: vec![fact.id],
    });

    let handler = TransitSendOnConnectionHandler::new();
    let err = handler
        .handle(&intent, &HandlerContext::with_facts([fact]))
        .expect_err("transit packaging is not yet wired");
    assert_eq!(err, NOT_YET_WIRED);
}
