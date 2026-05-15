//! Stub tests for the target `transit_send_on_connection` handler.
//!
//! The driver currently returns `NOT_YET_WIRED` after decoding its intent,
//! because the real packaging code (frame size selection, AEAD encryption,
//! nonce derivation) belongs under `src/event_modules/transit/`. These
//! tests pin only the envelope-decode + dispatch contract.

use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::handlers::transit::driver::{TransitSendOnConnectionHandler, NOT_YET_WIRED};
use topo::handlers::transit::intent::{
    send_on_connection_intent, HandlerId, TransitSendOnConnection,
};

#[test]
fn well_formed_send_intent_is_decoded_then_stops_at_packaging_stub() {
    let intent = send_on_connection_intent(TransitSendOnConnection {
        connection_id: [1u8; 32] as HandlerId,
        fact_ids: vec![[2u8; 32]],
    });

    let handler = TransitSendOnConnectionHandler::new();
    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("transit packaging is not yet wired");
    assert_eq!(err, NOT_YET_WIRED);
}
