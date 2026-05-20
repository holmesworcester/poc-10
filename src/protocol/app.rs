//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the match protocol as an executable
//! application: runtime declarations, daemon declarations, and command table.
//! The binary selects this description; core consumes it generically.

use crate::core::app::ProtocolDescription;
use crate::core::clock;
use crate::core::daemon::{DaemonDescription, DaemonTimeWake, InboundNetworkFrame};
use crate::core::intents::Intent;
use crate::core::network;
use crate::core::runtime::RuntimeDescription;
use crate::core::store::Store;
use crate::protocol::facts::{content, transport};
use crate::protocol::intents::transport as transport_intents;
use crate::protocol::registry::{
    protocol_context_matchers, protocol_projector, ATOMIC_ROW_TABLES,
    COMMAND_EXCLUDED_HANDLER_ROUTES, HANDLER_ROUTES, SCHEMA_SOURCES,
};
use crate::protocol::registry::{MatchCliContext, MATCH_COMMANDS};

pub const MATCH_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    schemas: network::SCHEMAS,
    atomic_row_tables: ATOMIC_ROW_TABLES,
    projector: protocol_projector,
    matchers: protocol_context_matchers,
    handlers: HANDLER_ROUTES,
    command_excluded_handlers: COMMAND_EXCLUDED_HANDLER_ROUTES,
};

pub const MATCH_PROTOCOL: ProtocolDescription<MatchCliContext> = ProtocolDescription {
    name: "match",
    runtime: MATCH_RUNTIME,
    daemon: DaemonDescription {
        inbound_network_intent: Some(receive_transit_frame_intent),
        time_wakes: MATCH_DAEMON_TIME_WAKES,
    },
    commands: MATCH_COMMANDS,
    context: MatchCliContext::new,
};

const MATCH_DAEMON_TIME_WAKES: &[DaemonTimeWake] = &[DaemonTimeWake {
    timeline: content::message::expiration_timeline,
    end_inclusive: current_message_expiration_minute,
}];

fn receive_transit_frame_intent(input: InboundNetworkFrame) -> Result<Intent, String> {
    transport_intents::receive_transit_frame::receive_transit_frame_intent(
        transport_intents::receive_transit_frame::ReceiveTransitFrame {
            frame: input.frame,
            origin_addr: transport::transit_received::addr::canonical_origin_addr_bytes(
                input.origin_addr,
            ),
            received_at_local_ms: input.received_at_local_ms,
        },
    )
}

fn current_message_expiration_minute(store: &Store) -> Result<Option<u64>, String> {
    Ok(clock::logical_time(store)?.map(|now_ms| now_ms / 60_000))
}
