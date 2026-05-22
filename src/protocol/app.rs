//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the match protocol as an executable
//! application: runtime declarations, daemon declarations, and command table.
//! The binary selects this description; core consumes it generically.
//!
//! `protocol::registry` is the larger table of contents. This file chooses the
//! pieces needed to run the protocol: schema sources, row mutation allowlist,
//! projector, handler routes, command-excluded handlers, daemon time wakes, and
//! inbound-network intent conversion. If a new protocol capability needs to be
//! visible to core, it is usually declared in the registry and wired into the
//! `MATCH_RUNTIME` or `MATCH_PROTOCOL` constants here.
//!
//! Keep executable protocol policy out of this file. The conversion from a TCP
//! frame to an intent is a small adapter; the actual transport admission and
//! frame interpretation live in transport intent and fact modules.

use crate::core::app::ProtocolDescription;
use crate::core::clock;
use crate::core::daemon::{DaemonDescription, DaemonTimeWake, InboundNetworkFrame};
use crate::core::intents::Intent;
use crate::core::runtime::RuntimeDescription;
use crate::core::store::Store;
use crate::protocol::facts::{content, transport};
use crate::protocol::intents::transport as transport_intents;
use crate::protocol::registry::{
    protocol_projector, COMMAND_EXCLUDED_HANDLER_ROUTES, HANDLER_ROUTES, ROW_MUTATION_TABLES,
    SCHEMA_SOURCES,
};
use crate::protocol::registry::{MatchCliContext, MATCH_COMMANDS};

pub const MATCH_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: ROW_MUTATION_TABLES,
    projector: protocol_projector,
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
