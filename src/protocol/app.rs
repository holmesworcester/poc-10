//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the Context protocol as an executable
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
//! frame to an intent is a small adapter; connection receive admission and
//! frame interpretation live in connection intent and fact modules.

use crate::core::app::ProtocolDescription;
use crate::core::clock;
use crate::core::daemon::{DaemonDescription, DaemonTimeWake, InboundNetworkFrame};
use crate::core::intents::Intent;
use crate::core::runtime::RuntimeDescription;
use crate::core::store::Store;
use crate::protocol::registry::{
    protocol_projector, COMMAND_EXCLUDED_HANDLER_ROUTES, HANDLER_ROUTES, ROW_MUTATION_TABLES,
    SCHEMA_SOURCES,
};
use crate::protocol::registry::{MatchCliContext, MATCH_COMMANDS};
use crate::protocol::{connection, content};

pub const MATCH_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: ROW_MUTATION_TABLES,
    projector: protocol_projector,
    handlers: HANDLER_ROUTES,
    command_excluded_handlers: COMMAND_EXCLUDED_HANDLER_ROUTES,
};

pub const MATCH_PROTOCOL: ProtocolDescription<MatchCliContext> = ProtocolDescription {
    display_name: "Context",
    command_name: "con",
    runtime: MATCH_RUNTIME,
    daemon: DaemonDescription {
        inbound_network_intent: Some(receive_network_frame_intent),
        time_wakes: MATCH_DAEMON_TIME_WAKES,
    },
    commands: MATCH_COMMANDS,
    context: MatchCliContext::new,
};

const MATCH_DAEMON_TIME_WAKES: &[DaemonTimeWake] = &[
    DaemonTimeWake {
        timeline: content::message::expiration_timeline,
        end_inclusive: current_message_expiration_minute,
    },
    DaemonTimeWake {
        timeline: connection::request::peer_retry_timeline,
        end_inclusive: current_wall_clock_ms,
    },
    DaemonTimeWake {
        timeline: connection::response::seed_sync_timeline,
        end_inclusive: current_wall_clock_ms,
    },
];

fn receive_network_frame_intent(input: InboundNetworkFrame) -> Result<Intent, String> {
    connection::receive_network_frame::receive_network_frame_intent(
        connection::receive_network_frame::ReceiveNetworkFrame {
            frame: input.frame,
            origin_addr: connection::fact_receipt::create::canonical_origin_addr_bytes(
                input.origin_addr,
            ),
            received_at_local_ms: input.received_at_local_ms,
        },
    )
}

fn current_message_expiration_minute(store: &Store) -> Result<Option<u64>, String> {
    Ok(clock::logical_time(store)?.map(|now_ms| now_ms / 60_000))
}

fn current_wall_clock_ms(_store: &Store) -> Result<Option<u64>, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("system clock before unix epoch: {err}"))?;
    Ok(Some(u64::try_from(now.as_millis()).unwrap_or(u64::MAX)))
}
