//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the Context protocol as an executable
//! application: runtime declarations, daemon declarations, and command table.
//! The binary selects this description; core consumes it generically.
//!
//! `protocol::registry` is the larger table of contents. This file chooses the
//! pieces needed to run the protocol: schema sources, row mutation allowlist,
//! projector, handler routes, daemon time wakes, and inbound-network intent
//! conversion. If a new protocol capability needs to be
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
    authenticate_fact_for_admission, protocol_projector, FACT_ROUTES, HANDLER_ROUTES,
    ROW_MUTATION_TABLES, SCHEMA_SOURCES,
};
use crate::protocol::registry::{MatchCliContext, MATCH_COMMANDS};
use crate::protocol::{connection, content};

pub const MATCH_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: ROW_MUTATION_TABLES,
    projector: protocol_projector,
    fact_routes: FACT_ROUTES,
    fact_admission: Some(authenticate_fact_for_admission),
    handlers: HANDLER_ROUTES,
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

/// Daemon-owned time wakes.
///
/// Every daemon time wake must be replayable: its high-water mark derives from
/// retained protocol state, not fresh wall-clock. The set is therefore exactly
/// the replayable timelines. Operational wall-clock loops such as connection
/// peer retry are not daemon time wakes; that work is the live recurring
/// `maintain_connections` intent.
const MATCH_DAEMON_TIME_WAKES: &[DaemonTimeWake] = REPLAYABLE_DAEMON_TIME_WAKES;

/// Replayable semantic time-wake timelines.
///
/// Replay admits wall-clock context only through these timelines, whose
/// high-water mark derives from retained protocol state (the store-local
/// logical clock), not fresh wall-clock. `content_message_expiry` qualifies
/// because it only advances disappearing-message expiry, which is replayable
/// protocol state.
pub const REPLAYABLE_DAEMON_TIME_WAKES: &[DaemonTimeWake] = &[DaemonTimeWake {
    timeline: content::message::expiration_timeline,
    end_inclusive: current_message_expiration_minute,
}];

fn receive_network_frame_intent(input: InboundNetworkFrame) -> Result<Intent, String> {
    connection::receive_network_frame::receive_network_frame_intent(
        connection::receive_network_frame::ReceiveNetworkFrame {
            frame: input.frame,
            origin_addr: connection::fact_receipt::fact::canonical_origin_addr_bytes(
                input.origin_addr,
            ),
            received_at_local_ms: input.received_at_local_ms,
        },
    )
}

fn current_message_expiration_minute(store: &Store) -> Result<Option<u64>, String> {
    Ok(clock::logical_time(store)?.map(|now_ms| now_ms / 60_000))
}
