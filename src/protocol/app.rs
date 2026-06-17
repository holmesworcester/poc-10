//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the Context protocol as an executable
//! application: runtime declarations, daemon declarations, and command table.
//! The binary selects this description; core consumes it generically.
//!
//! `protocol::registry` is the larger table of contents. This file chooses the
//! pieces needed to run the protocol: schema sources, row mutation allowlist,
//! projector, handler routes, daemon time wakes, and inbound-network intake
//! conversion. If a new protocol capability needs to be
//! visible to core, it is usually declared in the registry and wired into the
//! `MATCH_RUNTIME` or `MATCH_PROTOCOL` constants here.
//!
//! Keep executable protocol policy out of this file. The conversion from a TCP
//! frame to receive effects is a small adapter; connection receive admission
//! and frame interpretation live in connection fact and intake modules.

use crate::core::app::ProtocolDescription;
use crate::core::daemon::{DaemonDescription, DaemonTimeWake, InboundNetworkFrame};
use crate::core::effects::RuntimeEffects;
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
        inbound_network_intake: Some(receive_network_frame_effects),
        time_wakes: MATCH_DAEMON_TIME_WAKES,
    },
    commands: MATCH_COMMANDS,
    context: MatchCliContext::new,
};

/// Live daemon time wakes.
///
/// These wakes are driven by the daemon's current wall time. Replay does not
/// run daemon wall-clock work; it reprojects retained facts and leaves standing
/// time wakes for the next live daemon tick.
const MATCH_DAEMON_TIME_WAKES: &[DaemonTimeWake] = &[DaemonTimeWake {
    timeline: content::message::expiration_timeline,
    end_inclusive: current_message_expiration_minute,
}];

fn receive_network_frame_effects(input: InboundNetworkFrame) -> Result<RuntimeEffects, String> {
    connection::receive_network_frame::receive_network_frame_effects(
        connection::receive_network_frame::ReceiveNetworkFrame {
            frame: input.frame,
            origin_addr: connection::fact_receipt::fact::canonical_origin_addr_bytes(
                input.origin_addr,
            ),
            received_at_local_ms: input.received_at_local_ms,
        },
    )
}

fn current_message_expiration_minute(_store: &Store) -> Result<Option<u64>, String> {
    Ok(Some(crate::core::daemon::now_ms() / 60_000))
}
