//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the Context protocol as an executable
//! application: runtime declarations, runtime-turn declarations, and command
//! table.
//! The binary selects this description; core consumes it generically.
//!
//! `protocol::registry` is the larger table of contents. This file chooses the
//! pieces needed to run the protocol: schema sources, projected/intent row
//! table allowlists, projector, handler routes, runtime time wakes, and
//! inbound-network intake conversion. If a new protocol capability needs to be
//! visible to core, it is usually declared in the registry and wired into the
//! `CONTEXT_RUNTIME` or `CONTEXT_PROTOCOL` constants here.
//!
//! Keep executable protocol policy out of this file. The conversion from a TCP
//! frame to incoming facts is a small adapter; connection receive admission
//! and frame interpretation live in connection fact and intake modules.

use crate::core::app::ProtocolDescription;
use crate::core::db::Db;
use crate::core::facts::Fact;
use crate::core::runtime::{
    self, InboundNetworkFrame, RuntimeDescription, RuntimeTimeWake, RuntimeTurnDescription,
};
use crate::protocol::registry::{
    authenticate_fact_for_admission, protocol_projector, FACT_ROUTES, HANDLER_ROUTES,
    INTENT_ROW_MUTATION_TABLES, PROJECTED_ROW_MUTATION_TABLES, SCHEMA_SOURCES,
};
use crate::protocol::registry::{ContextCliContext, CONTEXT_COMMANDS};
use crate::protocol::{connection, content};

pub const CONTEXT_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    projected_row_mutation_tables: PROJECTED_ROW_MUTATION_TABLES,
    intent_row_mutation_tables: INTENT_ROW_MUTATION_TABLES,
    projector: protocol_projector,
    fact_routes: FACT_ROUTES,
    fact_admission: Some(authenticate_fact_for_admission),
    handlers: HANDLER_ROUTES,
};

pub const CONTEXT_PROTOCOL: ProtocolDescription<ContextCliContext> = ProtocolDescription {
    display_name: "Context",
    command_name: "con",
    runtime: CONTEXT_RUNTIME,
    runtime_turn: RuntimeTurnDescription {
        inbound_network_intake: Some(receive_network_frame_facts),
        time_wakes: CONTEXT_RUNTIME_TIME_WAKES,
    },
    commands: CONTEXT_COMMANDS,
    context: ContextCliContext::new,
};

/// Live runtime time wakes.
///
/// These wakes are driven by the host runtime turn's current wall time. Replay
/// does not run live wall-clock work; it reprojects retained facts and leaves
/// standing time wakes for the next live runtime turn.
const CONTEXT_RUNTIME_TIME_WAKES: &[RuntimeTimeWake] = &[RuntimeTimeWake {
    timeline: content::message::expiration_timeline,
    end_inclusive: current_message_expiration_minute,
}];

fn receive_network_frame_facts(input: InboundNetworkFrame) -> Result<Vec<Fact>, String> {
    connection::receive_network_frame::receive_network_frame_facts(
        connection::receive_network_frame::ReceiveNetworkFrame {
            frame: input.frame,
            received_at_local_ms: input.received_at_local_ms,
        },
    )
}

fn current_message_expiration_minute(_store: &Db) -> Result<Option<u64>, String> {
    Ok(Some(runtime::now_ms() / 60_000))
}
