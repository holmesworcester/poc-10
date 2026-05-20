//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the match protocol as an executable
//! application: runtime declarations, daemon tick, and command table. The
//! binary selects this description; core consumes it generically.

use crate::core::app::{DaemonDescription, ProtocolDescription};
use crate::core::clock;
use crate::core::daemon::TickActivity;
use crate::core::network;
use crate::core::runtime::{Runtime, RuntimeDescription};
use crate::core::tcp;
use crate::protocol::facts::{content, transport};
use crate::protocol::intents::transport as transport_intents;
use crate::protocol::registry::{
    protocol_context_matchers, protocol_projector, ATOMIC_ROW_TABLES, HANDLER_ROUTES,
    SCHEMA_SOURCES,
};
use crate::protocol::registry::{MatchCliContext, MATCH_COMMANDS};

pub const MATCH_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    schemas: network::SCHEMAS,
    atomic_row_tables: ATOMIC_ROW_TABLES,
    projector: protocol_projector,
    matchers: protocol_context_matchers,
    handlers: HANDLER_ROUTES,
};

pub const MATCH_PROTOCOL: ProtocolDescription<MatchCliContext> = ProtocolDescription {
    name: "match",
    runtime: MATCH_RUNTIME,
    daemon: DaemonDescription {
        tick: match_daemon_tick,
    },
    commands: MATCH_COMMANDS,
    context: MatchCliContext::new,
};

pub fn match_daemon_tick(
    runtime: &mut Runtime,
    listener: &tcp::Listener,
    work_limit: usize,
) -> Result<TickActivity, String> {
    let accepted = listener.accept_available(runtime.store(), work_limit)?;
    let inbound = network::claim_inbound(runtime.store(), work_limit)?;
    for row in &inbound {
        runtime.submit_intent(
            transport_intents::receive_transit_frame::receive_transit_frame_intent(
                transport_intents::receive_transit_frame::ReceiveTransitFrame {
                    frame: row.bytes.clone(),
                    origin_addr: transport::transit_received::addr::canonical_origin_addr_bytes(
                        row.source.addr(),
                    ),
                    received_at_local_ms: now_ms(),
                },
            )?,
        )?;
    }

    let mut due_time_wakes = 0;
    if let Some(current_minute) = current_minute(runtime.store())? {
        due_time_wakes = runtime.process_due_time_range(
            content::message::expiration_timeline(),
            None,
            current_minute,
            work_limit,
        );
    }
    let projection_before_handlers = runtime.process_projection_until_idle(4, work_limit)?;
    let dispatched = runtime.dispatch_intents(work_limit)?;
    let projection_after_handlers = runtime.process_projection_until_idle(4, work_limit)?;
    if !dispatched.retried {
        network::delete_inbound(runtime.store(), &inbound)?;
    }

    let active = accepted.accepted_connections > 0
        || accepted.value.sent_frames > 0
        || accepted.value.received_frames > 0
        || !inbound.is_empty()
        || due_time_wakes > 0
        || !projection_before_handlers.is_idle()
        || !dispatched.is_idle()
        || !projection_after_handlers.is_idle();
    Ok(TickActivity::from_bool(active))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn current_minute(store: &crate::core::store::Store) -> Result<Option<u64>, String> {
    Ok(clock::logical_time(store)?.map(|now_ms| now_ms / 60_000))
}
