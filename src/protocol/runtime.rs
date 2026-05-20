//! Runtime bindings for the concrete `match` protocol.
//!
//! Core owns runtime mechanics. The protocol registry supplies the declarative
//! tables and factories; this module wraps those declarations in a concrete
//! runtime facade and owns daemon-tick behavior.

use crate::core::clock;
use crate::core::daemon::TickActivity;
use crate::core::network;
use crate::core::runtime::{HandlerSet, Runtime, RuntimeDescription, WorkStatus};
use crate::core::tcp;
use crate::protocol::facts::{content, transport};
use crate::protocol::intents::transport as transport_intents;
use crate::protocol::registry::{
    protocol_context_matchers, protocol_projector, ATOMIC_ROW_TABLES, CLI_EFFECT_HANDLER_ROUTES,
    HANDLER_ROUTES, SCHEMA_SOURCES,
};
use std::ops::{Deref, DerefMut};
use std::path::Path;

pub const MATCH_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    schemas: network::SCHEMAS,
    atomic_row_tables: ATOMIC_ROW_TABLES,
    projector: protocol_projector,
    matchers: protocol_context_matchers,
    handlers: HANDLER_ROUTES,
};

pub struct ProtocolRuntime {
    runtime: Runtime,
}

impl ProtocolRuntime {
    pub fn from_runtime(runtime: Runtime) -> Self {
        Self { runtime }
    }

    pub fn open_memory() -> Result<Self, String> {
        Runtime::open_memory(&MATCH_RUNTIME).map(|runtime| Self { runtime })
    }

    pub fn open_disk(path: impl AsRef<Path>) -> Result<Self, String> {
        Runtime::open_disk(&MATCH_RUNTIME, path).map(|runtime| Self { runtime })
    }

    pub fn dispatch_cli_intents(&mut self, limit_per_handler: usize) -> Result<WorkStatus, String> {
        let handlers = HandlerSet::new_excluding(HANDLER_ROUTES, CLI_EFFECT_HANDLER_ROUTES);
        self.runtime
            .dispatch_with_handlers(&handlers, limit_per_handler)
    }

    pub fn daemon_tick(
        &mut self,
        listener: &tcp::Listener,
        work_limit: usize,
    ) -> Result<TickActivity, String> {
        match_daemon_tick(&mut self.runtime, listener, work_limit)
    }
}

impl Deref for ProtocolRuntime {
    type Target = Runtime;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

impl DerefMut for ProtocolRuntime {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.runtime
    }
}

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
