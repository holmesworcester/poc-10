//! Live connection-maintenance loop.
//!
//! `maintain_connections` keeps the local endpoint connected to its bootstrap
//! peers. It is a live-only recurring intent: the daemon installs an in-memory
//! schedule from the handler registry and fires it on a fixed cadence while the
//! process runs. It is never durable and never runs during replay, so there is
//! nothing to wipe on upgrade and nothing to rebuild.
//!
//! It owns no state. Each tick it asks the request family for the pending
//! bootstrap set — local outbound request rows with a route and no answer yet —
//! and queues a bootstrap send for each. That selection is a query over
//! connection-owned read models (request rows and response rows), not a separate
//! maintenance index; an answered request drops out of the query, so a connected
//! peer stops being retried. Because each fire re-queues sends for every
//! still-pending request, the recurring cadence is the retry interval and a
//! dropped send is retried on the next tick.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerError, HandlerResult, Intent, IntentKind};
use crate::core::store::Store;

use crate::protocol::connection::request::pending_bootstrap_requests;
use crate::protocol::connection::send_bootstrap_request::{
    send_bootstrap_connection_request_intent, SendBootstrapConnectionRequest,
};

pub const MAINTAIN_CONNECTIONS: &str = "maintain_connections";

/// Build one maintenance tick, or `None` when there is nothing to maintain.
///
/// This is the registry-declared recurring builder. It returns the singleton
/// maintenance intent only when at least one bootstrap is pending, so the daemon
/// does not queue empty work on every quiet tick.
pub fn build_maintain_connections_intent(store: &Store) -> Result<Option<Intent>, String> {
    if pending_bootstrap_requests(store)?.is_empty() {
        return Ok(None);
    }
    Ok(Some(maintain_connections_intent()))
}

pub fn maintain_connections_intent() -> Intent {
    // The maintenance pass is a singleton: one queued tick collapses to one.
    Intent::new(
        IntentKind::new(MAINTAIN_CONNECTIONS).expect("valid maintain connections intent kind"),
        b"maintain_connections".to_vec(),
        vec![1],
    )
}

#[derive(Debug, Clone, Default)]
pub struct MaintainConnectionsHandler;

impl MaintainConnectionsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl crate::core::intents::IntentHandler for MaintainConnectionsHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        if intent.kind.as_str() != MAINTAIN_CONNECTIONS {
            return Err(HandlerError::fatal("expected maintain_connections intent"));
        }
        let store = context.store()?;
        let mut effects = PipelineEffects::new();
        // Query connection-owned read models for pending bootstraps and queue one
        // local send each. The send is local-only, so it never survives replay.
        for pending in pending_bootstrap_requests(store)? {
            effects = effects.local_intent(send_bootstrap_connection_request_intent(
                SendBootstrapConnectionRequest {
                    request_id: pending.request_id,
                    initiator_ephemeral_secret_id: pending.initiator_ephemeral_secret_id,
                    addr: pending.addr,
                },
            )?);
        }
        Ok(effects)
    }
}
