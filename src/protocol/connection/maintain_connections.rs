//! Live connection-maintenance loop.
//!
//! `maintain_connections` is the operational repetition that keeps the local
//! endpoint connected to its bootstrap candidates. It is a live-only recurring
//! intent: the daemon installs an in-memory schedule from the handler registry
//! and fires it on a fixed cadence while the process runs. It is never durable
//! and never runs during replay, so there is nothing to wipe on upgrade and
//! nothing to rebuild.
//!
//! The handler reads only connection-maintenance-owned state — the candidate
//! index — through `maintenance::index`, and never broad-queries auth-owned or
//! endpoint-owned tables. For each candidate it queues a bootstrap send derived
//! from the candidate. A candidate disappears from the index once its request is
//! answered (`unregister_connection_candidate`), so a connected peer stops being
//! retried. Because each fire re-queues the send for every still-pending
//! candidate, the recurring cadence is the retry interval; a dropped send is
//! retried on the next tick. The handler does not mutate candidate rows, so
//! replay rebuilds the index deterministically from retained request facts.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerError, HandlerResult, Intent, IntentKind};
use crate::core::store::Store;

use crate::protocol::connection::maintenance::index::candidate_rows;
use crate::protocol::connection::send_bootstrap_request::{
    send_bootstrap_connection_request_intent, SendBootstrapConnectionRequest,
};

pub const MAINTAIN_CONNECTIONS: &str = "maintain_connections";

/// Build one maintenance tick, or `None` when there is nothing to maintain.
///
/// This is the registry-declared recurring builder. It returns the singleton
/// maintenance intent only when at least one candidate is registered, so the
/// daemon does not queue empty work on every quiet tick.
pub fn build_maintain_connections_intent(store: &Store) -> Result<Option<Intent>, String> {
    if candidate_rows(store)?.is_empty() {
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
        // Reads only the connection-maintenance-owned candidate index. Each
        // still-registered candidate gets one queued bootstrap send; the send is
        // local-only so it never survives into replay.
        for candidate in candidate_rows(store)? {
            effects = effects.local_intent(send_bootstrap_connection_request_intent(
                SendBootstrapConnectionRequest {
                    request_id: candidate.request_id,
                    initiator_ephemeral_secret_id: candidate.initiator_ephemeral_secret_id,
                    addr: candidate.addr,
                },
            )?);
        }
        Ok(effects)
    }
}
