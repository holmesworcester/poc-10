//! Driver for inbound sync decisions.
//!
//! Real but minimal: this handler implements one sync decision path — when
//! an inbound event references a dependency the local store has not yet
//! materialized, emit a `sync_need_id` follow-up. Full
//! `drain_sync_works`/`StoreSyncContext` mutable-index logic stays in
//! `src/workers/sync.rs` until Wave 6 retires the legacy worker.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::handlers::handle_sync::intent;

#[derive(Debug, Clone, Default)]
pub struct HandleSyncHandler;

impl HandleSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for HandleSyncHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::PROCESS_SYNC_INBOUND
    }

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        // The minimal decision path inspects only the intent payload itself;
        // when wave 6 lifts `StoreSyncContext` into facts, the relevant
        // workspace + connection fact ids will be declared here.
        Ok(Vec::new())
    }

    fn handle(&self, raw: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = intent::decode_process_sync_inbound(raw)?;
        match input.missing_dep_id {
            None => Ok(HandlerOutput::new()),
            Some(needed_id) => {
                let follow_up = intent::sync_need_id_intent(intent::SyncNeedId {
                    connection_id: input.connection_id,
                    needed_id,
                });
                Ok(HandlerOutput::new().intent(follow_up))
            }
        }
    }
}
