//! Driver for sync index event recording.
//!
//! The legacy `SyncIndex` in `src/workers/sync.rs` keeps a mutable in-memory
//! index that is fed by `prepare_index_for_response`. That mutable state
//! cannot move into a stateless `IntentHandler` until Wave 6 lifts the
//! index into facts. For poc-10 we pin down the deferred-intent contract
//! and prove dispatch wiring — the handler decodes its intent and returns
//! an empty `HandlerOutput`, so callers can begin enqueueing index-recording
//! intents ahead of the index lift without losing intents.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::handlers::sync_index_update::intent;

#[derive(Debug, Clone, Default)]
pub struct SyncIndexUpdateHandler;

impl SyncIndexUpdateHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SyncIndexUpdateHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::RECORD_INDEXED_EVENT
    }

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        // Once Wave 6 lifts SyncIndex into facts, the matching index fact id
        // will be declared here so the handler can update it deterministically.
        Ok(Vec::new())
    }

    fn handle(&self, raw: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let _input = intent::decode_record_indexed_event(raw)?;
        // No facts to produce yet: the SyncIndex remains owned by the legacy
        // worker. Decoding the intent here proves the dispatch contract and
        // catches malformed payloads at the deferred-intent boundary.
        Ok(HandlerOutput::new())
    }
}
