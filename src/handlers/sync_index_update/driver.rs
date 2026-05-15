//! Driver for sync index event recording.
//!
//! The legacy `SyncIndex` in `src/workers/sync.rs` keeps a mutable in-memory
//! index that is fed by `prepare_index_for_response`. That mutable state
//! cannot move into a stateless `IntentHandler` until Wave 6 lifts the
//! index into facts. For poc-10 we pin down the deferred-intent contract
//! and prove dispatch wiring — the handler decodes its intent and then
//! returns `Err(NOT_YET_WIRED)` so callers can enqueue index-recording
//! intents now without losing them once the durable index lift lands.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::handlers::sync_index_update::intent;

pub const NOT_YET_WIRED: &str = "durable sync index update is not yet wired";

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
        // Decode the intent so malformed payloads are caught at the deferred
        // boundary, but do not return success: producing an empty
        // `HandlerOutput` from a successful handle removes the intent from
        // the queue, which would silently swallow the index update until
        // Wave 6 lifts `SyncIndex` into facts. Returning `Err` keeps the
        // intent queued for retry once the durable path lands.
        let _input = intent::decode_record_indexed_event(raw)?;
        Err(NOT_YET_WIRED.to_string())
    }
}
