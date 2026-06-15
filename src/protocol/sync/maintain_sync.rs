//! Recurring sync maintenance.
//!
//! The daemon runs this live-only intent on its recurring schedule. It reads the
//! current local sync setting and existing connection rows, then seeds one
//! compare per connection. User commands influence this through projected local
//! state, not by queueing sync work directly.

use crate::core::effects::RuntimeEffects;
use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
use crate::core::runtime::RecurringIntentContext;
use crate::core::store::Store;
use crate::protocol::{connection, sync};

pub const MAINTAIN_SYNC: &str = "maintain_sync";

pub fn build_maintain_sync_intent(
    store: &Store,
    _context: RecurringIntentContext,
) -> Result<Option<Intent>, String> {
    if connection::connection::queries::connection_rows(store)?.is_empty() {
        return Ok(None);
    }
    Ok(Some(maintain_sync_intent()))
}

fn maintain_sync_intent() -> Intent {
    Intent::new(
        IntentKind::new(MAINTAIN_SYNC).expect("valid maintain_sync kind"),
        b"v1".to_vec(),
        vec![1],
    )
}

fn decode_maintain_sync(intent: &Intent) -> Result<(), String> {
    if intent.kind.as_str() != MAINTAIN_SYNC {
        return Err("expected maintain_sync intent".to_string());
    }
    if intent.key != b"v1" || intent.payload != [1] {
        return Err("maintain_sync payload is malformed".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct MaintainSyncHandler;

impl MaintainSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for MaintainSyncHandler {
    fn input_fact_ids(
        &self,
        intent: &Intent,
    ) -> Result<Vec<crate::core::intents::HandlerFactId>, String> {
        decode_maintain_sync(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        decode_maintain_sync(raw)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        let store = context.store()?;
        let mut output = RuntimeEffects::new();
        for row in connection::connection::queries::connection_rows(store)? {
            output = sync::seed_connection::append_connection_shareable_facts(
                output,
                store,
                row.connection_id,
            )?;
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn recurring_builder_skips_when_no_connections_exist() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");

        assert_eq!(
            build_maintain_sync_intent(&store, RecurringIntentContext::default()).expect("build"),
            None
        );
    }

    #[test]
    fn maintain_sync_intent_round_trips() {
        let intent = maintain_sync_intent();

        decode_maintain_sync(&intent).expect("decode");
        assert_eq!(intent.kind.as_str(), MAINTAIN_SYNC);
    }
}
