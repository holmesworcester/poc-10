//! Recurring intent that emits update facts when the schema-declared protocol marker is stale.
//!
//! The recurring `check_version` intent compares the schema-declared protocol marker with
//! `CURRENT_PROTOCOL_VERSION`. A mismatch emits a priority local update fact;
//! projecting that fact records protocol-visible update history, requests the
//! generic rebuild effect, and advances the schema-declared protocol marker.

use crate::core::effects::{RuntimeEffects, StorageRequirement};
use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
use crate::core::runtime::RecurringIntentContext;

use crate::protocol::versioning::{
    local_update::{author::update_fact, fact::UpdateFact},
    CURRENT_PROTOCOL_VERSION,
};

pub const CHECK_VERSION: &str = "check_version";
pub const STORAGE_REQUIREMENT: StorageRequirement = StorageRequirement::MaintenanceBypass;

pub fn stored_storage_version(store: &crate::core::db::Db) -> Result<Option<u32>, String> {
    store
        .current_storage_version()
        .map_err(|err| format!("read storage version marker: {err}"))
}

pub fn storage_ready(store: &crate::core::db::Db) -> Result<bool, String> {
    store
        .storage_version_is(CURRENT_PROTOCOL_VERSION)
        .map_err(|err| format!("read storage version marker: {err}"))
}

pub fn build_check_version_intent(
    store: &crate::core::db::Db,
    context: RecurringIntentContext,
) -> Result<Option<Intent>, String> {
    if storage_ready(store)? {
        return Ok(None);
    }
    Ok(Some(check_version_intent(context.now_ms)))
}

fn check_version_intent(now_ms: u64) -> Intent {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
    payload.extend_from_slice(&now_ms.to_be_bytes());
    let mut key = b"v".to_vec();
    key.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
    key.extend_from_slice(&now_ms.to_be_bytes());
    Intent::new(
        IntentKind::new(CHECK_VERSION).expect("valid check_version kind"),
        key,
        payload,
    )
}

fn decode_check_version(intent: &Intent) -> Result<UpdateFact, String> {
    if intent.kind.as_str() != CHECK_VERSION {
        return Err("expected check_version intent".to_string());
    }
    if intent.payload.len() != 12 {
        return Err("check_version intent payload must be 12 bytes".to_string());
    }
    let protocol_version = u32::from_be_bytes(
        intent.payload[0..4]
            .try_into()
            .expect("slice length checked"),
    );
    let applied_at_ms = u64::from_be_bytes(
        intent.payload[4..12]
            .try_into()
            .expect("slice length checked"),
    );
    Ok(UpdateFact {
        protocol_version,
        applied_at_ms,
    })
}

#[derive(Debug, Clone, Default)]
pub struct CheckVersionHandler;

impl CheckVersionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CheckVersionHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        let update = decode_check_version(intent)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        if storage_ready(context.db()?)? {
            return Ok(RuntimeEffects::new());
        }
        Ok(RuntimeEffects::new().priority_fact(update_fact(update)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::intents::IntentHandler;
    use crate::core::runtime::Runtime;
    use crate::protocol::app::CONTEXT_RUNTIME;
    use crate::protocol::versioning::local_update::encode::decode_update_fact;
    use rusqlite::params;

    fn replace_stored_version_for_test(store: &crate::core::db::Db, protocol_version: u32) {
        store
            .write_transaction(|tx| {
                tx.conn().execute("DELETE FROM protocol_version_rows", [])?;
                tx.conn().execute(
                    "INSERT INTO protocol_version_rows
                        (update_fact_id, protocol_version, applied_at_ms)
                     VALUES (?1, ?2, ?3)",
                    params![vec![1_u8; 32], i64::from(protocol_version), 1_i64],
                )?;
                Ok(())
            })
            .expect("replace stored protocol version");
    }

    fn delete_stored_version_for_test(store: &crate::core::db::Db) {
        store
            .write_transaction(|tx| {
                tx.conn().execute("DELETE FROM protocol_version_rows", [])?;
                Ok(())
            })
            .expect("delete stored protocol version");
    }

    #[test]
    fn check_version_handler_emits_priority_update_fact() {
        let runtime = Runtime::open_memory(&CONTEXT_RUNTIME).expect("runtime");
        replace_stored_version_for_test(runtime.db(), CURRENT_PROTOCOL_VERSION - 1);
        let intent = check_version_intent(55);
        let context = HandlerContext::new().with_db(runtime.db());
        let output = CheckVersionHandler::new()
            .handle(&intent, &context)
            .expect("handle check_version");
        assert!(output.facts.is_empty());
        assert_eq!(output.priority_facts.len(), 1);
        assert_eq!(
            decode_update_fact(output.priority_facts[0].body())
                .expect("decode update")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
    }

    #[test]
    fn missing_storage_marker_queues_and_emits_update_fact() {
        let runtime = Runtime::open_memory(&CONTEXT_RUNTIME).expect("runtime");
        delete_stored_version_for_test(runtime.db());

        assert!(build_check_version_intent(
            runtime.db(),
            RecurringIntentContext {
                now_ms: 77,
                local_addr: None,
            },
        )
        .expect("build check_version")
        .is_some());

        let intent = check_version_intent(77);
        let context = HandlerContext::new().with_db(runtime.db());
        let output = CheckVersionHandler::new()
            .handle(&intent, &context)
            .expect("handle missing marker");

        assert_eq!(output.priority_facts.len(), 1);
        assert_eq!(
            decode_update_fact(output.priority_facts[0].body())
                .expect("decode update")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
    }
}
