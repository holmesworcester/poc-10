use crate::core::intents::Intent;
use crate::core::pipeline_storage::intent_row_key;
use std::collections::BTreeMap;

/// Validate that a batch can be written to a single intent queue.
///
/// Intent durability is owned by the destination table. This check only rejects
/// conflicting duplicates within one destination queue.
pub(super) fn validate_intents(intents: &[Intent]) -> Result<(), String> {
    validate_intents_ignoring_key(intents, None)
}

/// As [`validate_intents`], with the handled row key reserved for the intent
/// currently being consumed.
pub(super) fn validate_intents_ignoring_key(
    intents: &[Intent],
    _ignored_key: Option<&[u8]>,
) -> Result<(), String> {
    let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
    for intent in intents {
        let key = intent_row_key(intent);
        if let Some(existing) = proposed.insert(key, intent) {
            if existing != intent {
                return Err(format!(
                    "pipeline emitted conflicting intents for {}",
                    intent.kind.as_str()
                ));
            }
        }
    }
    Ok(())
}
