//! Deferred intent layout emitted by sealed-message projection.

use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};

use super::fact::WorkspaceId;

pub const PURGE_EVENT: &str = "purge_event";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeEventIntent {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
}

pub fn purge_event_intent(input: PurgeEventIntent) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_EVENT).expect("valid purge_event intent kind"),
        IntentExecution::Deferred,
        message_key(input.workspace_id, input.message_id),
        encode_purge_event_payload(input.message_id),
    )
}

pub fn decode_purge_event_intent(intent: &Intent) -> Result<PurgeEventIntent, String> {
    if intent.kind.as_str() != PURGE_EVENT || intent.execution != IntentExecution::Deferred {
        return Err("expected purge_event deferred intent".to_string());
    }
    let workspace_id = decode_workspace_from_key(&intent.key)?;
    let message_id = decode_message_from_key(&intent.key)?;
    let payload_message_id = decode_purge_event_payload(&intent.payload)?;
    if payload_message_id != message_id {
        return Err("purge_event intent key does not match payload".to_string());
    }
    Ok(PurgeEventIntent {
        workspace_id,
        message_id,
    })
}

fn message_key(workspace_id: WorkspaceId, message_id: FactId) -> Vec<u8> {
    let mut key = workspace_id.to_vec();
    key.extend_from_slice(&message_id);
    key
}

fn decode_workspace_from_key(key: &[u8]) -> Result<WorkspaceId, String> {
    if key.len() != 64 {
        return Err("sealed-message intent key must be workspace id plus message id".to_string());
    }
    Ok(key[0..32].try_into().unwrap())
}

fn decode_message_from_key(key: &[u8]) -> Result<FactId, String> {
    if key.len() != 64 {
        return Err("sealed-message intent key must be workspace id plus message id".to_string());
    }
    Ok(key[32..64].try_into().unwrap())
}

fn encode_purge_event_payload(message_id: FactId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(33);
    payload.push(1);
    payload.extend_from_slice(&message_id);
    payload
}

fn decode_purge_event_payload(payload: &[u8]) -> Result<FactId, String> {
    if payload.len() != 33 || payload[0] != 1 {
        return Err("invalid purge_event intent payload".to_string());
    }
    Ok(payload[1..33].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_event_intent_round_trips_fixed_payload() {
        let input = PurgeEventIntent {
            workspace_id: [1; 32],
            message_id: [2; 32],
        };
        let intent = purge_event_intent(input.clone());

        assert_eq!(decode_purge_event_intent(&intent).unwrap(), input);
        assert_eq!(intent.payload.len(), 33);
    }
}
