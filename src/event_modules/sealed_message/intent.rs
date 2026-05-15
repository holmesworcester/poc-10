//! Deferred intent layout emitted by sealed-message projection.

use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};

use super::fact::WorkspaceId;

pub const OPEN_MESSAGE: &str = "open_message";
pub const PURGE_EVENT: &str = "purge_event";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessageIntent {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub minute: u64,
    pub leaf_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeEventIntent {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
}

pub fn open_message_intent(input: OpenMessageIntent) -> Intent {
    Intent::new(
        IntentKind::new(OPEN_MESSAGE).expect("valid open_message intent kind"),
        IntentExecution::Deferred,
        message_key(input.workspace_id, input.message_id),
        encode_open_message_payload(input.message_id, input.minute, input.leaf_id),
    )
}

pub fn purge_event_intent(input: PurgeEventIntent) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_EVENT).expect("valid purge_event intent kind"),
        IntentExecution::Deferred,
        message_key(input.workspace_id, input.message_id),
        encode_purge_event_payload(input.message_id),
    )
}

pub fn decode_open_message_intent(intent: &Intent) -> Result<OpenMessageIntent, String> {
    if intent.kind.as_str() != OPEN_MESSAGE || intent.execution != IntentExecution::Deferred {
        return Err("expected open_message deferred intent".to_string());
    }
    let workspace_id = decode_workspace_from_key(&intent.key)?;
    let message_id = decode_message_from_key(&intent.key)?;
    let (payload_message_id, minute, leaf_id) = decode_open_message_payload(&intent.payload)?;
    if payload_message_id != message_id {
        return Err("open_message intent key does not match payload".to_string());
    }
    Ok(OpenMessageIntent {
        workspace_id,
        message_id,
        minute,
        leaf_id,
    })
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

fn encode_open_message_payload(message_id: FactId, minute: u64, leaf_id: FactId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(73);
    payload.push(1);
    payload.extend_from_slice(&message_id);
    payload.extend_from_slice(&minute.to_be_bytes());
    payload.extend_from_slice(&leaf_id);
    payload
}

fn decode_open_message_payload(payload: &[u8]) -> Result<(FactId, u64, FactId), String> {
    if payload.len() != 73 || payload[0] != 1 {
        return Err("invalid open_message intent payload".to_string());
    }
    Ok((
        payload[1..33].try_into().unwrap(),
        u64::from_be_bytes(payload[33..41].try_into().unwrap()),
        payload[41..73].try_into().unwrap(),
    ))
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
    fn open_message_intent_round_trips_fixed_payload() {
        let input = OpenMessageIntent {
            workspace_id: [1; 32],
            message_id: [2; 32],
            minute: 42,
            leaf_id: [3; 32],
        };
        let intent = open_message_intent(input.clone());

        assert_eq!(decode_open_message_intent(&intent).unwrap(), input);
        assert_eq!(intent.payload.len(), 73);
    }

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
