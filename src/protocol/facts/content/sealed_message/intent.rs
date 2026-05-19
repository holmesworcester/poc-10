//! Deferred intent layout emitted by sealed-message projection.

use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};

use super::fact::WorkspaceId;

pub const PURGE_DELETED_MESSAGE: &str = "purge_deleted_message";
pub const PURGE_TARGET_MESSAGE: u8 = 1;
pub const PURGE_REASON_AUTHOR_DELETION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeDeletedMessage {
    pub workspace_id: WorkspaceId,
    pub target_kind: u8,
    pub target_id: FactId,
    pub reason_kind: u8,
    pub reason_fact_id: FactId,
}

pub fn purge_deleted_message_intent(input: PurgeDeletedMessage) -> Intent {
    let key = purge_deleted_message_key(
        input.workspace_id,
        input.target_kind,
        input.target_id,
        input.reason_kind,
        input.reason_fact_id,
    );
    Intent::new(
        IntentKind::new(PURGE_DELETED_MESSAGE).expect("valid purge_deleted_message intent kind"),
        IntentExecution::Deferred,
        key,
        encode_purge_deleted_message_payload(&input),
    )
}

pub fn decode_purge_deleted_message_intent(intent: &Intent) -> Result<PurgeDeletedMessage, String> {
    if intent.kind.as_str() != PURGE_DELETED_MESSAGE
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected purge_deleted_message deferred intent".to_string());
    }
    let decoded = decode_purge_deleted_message_payload(&intent.payload)?;
    let expected_key = purge_deleted_message_key(
        decoded.workspace_id,
        decoded.target_kind,
        decoded.target_id,
        decoded.reason_kind,
        decoded.reason_fact_id,
    );
    if intent.key != expected_key {
        return Err("purge_deleted_message intent key does not match payload".to_string());
    }
    Ok(decoded)
}

fn purge_deleted_message_key(
    workspace_id: WorkspaceId,
    target_kind: u8,
    target_id: FactId,
    reason_kind: u8,
    reason_fact_id: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(98);
    key.extend_from_slice(&workspace_id);
    key.push(target_kind);
    key.extend_from_slice(&target_id);
    key.push(reason_kind);
    key.extend_from_slice(&reason_fact_id);
    key
}

fn encode_purge_deleted_message_payload(input: &PurgeDeletedMessage) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("purge_deleted_message_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            ("target_kind", FieldValue::U8(input.target_kind)),
            ("target_id", FieldValue::Bytes(input.target_id.to_vec())),
            ("reason_kind", FieldValue::U8(input.reason_kind)),
            (
                "reason_fact_id",
                FieldValue::Bytes(input.reason_fact_id.to_vec()),
            ),
        ],
    )
    .expect("purge_deleted_message payload matches schema")
}

fn decode_purge_deleted_message_payload(payload: &[u8]) -> Result<PurgeDeletedMessage, String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("purge_deleted_message_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("purge_deleted_message payload version unsupported".to_string());
    }
    Ok(PurgeDeletedMessage {
        workspace_id: payload.bytes_array("workspace_id")?,
        target_kind: payload.u8("target_kind")?,
        target_id: payload.bytes_array("target_id")?,
        reason_kind: payload.u8("reason_kind")?,
        reason_fact_id: payload.bytes_array("reason_fact_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_deleted_message_intent_round_trips_fixed_payload() {
        let input = PurgeDeletedMessage {
            workspace_id: [1; 32],
            target_kind: PURGE_TARGET_MESSAGE,
            target_id: [2; 32],
            reason_kind: PURGE_REASON_AUTHOR_DELETION,
            reason_fact_id: [3; 32],
        };
        let intent = purge_deleted_message_intent(input.clone());

        assert_eq!(decode_purge_deleted_message_intent(&intent).unwrap(), input);
        assert_eq!(intent.key.len(), 98);
        assert_eq!(intent.payload.len(), 99);
    }

    #[test]
    fn purge_deleted_message_intent_rejects_key_payload_mismatch() {
        let mut intent = purge_deleted_message_intent(PurgeDeletedMessage {
            workspace_id: [1; 32],
            target_kind: PURGE_TARGET_MESSAGE,
            target_id: [2; 32],
            reason_kind: PURGE_REASON_AUTHOR_DELETION,
            reason_fact_id: [3; 32],
        });
        intent.key[97] ^= 0xff;

        assert!(decode_purge_deleted_message_intent(&intent).is_err());
    }
}
