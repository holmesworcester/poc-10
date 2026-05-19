//! Bounded retention-floor handler.
//!
//! The intent names one disappearing-messages setting fact and one sealed
//! message fact. The handler purges only when the message minute is below the
//! setting's monotonic retire floor.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};
use crate::protocol::facts::{
    content::sealed_message::retention, encryption::disappearing_messages_setting,
};

pub const PURGE_BELOW_RETENTION_FLOOR: &str = "purge_below_retention_floor";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeBelowRetentionFloor {
    pub workspace_id: HandlerFactId,
    pub setting_id: HandlerFactId,
    pub target_id: HandlerFactId,
}

pub fn purge_below_retention_floor_intent(input: PurgeBelowRetentionFloor) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_BELOW_RETENTION_FLOOR)
            .expect("valid purge_below_retention_floor kind"),
        IntentExecution::Deferred,
        purge_below_retention_floor_key(&input),
        encode_purge_below_retention_floor(&input),
    )
}

pub fn decode_purge_below_retention_floor(
    intent: &Intent,
) -> Result<PurgeBelowRetentionFloor, String> {
    if intent.kind.as_str() != PURGE_BELOW_RETENTION_FLOOR
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected purge_below_retention_floor deferred intent".to_string());
    }
    let input = decode_purge_below_retention_floor_payload(&intent.payload)?;
    if intent.key != purge_below_retention_floor_key(&input) {
        return Err("purge_below_retention_floor key does not match payload".to_string());
    }
    Ok(input)
}

fn purge_below_retention_floor_key(input: &PurgeBelowRetentionFloor) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.setting_id);
    key.extend_from_slice(&input.target_id);
    key
}

fn encode_purge_below_retention_floor(input: &PurgeBelowRetentionFloor) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("purge_below_retention_floor_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            ("setting_id", FieldValue::Bytes(input.setting_id.to_vec())),
            ("target_id", FieldValue::Bytes(input.target_id.to_vec())),
        ],
    )
    .expect("purge_below_retention_floor payload matches schema")
}

fn decode_purge_below_retention_floor_payload(
    payload: &[u8],
) -> Result<PurgeBelowRetentionFloor, String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("purge_below_retention_floor_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("purge_below_retention_floor payload version unsupported".to_string());
    }
    Ok(PurgeBelowRetentionFloor {
        workspace_id: payload.bytes_array("workspace_id")?,
        setting_id: payload.bytes_array("setting_id")?,
        target_id: payload.bytes_array("target_id")?,
    })
}

#[derive(Debug, Clone, Default)]
pub struct PurgeBelowRetentionFloorHandler;

impl PurgeBelowRetentionFloorHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeBelowRetentionFloorHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == PURGE_BELOW_RETENTION_FLOOR
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_below_retention_floor(raw_intent)?;
        Ok(vec![input.setting_id, input.target_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = decode_purge_below_retention_floor(raw_intent)?;
        let setting = disappearing_messages_setting::layout::decode_fact(
            &context.require_fact(&input.setting_id)?.bytes,
        )?;
        let target = context.require_fact(&input.target_id)?;
        let message = retention::decode_sealed_message_fact(target)?;

        if setting.workspace_id != input.workspace_id {
            return Err("purge_below_retention_floor setting workspace mismatch".to_string());
        }
        if message.workspace_id != input.workspace_id {
            return Err("purge_below_retention_floor target workspace mismatch".to_string());
        }
        if message.minute >= setting.retire_minute {
            return Err("purge_below_retention_floor target is not below floor".to_string());
        }
        if let Ok(store) = context.store() {
            retention::delete_message_projection(
                store,
                input.target_id,
                &message,
                "delete retired message rows",
            )?;
        }

        Ok(HandlerOutput::new().purge_fact(input.target_id))
    }
}
