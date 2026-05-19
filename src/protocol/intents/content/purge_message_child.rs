//! Bounded purge cascade handlers.
//!
//! A cascade intent names one child fact and the parent deletion fact that
//! authorizes removing it. The handler does not scan projection rows; callers
//! enqueue one intent per child discovered by their own bounded context.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};
use crate::protocol::facts::{content::file, content::reaction, content::sealed_message};

pub const PURGE_MESSAGE_CHILD: &str = "purge_message_child";

pub const CASCADE_CHILD_REACTION: u8 = 1;
pub const CASCADE_CHILD_FILE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeMessageChild {
    pub workspace_id: HandlerFactId,
    pub parent_message_id: HandlerFactId,
    pub child_kind: u8,
    pub child_id: HandlerFactId,
    pub parent_deletion_id: HandlerFactId,
}

pub fn purge_message_child_intent(input: PurgeMessageChild) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_MESSAGE_CHILD).expect("valid purge_message_child kind"),
        IntentExecution::Deferred,
        purge_message_child_key(&input),
        encode_purge_message_child(&input),
    )
}

pub fn decode_purge_message_child(intent: &Intent) -> Result<PurgeMessageChild, String> {
    if intent.kind.as_str() != PURGE_MESSAGE_CHILD || intent.execution != IntentExecution::Deferred
    {
        return Err("expected purge_message_child deferred intent".to_string());
    }
    let input = decode_purge_message_child_payload(&intent.payload)?;
    if intent.key != purge_message_child_key(&input) {
        return Err("purge_message_child key does not match payload".to_string());
    }
    Ok(input)
}

fn purge_message_child_key(input: &PurgeMessageChild) -> Vec<u8> {
    let mut key = Vec::with_capacity(129);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.parent_message_id);
    key.push(input.child_kind);
    key.extend_from_slice(&input.child_id);
    key.extend_from_slice(&input.parent_deletion_id);
    key
}

fn encode_purge_message_child(input: &PurgeMessageChild) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("purge_message_child_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            (
                "parent_message_id",
                FieldValue::Bytes(input.parent_message_id.to_vec()),
            ),
            ("child_kind", FieldValue::U8(input.child_kind)),
            ("child_id", FieldValue::Bytes(input.child_id.to_vec())),
            (
                "parent_deletion_id",
                FieldValue::Bytes(input.parent_deletion_id.to_vec()),
            ),
        ],
    )
    .expect("purge_message_child payload matches schema")
}

fn decode_purge_message_child_payload(payload: &[u8]) -> Result<PurgeMessageChild, String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("purge_message_child_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("purge_message_child payload version unsupported".to_string());
    }
    Ok(PurgeMessageChild {
        workspace_id: payload.bytes_array("workspace_id")?,
        parent_message_id: payload.bytes_array("parent_message_id")?,
        child_kind: payload.u8("child_kind")?,
        child_id: payload.bytes_array("child_id")?,
        parent_deletion_id: payload.bytes_array("parent_deletion_id")?,
    })
}

#[derive(Debug, Clone, Default)]
pub struct PurgeMessageChildHandler;

impl PurgeMessageChildHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeMessageChildHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == PURGE_MESSAGE_CHILD
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_message_child(raw_intent)?;
        Ok(vec![input.parent_deletion_id, input.child_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = decode_purge_message_child(raw_intent)?;
        let deletion = sealed_message::layout::decode_message_deletion(
            &context.require_fact(&input.parent_deletion_id)?.bytes,
        )?;
        if deletion.workspace_id != input.workspace_id {
            return Err("cascade parent deletion workspace mismatch".to_string());
        }
        if deletion.target_id != input.parent_message_id {
            return Err("cascade parent deletion target mismatch".to_string());
        }

        let child = context.require_fact(&input.child_id)?;
        match input.child_kind {
            CASCADE_CHILD_REACTION => {
                let reaction = reaction::layout::decode_fact(child.body())?;
                if reaction.workspace_id != input.workspace_id {
                    return Err("cascade reaction workspace mismatch".to_string());
                }
                if reaction.target_message_id != input.parent_message_id {
                    return Err("cascade reaction parent mismatch".to_string());
                }
            }
            CASCADE_CHILD_FILE => {
                let file = file::layout::decode_fact(child.body())?;
                if file.workspace_id != input.workspace_id {
                    return Err("cascade file workspace mismatch".to_string());
                }
                if file.message_id != input.parent_message_id {
                    return Err("cascade file parent mismatch".to_string());
                }
            }
            _ => return Err("cascade child kind is not supported".to_string()),
        }

        Ok(HandlerOutput::new().purge_fact(input.child_id))
    }
}
