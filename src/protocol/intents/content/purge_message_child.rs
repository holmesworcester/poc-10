//! Bounded purge cascade handlers.
//!
//! A cascade intent names one child fact and the parent deletion fact that
//! authorizes removing it. The handler does not scan projection rows; callers
//! enqueue one intent per child discovered by their own bounded context.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::facts::content::{file, message_deletion, reaction};

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
        purge_message_child_key(&input),
        encode_purge_message_child(&input),
    )
}

pub fn decode_purge_message_child(intent: &Intent) -> Result<PurgeMessageChild, String> {
    if intent.kind.as_str() != PURGE_MESSAGE_CHILD {
        return Err("expected purge_message_child deferred intent".into());
    }
    let input = decode_purge_message_child_payload(&intent.payload)?;
    if intent.key != purge_message_child_key(&input) {
        return Err("purge_message_child key does not match payload".into());
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
    let mut payload = Vec::with_capacity(130);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.parent_message_id);
    payload.push(input.child_kind);
    payload.extend_from_slice(&input.child_id);
    payload.extend_from_slice(&input.parent_deletion_id);
    payload
}

fn decode_purge_message_child_payload(payload: &[u8]) -> Result<PurgeMessageChild, String> {
    if payload.len() != 130 || payload[0] != 1 {
        return Err("invalid purge_message_child payload".into());
    }
    Ok(PurgeMessageChild {
        workspace_id: payload[1..33].try_into().unwrap(),
        parent_message_id: payload[33..65].try_into().unwrap(),
        child_kind: payload[65],
        child_id: payload[66..98].try_into().unwrap(),
        parent_deletion_id: payload[98..130].try_into().unwrap(),
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
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_message_child(raw_intent)?;
        Ok(vec![input.parent_deletion_id, input.child_id])
    }

    fn handle(&self, raw_intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_purge_message_child(raw_intent)?;
        let deletion =
            message_deletion::decode_any_fact(context.require_fact(&input.parent_deletion_id)?)?;
        if deletion.workspace_id != input.workspace_id {
            return Err("cascade parent deletion workspace mismatch".into());
        }
        if deletion.target_message_id != input.parent_message_id {
            return Err("cascade parent deletion target mismatch".into());
        }

        let child = context.require_fact(&input.child_id)?;
        match input.child_kind {
            CASCADE_CHILD_REACTION => {
                let reaction = reaction::decode_any_fact(child)?;
                if reaction.workspace_id != input.workspace_id {
                    return Err("cascade reaction workspace mismatch".into());
                }
                if reaction.target_message_id != input.parent_message_id {
                    return Err("cascade reaction parent mismatch".into());
                }
            }
            CASCADE_CHILD_FILE => {
                let file = file::decode_any_fact(child)?;
                if file.workspace_id != input.workspace_id {
                    return Err("cascade file workspace mismatch".into());
                }
                if file.message_id != input.parent_message_id {
                    return Err("cascade file parent mismatch".into());
                }
            }
            _ => return Err("cascade child kind is not supported".into()),
        }

        Ok(PipelineEffects::new().purge_fact(input.child_id))
    }
}
