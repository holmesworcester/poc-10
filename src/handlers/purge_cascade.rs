//! Bounded purge cascade handlers.
//!
//! A cascade intent names one child fact and the parent deletion fact that
//! authorizes removing it. The handler does not scan projection rows; callers
//! enqueue one intent per child discovered by their own bounded context.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::event_modules::{content_file, content_reaction, sealed_message};

pub const CASCADE_CHILD_PURGE: &str = "cascade_child_purge";

pub const CASCADE_CHILD_REACTION: u8 = 1;
pub const CASCADE_CHILD_FILE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeChildPurge {
    pub workspace_id: HandlerFactId,
    pub parent_message_id: HandlerFactId,
    pub child_kind: u8,
    pub child_id: HandlerFactId,
    pub parent_deletion_id: HandlerFactId,
}

pub fn cascade_child_purge_intent(input: CascadeChildPurge) -> Intent {
    Intent::new(
        IntentKind::new(CASCADE_CHILD_PURGE).expect("valid cascade_child_purge kind"),
        IntentExecution::Deferred,
        cascade_child_key(&input),
        encode_cascade_child(&input),
    )
}

pub fn decode_cascade_child_purge(intent: &Intent) -> Result<CascadeChildPurge, String> {
    if intent.kind.as_str() != CASCADE_CHILD_PURGE || intent.execution != IntentExecution::Deferred
    {
        return Err("expected cascade_child_purge deferred intent".to_string());
    }
    let input = decode_cascade_child(&intent.payload)?;
    if intent.key != cascade_child_key(&input) {
        return Err("cascade_child_purge key does not match payload".to_string());
    }
    Ok(input)
}

fn cascade_child_key(input: &CascadeChildPurge) -> Vec<u8> {
    let mut key = Vec::with_capacity(129);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.parent_message_id);
    key.push(input.child_kind);
    key.extend_from_slice(&input.child_id);
    key.extend_from_slice(&input.parent_deletion_id);
    key
}

fn encode_cascade_child(input: &CascadeChildPurge) -> Vec<u8> {
    let mut payload = Vec::with_capacity(130);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.parent_message_id);
    payload.push(input.child_kind);
    payload.extend_from_slice(&input.child_id);
    payload.extend_from_slice(&input.parent_deletion_id);
    payload
}

fn decode_cascade_child(payload: &[u8]) -> Result<CascadeChildPurge, String> {
    if payload.len() != 130 || payload[0] != 1 {
        return Err("invalid cascade_child_purge payload".to_string());
    }
    Ok(CascadeChildPurge {
        workspace_id: payload[1..33].try_into().unwrap(),
        parent_message_id: payload[33..65].try_into().unwrap(),
        child_kind: payload[65],
        child_id: payload[66..98].try_into().unwrap(),
        parent_deletion_id: payload[98..130].try_into().unwrap(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct PurgeCascadeHandler;

impl PurgeCascadeHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeCascadeHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == CASCADE_CHILD_PURGE
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_cascade_child_purge(raw_intent)?;
        Ok(vec![input.parent_deletion_id, input.child_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = decode_cascade_child_purge(raw_intent)?;
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
                let reaction = content_reaction::layout::decode_fact(&child.bytes)?;
                if reaction.workspace_id != input.workspace_id {
                    return Err("cascade reaction workspace mismatch".to_string());
                }
                if reaction.target_message_id != input.parent_message_id {
                    return Err("cascade reaction parent mismatch".to_string());
                }
            }
            CASCADE_CHILD_FILE => {
                let file = content_file::layout::decode_fact(&child.bytes)?;
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
