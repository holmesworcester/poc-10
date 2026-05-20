//! Sync shareable-fact recording intent layout.
//!
//! `share_fact_with_workspace` records that an applied workspace-scoped fact
//! is eligible for sync in that workspace. The handler is intentionally
//! bounded: it consumes the update only after the referenced non-local fact is
//! present with the expected timestamp.

use crate::core::{
    facts::{Fact, FactId},
    handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler},
    intents::{Intent, IntentExecution, IntentKind},
};
use crate::protocol::facts::sync::shared_fact;
use crate::protocol::intents::sync::seed_connection;

pub const SHARE_FACT_WITH_WORKSPACE: &str = "share_fact_with_workspace";

pub type HandlerId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareFactWithWorkspace {
    pub workspace_id: HandlerId,
    pub fact_id: HandlerId,
    pub timestamp_ms: u64,
}

pub fn share_fact_with_workspace_intent(input: ShareFactWithWorkspace) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + 8);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.fact_id);
    payload.extend_from_slice(&input.timestamp_ms.to_be_bytes());
    Intent::new(
        IntentKind::new(SHARE_FACT_WITH_WORKSPACE).expect("valid share_fact_with_workspace kind"),
        IntentExecution::Deferred,
        share_fact_with_workspace_key(&input),
        payload,
    )
}

pub fn share_fact_with_workspace_intent_for_fact(workspace_id: HandlerId, fact: &Fact) -> Intent {
    share_fact_with_workspace_intent(ShareFactWithWorkspace {
        workspace_id,
        fact_id: fact.id,
        timestamp_ms: fact.timestamp,
    })
}

pub fn decode_share_fact_with_workspace(intent: &Intent) -> Result<ShareFactWithWorkspace, String> {
    if intent.kind.as_str() != SHARE_FACT_WITH_WORKSPACE {
        return Err("expected share_fact_with_workspace intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("share_fact_with_workspace intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("share_fact_with_workspace payload version unsupported".to_string());
    }
    let workspace_id = reader.id()?;
    let fact_id = reader.id()?;
    let timestamp_ms = reader.u64()?;
    reader.finish()?;
    let input = ShareFactWithWorkspace {
        workspace_id,
        fact_id,
        timestamp_ms,
    };
    if intent.key != share_fact_with_workspace_key(&input) {
        return Err("share_fact_with_workspace idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn share_fact_with_workspace_key(input: &ShareFactWithWorkspace) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:share-fact-with-workspace:v1:");
    hash.update(&input.workspace_id);
    hash.update(&input.fact_id);
    hash.update(&input.timestamp_ms.to_be_bytes());
    hash.finalize().as_bytes().to_vec()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, String> {
        let byte = self.take(1)?;
        Ok(byte[0])
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn id(&mut self) -> Result<[u8; 32], String> {
        let bytes = self.take(32)?;
        Ok(bytes.try_into().unwrap())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "intent payload length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated intent payload".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("intent payload has trailing bytes".to_string())
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ShareFactWithWorkspaceHandler;

impl ShareFactWithWorkspaceHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ShareFactWithWorkspaceHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SHARE_FACT_WITH_WORKSPACE
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_share_fact_with_workspace(intent)?;
        Ok(vec![input.fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_share_fact_with_workspace(raw)?;
        let fact = context.require_fact(&input.fact_id)?;
        context.require_non_local_fact_bytes(&input.fact_id)?;
        shared_fact::record_shareable_fact(
            context.store()?,
            input.workspace_id,
            fact,
            input.timestamp_ms,
        )?;
        seed_connection::advertise_indexed_fact_to_connections(context.store()?, fact)
    }
}
