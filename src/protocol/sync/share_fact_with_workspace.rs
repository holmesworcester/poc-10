//! Sync shareable-fact recording intent layout.
//!
//! `share_fact_with_workspace` records that an applied workspace-scoped fact
//! is eligible for sync in that workspace. The handler is intentionally
//! bounded: it consumes the update only after the referenced non-local fact is
//! present with the expected timestamp.

use crate::core::{
    facts::{Fact, FactId},
    intents::{HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind},
};
use crate::protocol::sync::shared_fact;
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::sync::seed_connection;

pub const SHARE_FACT_WITH_WORKSPACE: &str = "share_fact_with_workspace";

pub type HandlerId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareFactWithWorkspace {
    pub workspace_id: HandlerId,
    pub fact_id: HandlerId,
    pub timestamp_ms: u64,
}

pub fn share_fact_with_workspace_intent(input: ShareFactWithWorkspace) -> Intent {
    let mut payload = PayloadWriter::with_capacity(1 + 32 + 32 + 8);
    payload.u8(1);
    payload.fixed(&input.workspace_id);
    payload.fixed(&input.fact_id);
    payload.u64be(input.timestamp_ms);
    Intent::new(
        IntentKind::new(SHARE_FACT_WITH_WORKSPACE).expect("valid share_fact_with_workspace kind"),
        share_fact_with_workspace_key(&input),
        payload.finish(),
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
        return Err("expected share_fact_with_workspace intent".into());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    reader.expect_u8(1).map_err(payload_error)?;
    let workspace_id = reader.array::<32>().map_err(payload_error)?;
    let fact_id = reader.array::<32>().map_err(payload_error)?;
    let timestamp_ms = reader.u64be().map_err(payload_error)?;
    reader.finish().map_err(payload_error)?;
    let input = ShareFactWithWorkspace {
        workspace_id,
        fact_id,
        timestamp_ms,
    };
    if intent.key != share_fact_with_workspace_key(&input) {
        return Err("share_fact_with_workspace idempotence key does not match payload".into());
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

fn payload_error(err: PayloadError) -> String {
    format!("invalid share_fact_with_workspace payload: {err}")
}

#[derive(Debug, Clone, Default)]
pub struct ShareFactWithWorkspaceHandler;

impl ShareFactWithWorkspaceHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ShareFactWithWorkspaceHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_share_fact_with_workspace(intent)?;
        Ok(vec![input.fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
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
