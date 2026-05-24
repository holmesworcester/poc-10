//! Negentropy tree update intent layout.
//!
//! Fact projection emits `update_negentropy_tree` after decoding a fact and
//! validating any context it chooses to advertise as safe dependency context.
//! The handler is intentionally mechanical: it applies the supplied owner leaf
//! view and `context_have` links, and it rejects local-only fact bytes. It does
//! not parse raw selectors or infer dependency closure from fact bodies.

use crate::core::{
    fact_store::persisted_fact,
    facts::FactId,
    intents::{HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind},
};
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::sync::shared_fact;

pub const UPDATE_NEGENTROPY_TREE: &str = "update_negentropy_tree";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateNegentropyTree {
    pub workspace_id: FactId,
    pub owner_fact_id: FactId,
    pub timestamp_ms: u64,
    pub context_have: Vec<FactId>,
}

pub fn update_negentropy_tree_intent(mut input: UpdateNegentropyTree) -> Intent {
    input.context_have.sort();
    input.context_have.dedup();

    let mut payload =
        PayloadWriter::with_capacity(1 + 32 + 32 + 8 + 4 + input.context_have.len() * 32);
    payload.u8(1);
    payload.fixed(&input.workspace_id);
    payload.fixed(&input.owner_fact_id);
    payload.u64be(input.timestamp_ms);
    payload.u32be(
        input
            .context_have
            .len()
            .try_into()
            .expect("context_have count fits u32"),
    );
    for fact_id in &input.context_have {
        payload.fixed(fact_id);
    }

    Intent::new(
        IntentKind::new(UPDATE_NEGENTROPY_TREE).expect("valid update_negentropy_tree kind"),
        update_negentropy_tree_key(&input),
        payload.finish(),
    )
}

pub fn update_negentropy_tree_intent_for_fact(
    workspace_id: FactId,
    fact_id: FactId,
    timestamp_ms: u64,
    context_have: Vec<FactId>,
) -> Intent {
    update_negentropy_tree_intent(UpdateNegentropyTree {
        workspace_id,
        owner_fact_id: fact_id,
        timestamp_ms,
        context_have,
    })
}

pub fn decode_update_negentropy_tree(intent: &Intent) -> Result<UpdateNegentropyTree, String> {
    if intent.kind.as_str() != UPDATE_NEGENTROPY_TREE {
        return Err("expected update_negentropy_tree intent".into());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    reader.expect_u8(1).map_err(payload_error)?;
    let workspace_id = reader.array::<32>().map_err(payload_error)?;
    let owner_fact_id = reader.array::<32>().map_err(payload_error)?;
    let timestamp_ms = reader.u64be().map_err(payload_error)?;
    let count = reader.u32be().map_err(payload_error)? as usize;
    let mut context_have = Vec::with_capacity(count);
    for _ in 0..count {
        context_have.push(reader.array::<32>().map_err(payload_error)?);
    }
    reader.finish().map_err(payload_error)?;
    context_have.sort();
    context_have.dedup();
    let input = UpdateNegentropyTree {
        workspace_id,
        owner_fact_id,
        timestamp_ms,
        context_have,
    };
    if intent.key != update_negentropy_tree_key(&input) {
        return Err("update_negentropy_tree idempotence key does not match payload".into());
    }
    Ok(input)
}

fn update_negentropy_tree_key(input: &UpdateNegentropyTree) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:update-negentropy-tree:v1:");
    hash.update(&input.workspace_id);
    hash.update(&input.owner_fact_id);
    hash.update(&input.timestamp_ms.to_be_bytes());
    for fact_id in &input.context_have {
        hash.update(fact_id);
    }
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid update_negentropy_tree payload: {err}")
}

#[derive(Debug, Clone, Default)]
pub struct UpdateNegentropyTreeHandler;

impl UpdateNegentropyTreeHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for UpdateNegentropyTreeHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_update_negentropy_tree(intent)?;
        Ok(vec![input.owner_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_update_negentropy_tree(raw)?;
        let owner = context.require_fact(&input.owner_fact_id)?;
        context.require_non_local_fact_bytes(&input.owner_fact_id)?;
        // Context links came from projector-validated offers. A context fact may
        // already be purged by the time this queued handler runs.
        for fact_id in &input.context_have {
            let Some(fact) = persisted_fact(context.store()?, fact_id)? else {
                continue;
            };
            HandlerContext::with_facts([fact]).require_non_local_fact_bytes(fact_id)?;
        }
        shared_fact::record_negentropy_contribution(context.store()?, &input, owner)?;
        Ok(crate::core::effects::PipelineEffects::new())
    }
}
