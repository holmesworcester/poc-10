//! Negentropy contribution recording intent layout.
//!
//! Fact projection emits `add_to_negentropy` after decoding a fact and
//! validating any context it chooses to advertise as safe dependency context.
//! The handler is intentionally mechanical: it persists the supplied owner leaf
//! and `context_have` links, and it rejects local-only fact bytes. It does not
//! parse raw selectors or infer dependency closure from fact bodies.

use crate::core::{
    facts::FactId,
    intents::{HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind},
};
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::sync::shared_fact;

pub const ADD_TO_NEGENTROPY: &str = "add_to_negentropy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddToNegentropy {
    pub workspace_id: FactId,
    pub owner_fact_id: FactId,
    pub timestamp_ms: u64,
    pub context_have: Vec<FactId>,
}

pub fn add_to_negentropy_intent(mut input: AddToNegentropy) -> Intent {
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
        IntentKind::new(ADD_TO_NEGENTROPY).expect("valid add_to_negentropy kind"),
        add_to_negentropy_key(&input),
        payload.finish(),
    )
}

pub fn add_to_negentropy_intent_for_fact(
    workspace_id: FactId,
    fact_id: FactId,
    timestamp_ms: u64,
    context_have: Vec<FactId>,
) -> Intent {
    add_to_negentropy_intent(AddToNegentropy {
        workspace_id,
        owner_fact_id: fact_id,
        timestamp_ms,
        context_have,
    })
}

pub fn decode_add_to_negentropy(intent: &Intent) -> Result<AddToNegentropy, String> {
    if intent.kind.as_str() != ADD_TO_NEGENTROPY {
        return Err("expected add_to_negentropy intent".into());
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
    let input = AddToNegentropy {
        workspace_id,
        owner_fact_id,
        timestamp_ms,
        context_have,
    };
    if intent.key != add_to_negentropy_key(&input) {
        return Err("add_to_negentropy idempotence key does not match payload".into());
    }
    Ok(input)
}

fn add_to_negentropy_key(input: &AddToNegentropy) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:add-to-negentropy:v1:");
    hash.update(&input.workspace_id);
    hash.update(&input.owner_fact_id);
    hash.update(&input.timestamp_ms.to_be_bytes());
    for fact_id in &input.context_have {
        hash.update(fact_id);
    }
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid add_to_negentropy payload: {err}")
}

#[derive(Debug, Clone, Default)]
pub struct AddToNegentropyHandler;

impl AddToNegentropyHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for AddToNegentropyHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_add_to_negentropy(intent)?;
        let mut ids = Vec::with_capacity(1 + input.context_have.len());
        ids.push(input.owner_fact_id);
        ids.extend(input.context_have);
        Ok(ids)
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_add_to_negentropy(raw)?;
        let owner = context.require_fact(&input.owner_fact_id)?;
        context.require_non_local_fact_bytes(&input.owner_fact_id)?;
        for fact_id in &input.context_have {
            context.require_non_local_fact_bytes(fact_id)?;
        }
        shared_fact::record_negentropy_contribution(context.store()?, &input, owner)?;
        Ok(crate::core::effects::PipelineEffects::new())
    }
}
