//! Deterministic target key-wrap creation intent and handler.
//!
//! The projector decides that a recipient, source secret, and signer capability
//! may meet; this handler loads those declared facts and asks the key-wrap
//! module to build the signed wrap. The intent payload, idempotence key, and
//! constructor live here so the handler is self-contained.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind,
};

use crate::protocol::auth::key_wrap::create;
use crate::protocol::auth::key_wrap::project::{WrapSourceDescriptor, WrapSourceKind};

type FactId = HandlerFactId;

pub const CREATE_KEY_WRAP: &str = "create_key_wrap";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateKeyWrapIntent {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub recipient_key_id: FactId,
    pub source_fact_id: FactId,
    pub signer_secret_fact_id: FactId,
    pub source: WrapSourceKind,
}

pub fn create_key_wrap_intent(
    recipient_key_id: FactId,
    source_fact_id: FactId,
    signer_secret_fact_id: FactId,
    source: WrapSourceDescriptor,
) -> Intent {
    let input = CreateKeyWrapIntent {
        workspace_id: source.workspace_id,
        frontier_id: source.frontier_id,
        recipient_key_id,
        source_fact_id,
        signer_secret_fact_id,
        source: source.kind,
    };
    Intent::new(
        IntentKind::new(CREATE_KEY_WRAP).expect("valid create_key_wrap intent kind"),
        create_key_wrap_key(&input),
        encode_create_key_wrap_payload(&input),
    )
}

pub fn decode_create_key_wrap_intent(intent: &Intent) -> Result<CreateKeyWrapIntent, String> {
    if intent.kind.as_str() != CREATE_KEY_WRAP {
        return Err("expected create_key_wrap deferred intent".to_string());
    }
    let input = decode_create_key_wrap_payload(&intent.payload)?;
    if create_key_wrap_key(&input) != intent.key {
        return Err("create_key_wrap intent key does not match payload".to_string());
    }
    Ok(input)
}

fn create_key_wrap_key(input: &CreateKeyWrapIntent) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 32 + 32 + 1 + 8 + 8 + 2 + 32);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.frontier_id);
    key.extend_from_slice(&input.recipient_key_id);
    match input.source {
        WrapSourceKind::FrontierRoot => {
            key.push(1);
            key.extend_from_slice(&[0; 49]);
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            key.push(2);
            key.extend_from_slice(&range_start.to_be_bytes());
            key.extend_from_slice(&range_width.to_be_bytes());
            key.extend_from_slice(&bit_depth.to_be_bytes());
            key.extend_from_slice(&fact_id_prefix);
        }
    }
    key
}

fn encode_create_key_wrap_payload(input: &CreateKeyWrapIntent) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 2 + 32);
    out.push(1);
    out.extend_from_slice(&input.workspace_id);
    out.extend_from_slice(&input.frontier_id);
    out.extend_from_slice(&input.recipient_key_id);
    out.extend_from_slice(&input.source_fact_id);
    out.extend_from_slice(&input.signer_secret_fact_id);
    match input.source {
        WrapSourceKind::FrontierRoot => {
            out.push(1);
            out.extend_from_slice(&[0; 50]);
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            out.push(2);
            out.extend_from_slice(&range_start.to_be_bytes());
            out.extend_from_slice(&range_width.to_be_bytes());
            out.extend_from_slice(&bit_depth.to_be_bytes());
            out.extend_from_slice(&fact_id_prefix);
        }
    }
    out
}

fn decode_create_key_wrap_payload(payload: &[u8]) -> Result<CreateKeyWrapIntent, String> {
    if payload.len() != 212 || payload[0] != 1 {
        return Err("invalid create_key_wrap payload".to_string());
    }
    let workspace_id = payload[1..33].try_into().unwrap();
    let frontier_id = payload[33..65].try_into().unwrap();
    let recipient_key_id = payload[65..97].try_into().unwrap();
    let source_fact_id = payload[97..129].try_into().unwrap();
    let signer_secret_fact_id = payload[129..161].try_into().unwrap();
    let source = match payload[161] {
        1 => {
            if payload[162..212].iter().any(|byte| *byte != 0) {
                return Err("invalid create_key_wrap root padding".to_string());
            }
            WrapSourceKind::FrontierRoot
        }
        2 => {
            let range_start = u64::from_be_bytes(payload[162..170].try_into().unwrap());
            let range_width = u64::from_be_bytes(payload[170..178].try_into().unwrap());
            let bit_depth = u16::from_be_bytes(payload[178..180].try_into().unwrap());
            if bit_depth > 256 || range_width == 0 || !range_width.is_power_of_two() {
                return Err("invalid create_key_wrap history range".to_string());
            }
            WrapSourceKind::HistoryNode {
                range_start,
                range_width,
                bit_depth,
                fact_id_prefix: payload[180..212].try_into().unwrap(),
            }
        }
        _ => return Err("invalid create_key_wrap source kind".to_string()),
    };
    Ok(CreateKeyWrapIntent {
        workspace_id,
        frontier_id,
        recipient_key_id,
        source_fact_id,
        signer_secret_fact_id,
        source,
    })
}

#[derive(Debug, Clone, Default)]
pub struct CreateKeyWrapHandler;

impl CreateKeyWrapHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateKeyWrapHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_create_key_wrap_intent(raw_intent)?;
        Ok(vec![
            input.recipient_key_id,
            input.source_fact_id,
            input.signer_secret_fact_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_create_key_wrap_intent(intent)?;
        let recipient = context.require_fact(&input.recipient_key_id)?;
        let source = context.require_fact(&input.source_fact_id)?;
        let signer_secret = context.require_fact(&input.signer_secret_fact_id)?;
        let wrap = create::create_signed_key_wrap_fact(&input, recipient, source, signer_secret)?;
        Ok(PipelineEffects::new().fact(wrap))
    }
}
