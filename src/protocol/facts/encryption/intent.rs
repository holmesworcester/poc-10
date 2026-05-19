//! Deferred encryption intent layouts.

use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};

use super::fact::{RecipientKeyId, WorkspaceId};
use crate::protocol::matchers::{WrapSourceKind, WrapSourceSelector};

pub const CREATE_KEY_WRAP: &str = "create_key_wrap";
pub const UNWRAP_KEY_WRAP: &str = "unwrap_key_wrap";
pub const PURGE_RETIRED_RECIPIENT_MATERIAL: &str = "purge_retired_recipient_material";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateKeyWrapIntent {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub source_fact_id: FactId,
    pub signer_secret_fact_id: FactId,
    pub source: WrapSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapKeyWrapIntent {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub key_wrap_id: FactId,
    pub local_recipient_key_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeRetiredRecipientMaterialIntent {
    pub workspace_id: WorkspaceId,
    pub recipient_key_id: RecipientKeyId,
    pub local_recipient_key_id: FactId,
}

pub fn create_key_wrap_intent(
    recipient_key_id: RecipientKeyId,
    source_fact_id: FactId,
    signer_secret_fact_id: FactId,
    source: WrapSourceSelector,
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
        IntentExecution::Deferred,
        create_key_wrap_key(&input),
        encode_create_key_wrap_payload(&input),
    )
}

pub fn decode_create_key_wrap_intent(intent: &Intent) -> Result<CreateKeyWrapIntent, String> {
    if intent.kind.as_str() != CREATE_KEY_WRAP || intent.execution != IntentExecution::Deferred {
        return Err("expected create_key_wrap deferred intent".to_string());
    }
    let input = decode_create_key_wrap_payload(&intent.payload)?;
    if create_key_wrap_key(&input) != intent.key {
        return Err("create_key_wrap intent key does not match payload".to_string());
    }
    Ok(input)
}

pub fn unwrap_key_wrap_intent(input: UnwrapKeyWrapIntent) -> Intent {
    Intent::new(
        IntentKind::new(UNWRAP_KEY_WRAP).expect("valid unwrap_key_wrap intent kind"),
        IntentExecution::Deferred,
        unwrap_key(&input),
        encode_unwrap_payload(&input),
    )
}

pub fn decode_unwrap_key_wrap_intent(intent: &Intent) -> Result<UnwrapKeyWrapIntent, String> {
    if intent.kind.as_str() != UNWRAP_KEY_WRAP || intent.execution != IntentExecution::Deferred {
        return Err("expected unwrap_key_wrap deferred intent".to_string());
    }
    let input = decode_unwrap_payload(&intent.payload)?;
    if unwrap_key(&input) != intent.key {
        return Err("unwrap_key_wrap intent key does not match payload".to_string());
    }
    Ok(input)
}

pub fn purge_retired_recipient_material_intent(
    input: PurgeRetiredRecipientMaterialIntent,
) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_RETIRED_RECIPIENT_MATERIAL)
            .expect("valid purge_retired_recipient_material intent kind"),
        IntentExecution::Deferred,
        retired_recipient_key(
            input.workspace_id,
            input.recipient_key_id,
            input.local_recipient_key_id,
        ),
        encode_retired_recipient_payload(input.recipient_key_id, input.local_recipient_key_id),
    )
}

pub fn decode_purge_retired_recipient_material_intent(
    intent: &Intent,
) -> Result<PurgeRetiredRecipientMaterialIntent, String> {
    if intent.kind.as_str() != PURGE_RETIRED_RECIPIENT_MATERIAL
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected purge_retired_recipient_material deferred intent".to_string());
    }
    let workspace_id = decode_workspace_from_retired_key(&intent.key)?;
    let recipient_key_id = decode_recipient_from_retired_key(&intent.key)?;
    let local_recipient_key_id = decode_local_recipient_from_retired_key(&intent.key)?;
    if decode_retired_recipient_payload(&intent.payload)?
        != (recipient_key_id, local_recipient_key_id)
    {
        return Err("purge_retired_recipient_material key does not match payload".to_string());
    }
    Ok(PurgeRetiredRecipientMaterialIntent {
        workspace_id,
        recipient_key_id,
        local_recipient_key_id,
    })
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

fn unwrap_key(input: &UnwrapKeyWrapIntent) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 * 5);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.frontier_id);
    key.extend_from_slice(&input.recipient_key_id);
    key.extend_from_slice(&input.key_wrap_id);
    key.extend_from_slice(&input.local_recipient_key_id);
    key
}

fn encode_create_key_wrap_payload(input: &CreateKeyWrapIntent) -> Vec<u8> {
    let (source_kind, range_start, range_width, bit_depth, fact_id_prefix) = match input.source {
        WrapSourceKind::FrontierRoot => (1, 0, 0, 0, [0; 32]),
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => (2, range_start, range_width, bit_depth, fact_id_prefix),
    };
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("create_key_wrap_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            ("frontier_id", FieldValue::Bytes(input.frontier_id.to_vec())),
            (
                "recipient_key_id",
                FieldValue::Bytes(input.recipient_key_id.to_vec()),
            ),
            (
                "source_fact_id",
                FieldValue::Bytes(input.source_fact_id.to_vec()),
            ),
            (
                "signer_secret_fact_id",
                FieldValue::Bytes(input.signer_secret_fact_id.to_vec()),
            ),
            ("source_kind", FieldValue::U8(source_kind)),
            ("source_range_start", FieldValue::U64(range_start)),
            ("source_range_width", FieldValue::U64(range_width)),
            ("source_bit_depth", FieldValue::U16(bit_depth)),
            (
                "source_fact_id_prefix",
                FieldValue::Bytes(fact_id_prefix.to_vec()),
            ),
        ],
    )
    .expect("create_key_wrap payload matches schema")
}

fn decode_create_key_wrap_payload(payload: &[u8]) -> Result<CreateKeyWrapIntent, String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("create_key_wrap_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("create_key_wrap payload version unsupported".to_string());
    }
    let source = match payload.u8("source_kind")? {
        1 => {
            if payload.u64("source_range_start")? != 0
                || payload.u64("source_range_width")? != 0
                || payload.u16("source_bit_depth")? != 0
                || payload
                    .bytes("source_fact_id_prefix")?
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err("invalid create_key_wrap root padding".to_string());
            }
            WrapSourceKind::FrontierRoot
        }
        2 => {
            let range_start = payload.u64("source_range_start")?;
            let range_width = payload.u64("source_range_width")?;
            let bit_depth = payload.u16("source_bit_depth")?;
            if bit_depth > 256 || range_width == 0 || !range_width.is_power_of_two() {
                return Err("invalid create_key_wrap history range".to_string());
            }
            WrapSourceKind::HistoryNode {
                range_start,
                range_width,
                bit_depth,
                fact_id_prefix: payload.bytes_array("source_fact_id_prefix")?,
            }
        }
        _ => return Err("invalid create_key_wrap source kind".to_string()),
    };
    Ok(CreateKeyWrapIntent {
        workspace_id: payload.bytes_array("workspace_id")?,
        frontier_id: payload.bytes_array("frontier_id")?,
        recipient_key_id: payload.bytes_array("recipient_key_id")?,
        source_fact_id: payload.bytes_array("source_fact_id")?,
        signer_secret_fact_id: payload.bytes_array("signer_secret_fact_id")?,
        source,
    })
}

fn encode_unwrap_payload(input: &UnwrapKeyWrapIntent) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("unwrap_key_wrap_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            ("frontier_id", FieldValue::Bytes(input.frontier_id.to_vec())),
            (
                "recipient_key_id",
                FieldValue::Bytes(input.recipient_key_id.to_vec()),
            ),
            ("key_wrap_id", FieldValue::Bytes(input.key_wrap_id.to_vec())),
            (
                "local_recipient_key_id",
                FieldValue::Bytes(input.local_recipient_key_id.to_vec()),
            ),
        ],
    )
    .expect("unwrap_key_wrap payload matches schema")
}

fn decode_unwrap_payload(payload: &[u8]) -> Result<UnwrapKeyWrapIntent, String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("unwrap_key_wrap_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("unwrap_key_wrap payload version unsupported".to_string());
    }
    Ok(UnwrapKeyWrapIntent {
        workspace_id: payload.bytes_array("workspace_id")?,
        frontier_id: payload.bytes_array("frontier_id")?,
        recipient_key_id: payload.bytes_array("recipient_key_id")?,
        key_wrap_id: payload.bytes_array("key_wrap_id")?,
        local_recipient_key_id: payload.bytes_array("local_recipient_key_id")?,
    })
}

fn retired_recipient_key(
    workspace_id: WorkspaceId,
    recipient_key_id: RecipientKeyId,
    local_recipient_key_id: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&recipient_key_id);
    key.extend_from_slice(&local_recipient_key_id);
    key
}

fn decode_workspace_from_retired_key(key: &[u8]) -> Result<WorkspaceId, String> {
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    Ok(key[0..32].try_into().unwrap())
}

fn decode_recipient_from_retired_key(key: &[u8]) -> Result<RecipientKeyId, String> {
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    Ok(key[32..64].try_into().unwrap())
}

fn decode_local_recipient_from_retired_key(key: &[u8]) -> Result<FactId, String> {
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    Ok(key[64..96].try_into().unwrap())
}

fn encode_retired_recipient_payload(
    recipient_key_id: RecipientKeyId,
    local_recipient_key_id: FactId,
) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("purge_retired_recipient_material_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "recipient_key_id",
                FieldValue::Bytes(recipient_key_id.to_vec()),
            ),
            (
                "local_recipient_key_id",
                FieldValue::Bytes(local_recipient_key_id.to_vec()),
            ),
        ],
    )
    .expect("purge_retired_recipient_material payload matches schema")
}

fn decode_retired_recipient_payload(payload: &[u8]) -> Result<(RecipientKeyId, FactId), String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("purge_retired_recipient_material_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("purge_retired_recipient_material payload version unsupported".to_string());
    }
    Ok((
        payload.bytes_array("recipient_key_id")?,
        payload.bytes_array("local_recipient_key_id")?,
    ))
}
