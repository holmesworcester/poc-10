use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SECRET};
use crate::crypto::EventId;

// ─── Layout (owned by this module) ───

pub const KEY_SECRET_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("key_bytes"),
];

/// Secret (type 6): type(1) + created_at(8) + workspace_id(32) + key_bytes(32) = 73
///
/// `workspace_id` was added in plan.md Stage 2 — chain-friendly migration.
/// The field carries the workspace this key-secret is rooted in, so the
/// projection-table key shifts from `(recorded_by, event_id)` to
/// `(workspace_id, event_id)` with no per-tenant duplication.
pub const KEY_SECRET_WIRE_SIZE: usize = wire_size_for_fields(KEY_SECRET_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySecretEvent {
    pub created_at_ms: u64,
    /// Canonical workspace this key-secret belongs to.
    /// (plan.md Stage 2 — drop `recorded_by` in favor of the event's
    /// own `workspace_id`).
    pub workspace_id: [u8; 32],
    pub key_bytes: [u8; 32], // AES-256 symmetric key
}

impl super::super::Describe for KeySecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("key_bytes", super::super::trunc_hex(&self.key_bytes, 16))]
    }
}

/// Wire format (73 bytes fixed):
/// [0]      type_code = 6
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  workspace_id (32 bytes)
/// [41..73] key_bytes (32 bytes)
pub fn parse_key_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_SECRET, KEY_SECRET_FIELDS, blob)?;

    Ok(ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        key_bytes: values[2].as_event_id().unwrap(),
    }))
}

pub fn encode_key_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let sk = match event {
        ParsedEvent::KeySecret(s) => s,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(sk.created_at_ms),
        FieldValue::EventId(sk.workspace_id),
        FieldValue::EventId(sk.key_bytes),
    ];

    Ok(encode_fields(
        EVENT_TYPE_KEY_SECRET,
        KEY_SECRET_FIELDS,
        &values,
    )?)
}

/// Deterministic timestamp derivation for key materialized Secret events.
pub fn deterministic_key_secret_created_at_ms(key_bytes: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_key_secret_event(
    workspace_id: [u8; 32],
    key_bytes: [u8; 32],
) -> ParsedEvent {
    ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: deterministic_key_secret_created_at_ms(&key_bytes),
        workspace_id,
        key_bytes,
    })
}

pub fn deterministic_key_secret_event_id(
    workspace_id: &[u8; 32],
    key_bytes: &[u8; 32],
) -> EventId {
    let event = deterministic_key_secret_event(*workspace_id, *key_bytes);
    let blob = super::super::encode_event(&event)
        .expect("deterministic key_secret encoding should succeed");
    crate::crypto::hash_event(&blob)
}

pub static KEY_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_SECRET,
    type_name: "key_secret",
    projection_table: "key_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_key_secret,
    encode: encode_key_secret,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
