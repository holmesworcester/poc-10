use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_KEY_REQUEST};

pub const KEY_REQUEST_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("blocked_event_id"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("delivery_target_id"),
    FieldSpec::EventId("recipient_event_id"),
    FieldSpec::EventId("unwrap_key_event_id"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// KeyRequest (type 30): type(1) + created_at(8) + workspace_id(32) + blocked_event_id(32)
///   + key_event_id(32) + frontier_hash(32) + delivery_target_id(32)
///   + recipient_event_id(32) + unwrap_key_event_id(32)
///   + signed_by(32) + signer_type(1) + signature(64) = 330
///
/// `workspace_id` was added in plan.md Stage 2 — chain-friendly migration.
pub const KEY_REQUEST_WIRE_SIZE: usize = wire_size_for_fields(KEY_REQUEST_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestEvent {
    pub created_at_ms: u64,
    /// Canonical workspace this key_request belongs to (plan.md Stage 2).
    pub workspace_id: [u8; 32],
    pub blocked_event_id: [u8; 32],
    pub key_event_id: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub delivery_target_id: [u8; 32],
    pub recipient_event_id: [u8; 32],
    pub unwrap_key_event_id: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for KeyRequestEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "blocked_event_id",
                super::super::short_id_b64(&self.blocked_event_id),
            ),
            (
                "key_event_id",
                super::super::short_id_b64(&self.key_event_id),
            ),
            (
                "frontier_hash",
                super::super::short_id_b64(&self.frontier_hash),
            ),
        ]
    }
}

pub fn delivery_target_id(
    key_event_id: &[u8; 32],
    frontier_hash: &[u8; 32],
    recipient_event_id: &[u8; 32],
    unwrap_key_event_id: &[u8; 32],
) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"poc7-key-delivery-target-v1");
    hasher.update(key_event_id);
    hasher.update(frontier_hash);
    hasher.update(recipient_event_id);
    hasher.update(unwrap_key_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

pub fn deterministic_key_request_created_at_ms(
    blocked_event_id: &[u8; 32],
    key_event_id: &[u8; 32],
    frontier_hash: &[u8; 32],
    recipient_event_id: &[u8; 32],
    unwrap_key_event_id: &[u8; 32],
    signed_by: &[u8; 32],
) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-key-request-created-at-v1");
    hasher.update(blocked_event_id);
    hasher.update(key_event_id);
    hasher.update(frontier_hash);
    hasher.update(recipient_event_id);
    hasher.update(unwrap_key_event_id);
    hasher.update(signed_by);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn parse_key_request(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_REQUEST, KEY_REQUEST_FIELDS, blob)?;
    Ok(ParsedEvent::KeyRequest(KeyRequestEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        blocked_event_id: values[2].as_event_id().unwrap(),
        key_event_id: values[3].as_event_id().unwrap(),
        frontier_hash: values[4].as_event_id().unwrap(),
        delivery_target_id: values[5].as_event_id().unwrap(),
        recipient_event_id: values[6].as_event_id().unwrap(),
        unwrap_key_event_id: values[7].as_event_id().unwrap(),
        signed_by: values[8].as_event_id().unwrap(),
        signer_type: values[9].as_u8().unwrap(),
        signature: {
            let bytes = values[10].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_key_request(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let kr = match event {
        ParsedEvent::KeyRequest(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(kr.created_at_ms),
        FieldValue::EventId(kr.workspace_id),
        FieldValue::EventId(kr.blocked_event_id),
        FieldValue::EventId(kr.key_event_id),
        FieldValue::EventId(kr.frontier_hash),
        FieldValue::EventId(kr.delivery_target_id),
        FieldValue::EventId(kr.recipient_event_id),
        FieldValue::EventId(kr.unwrap_key_event_id),
        FieldValue::EventId(kr.signed_by),
        FieldValue::U8(kr.signer_type),
        FieldValue::FixedBytes(kr.signature.to_vec()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_KEY_REQUEST,
        KEY_REQUEST_FIELDS,
        &values,
    )?)
}

pub static KEY_REQUEST_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_REQUEST,
    type_name: "key_request",
    projection_table: "key_requests",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_key_request,
    encode: encode_key_request,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
