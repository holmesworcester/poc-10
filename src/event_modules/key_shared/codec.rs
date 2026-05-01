use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SHARED};

pub const KEY_SHARED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::U8("frontier_count"),
    FieldSpec::EventId("frontier_ref_1"),
    FieldSpec::EventId("frontier_ref_2"),
    FieldSpec::EventId("frontier_ref_3"),
    FieldSpec::EventId("frontier_ref_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("delivery_target_id"),
    FieldSpec::EventId("recipient_event_id"),
    FieldSpec::EventId("unwrap_key_event_id"),
    FieldSpec::EventId("wrapped_key"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// KeyShared (type 22): type(1) + created_at(8) + workspace_id(32) + key_event_id(32)
///   + frontier_count(1) + frontier_ref_1..4(128) + frontier_hash(32)
///   + delivery_target_id(32) + recipient_event_id(32) + unwrap_key_event_id(32)
///   + wrapped_key(32) + signed_by(32) + signer_type(1) + signature(64) = 459
///
/// `workspace_id` was added in plan.md Stage 2 — chain-friendly migration.
/// The field carries the workspace this key-shared event belongs to, so
/// the projection-table key shifts from `(recorded_by, event_id)` to
/// `(workspace_id, event_id)` with no per-tenant duplication.
pub const KEY_SHARED_WIRE_SIZE: usize = wire_size_for_fields(KEY_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySharedEvent {
    pub created_at_ms: u64,
    /// Canonical workspace this key_shared belongs to (plan.md Stage 2).
    pub workspace_id: [u8; 32],
    pub key_event_id: [u8; 32],
    pub frontier_count: u8,
    pub frontier_ref_1: [u8; 32],
    pub frontier_ref_2: [u8; 32],
    pub frontier_ref_3: [u8; 32],
    pub frontier_ref_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub delivery_target_id: [u8; 32],
    pub recipient_event_id: [u8; 32],
    pub unwrap_key_event_id: [u8; 32],
    pub wrapped_key: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for KeySharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "key_event_id",
                super::super::short_id_b64(&self.key_event_id),
            ),
            (
                "frontier_hash",
                super::super::short_id_b64(&self.frontier_hash),
            ),
            (
                "wrapped_key",
                super::super::trunc_hex(&self.wrapped_key, 16),
            ),
        ]
    }
}

pub fn parse_key_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_SHARED, KEY_SHARED_FIELDS, blob)?;

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        key_event_id: values[2].as_event_id().unwrap(),
        frontier_count: values[3].as_u8().unwrap(),
        frontier_ref_1: values[4].as_event_id().unwrap(),
        frontier_ref_2: values[5].as_event_id().unwrap(),
        frontier_ref_3: values[6].as_event_id().unwrap(),
        frontier_ref_4: values[7].as_event_id().unwrap(),
        frontier_hash: values[8].as_event_id().unwrap(),
        delivery_target_id: values[9].as_event_id().unwrap(),
        recipient_event_id: values[10].as_event_id().unwrap(),
        unwrap_key_event_id: values[11].as_event_id().unwrap(),
        wrapped_key: values[12].as_event_id().unwrap(),
        signed_by: values[13].as_event_id().unwrap(),
        signer_type: values[14].as_u8().unwrap(),
        signature: {
            let bytes = values[15].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_key_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::KeyShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.workspace_id),
        FieldValue::EventId(e.key_event_id),
        FieldValue::U8(e.frontier_count),
        FieldValue::EventId(e.frontier_ref_1),
        FieldValue::EventId(e.frontier_ref_2),
        FieldValue::EventId(e.frontier_ref_3),
        FieldValue::EventId(e.frontier_ref_4),
        FieldValue::EventId(e.frontier_hash),
        FieldValue::EventId(e.delivery_target_id),
        FieldValue::EventId(e.recipient_event_id),
        FieldValue::EventId(e.unwrap_key_event_id),
        FieldValue::EventId(e.wrapped_key),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_KEY_SHARED,
        KEY_SHARED_FIELDS,
        &values,
    )?)
}

pub static KEY_SHARED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_SHARED,
    type_name: "key_shared",
    projection_table: "key_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &[
        "recipient_event_id",
        "frontier_ref_1",
        "frontier_ref_2",
        "frontier_ref_3",
        "frontier_ref_4",
        "signed_by",
    ],
    dep_field_type_codes: &[&[10, 12], &[], &[], &[], &[], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_key_shared,
    encode: encode_key_shared,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
