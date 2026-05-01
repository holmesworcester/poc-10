use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_KEY_ROTATION};

pub const KEY_ROTATION_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::U8("frontier_count"),
    FieldSpec::EventId("frontier_ref_1"),
    FieldSpec::EventId("frontier_ref_2"),
    FieldSpec::EventId("frontier_ref_3"),
    FieldSpec::EventId("frontier_ref_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("rotated_by"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// KeyRotation: type(1) + created_at(8) + workspace_id(32) + key_event_id(32)
///   + frontier_count(1) + frontier_refs(128) + frontier_hash(32)
///   + rotated_by(32) + signed_by(32) + signer_type(1) + signature(64) = 363
///
/// `workspace_id` was added in plan.md Stage 2 — chain-friendly migration.
pub const KEY_ROTATION_WIRE_SIZE: usize = wire_size_for_fields(KEY_ROTATION_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationEvent {
    pub created_at_ms: u64,
    /// Canonical workspace this key_rotation belongs to (plan.md Stage 2).
    pub workspace_id: [u8; 32],
    pub key_event_id: [u8; 32],
    pub frontier_count: u8,
    pub frontier_ref_1: [u8; 32],
    pub frontier_ref_2: [u8; 32],
    pub frontier_ref_3: [u8; 32],
    pub frontier_ref_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub rotated_by: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for KeyRotationEvent {
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
        ]
    }
}

pub fn parse_key_rotation(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_ROTATION, KEY_ROTATION_FIELDS, blob)?;
    Ok(ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        key_event_id: values[2].as_event_id().unwrap(),
        frontier_count: values[3].as_u8().unwrap(),
        frontier_ref_1: values[4].as_event_id().unwrap(),
        frontier_ref_2: values[5].as_event_id().unwrap(),
        frontier_ref_3: values[6].as_event_id().unwrap(),
        frontier_ref_4: values[7].as_event_id().unwrap(),
        frontier_hash: values[8].as_event_id().unwrap(),
        rotated_by: values[9].as_event_id().unwrap(),
        signed_by: values[10].as_event_id().unwrap(),
        signer_type: values[11].as_u8().unwrap(),
        signature: {
            let bytes = values[12].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_key_rotation(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rotation = match event {
        ParsedEvent::KeyRotation(event) => event,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(rotation.created_at_ms),
        FieldValue::EventId(rotation.workspace_id),
        FieldValue::EventId(rotation.key_event_id),
        FieldValue::U8(rotation.frontier_count),
        FieldValue::EventId(rotation.frontier_ref_1),
        FieldValue::EventId(rotation.frontier_ref_2),
        FieldValue::EventId(rotation.frontier_ref_3),
        FieldValue::EventId(rotation.frontier_ref_4),
        FieldValue::EventId(rotation.frontier_hash),
        FieldValue::EventId(rotation.rotated_by),
        FieldValue::EventId(rotation.signed_by),
        FieldValue::U8(rotation.signer_type),
        FieldValue::FixedBytes(rotation.signature.to_vec()),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_ROTATION,
        KEY_ROTATION_FIELDS,
        &values,
    )?)
}

pub static KEY_ROTATION_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_ROTATION,
    type_name: "key_rotation",
    projection_table: "key_rotations",
    share_scope: ShareScope::Shared,
    dep_fields: &[
        "frontier_ref_1",
        "frontier_ref_2",
        "frontier_ref_3",
        "frontier_ref_4",
        "signed_by",
    ],
    dep_field_type_codes: &[&[], &[], &[], &[], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_key_rotation,
    encode: encode_key_rotation,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
