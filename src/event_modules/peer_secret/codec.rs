use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_PEER_SECRET};

pub const PEER_SECRET_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("signer_event_id"),
    FieldSpec::EventId("private_key_bytes"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSecretEvent {
    pub created_at_ms: u64,
    /// Stage 3.5 round-9 step 4 (plan.md): canonical workspace this
    /// local peer secret belongs to. Drives the new
    /// `peer_secrets(workspace_id, peer_id)` PK.
    pub workspace_id: [u8; 32],
    pub signer_event_id: [u8; 32],
    pub private_key_bytes: [u8; 32],
}

impl super::super::Describe for PeerSecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![(
            "signer_event_id",
            super::super::short_id_b64(&self.signer_event_id),
        )]
    }
}

/// Wire format (105 bytes fixed):
/// [0]       type_code = 27
/// [1..9]    created_at_ms (u64 LE)
/// [9..41]   workspace_id (32 bytes)
/// [41..73]  signer_event_id (32 bytes, dep: peer_shared)
/// [73..105] private_key_bytes (32 bytes)
pub const PEER_SECRET_WIRE_SIZE: usize = wire_size_for_fields(PEER_SECRET_FIELDS);

pub fn parse_peer_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_PEER_SECRET, PEER_SECRET_FIELDS, blob)?;

    Ok(ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        signer_event_id: values[2].as_event_id().unwrap(),
        private_key_bytes: values[3].as_event_id().unwrap(),
    }))
}

pub fn encode_peer_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerSecret(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.workspace_id),
        FieldValue::EventId(e.signer_event_id),
        FieldValue::EventId(e.private_key_bytes),
    ];

    Ok(encode_fields(
        EVENT_TYPE_PEER_SECRET,
        PEER_SECRET_FIELDS,
        &values,
    )?)
}

pub static PEER_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_SECRET,
    type_name: "peer_secret",
    projection_table: "peer_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &["signer_event_id"],
    dep_field_type_codes: &[&[16]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_peer_secret,
    encode: encode_peer_secret,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
