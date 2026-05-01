use super::super::layout::common::NAME_BYTES;
use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_USER};

pub const USER_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::Text("username", NAME_BYTES),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// User (type 14):
/// type(1) + created_at(8) + public_key(32) + workspace_id(32) + username(64)
/// + signed_by(32) + signer_type(1) + signature(64) = 234
///
/// Plan.md Stage 2: `workspace_id` was implicit (carried by `recorded_by`
/// thread-local) under the legacy chain. Phase 32 makes it an explicit wire
/// field so the projector keys writes by `(workspace_id, event_id)` without
/// reading thread-locals. The `public_key` field stays at offset 9..41 so
/// `state::projection::signer::resolve_signer_key` (which extracts the key
/// at a fixed offset across all signer types) keeps working.
pub const USER_WIRE_SIZE: usize = wire_size_for_fields(USER_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEvent {
    pub created_at_ms: u64,
    /// Workspace this user belongs to. Children/siblings carry the same
    /// `workspace_id`; projection key is `(workspace_id, event_id)`.
    pub workspace_id: [u8; 32],
    pub public_key: [u8; 32],
    pub username: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for UserEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("username", self.username.clone()),
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
        ]
    }
}

pub fn parse_user(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_USER, USER_FIELDS, blob)?;

    let signer_type = values[5].as_u8().unwrap();
    if signer_type != 2 {
        return Err(EventError::InvalidMetadata(
            "user signer_type must be 2 (user_invite_shared)",
        ));
    }

    Ok(ParsedEvent::User(UserEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        workspace_id: values[2].as_event_id().unwrap(),
        username: values[3].as_text().unwrap().to_string(),
        signed_by: values[4].as_event_id().unwrap(),
        signer_type,
        signature: {
            let bytes = values[6].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_user(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::User(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
        FieldValue::EventId(e.workspace_id),
        FieldValue::Text(e.username.clone()),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];

    Ok(encode_fields(EVENT_TYPE_USER, USER_FIELDS, &values)?)
}

pub static USER_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER,
    type_name: "user",
    projection_table: "users",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user,
    encode: encode_user,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn offsets_consistent() {
        assert_eq!(field_offset(USER_FIELDS, 6) + 64, USER_WIRE_SIZE);
    }

    #[test]
    fn parse_user_accepts_user_invite_signer_type() {
        let event = ParsedEvent::User(UserEvent {
            created_at_ms: 123,
            workspace_id: [9u8; 32],
            public_key: [1u8; 32],
            username: "alice".to_string(),
            signed_by: [2u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_user_rejects_wrong_signer_type() {
        let signer_type_offset = field_offset(USER_FIELDS, 5);
        let mut blob = vec![0u8; USER_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER;
        blob[signer_type_offset] = 1;

        let err = parse_user(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
