use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_ACCEPTED};

// ─── Layout (owned by this module) ───

pub const INVITE_ACCEPTED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("tenant_event_id"),
    FieldSpec::EventId("invite_event_id"),
    FieldSpec::EventId("workspace_id"),
];

/// InviteAccepted (type 9): type(1) + created_at(8) + tenant_event_id(32) + invite_event_id(32)
/// + workspace_id(32) = 105
pub const INVITE_ACCEPTED_WIRE_SIZE: usize = wire_size_for_fields(INVITE_ACCEPTED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub created_at_ms: u64,
    pub tenant_event_id: [u8; 32], // dep: local tenant event
    pub invite_event_id: [u8; 32], // the invite event being accepted
    pub workspace_id: [u8; 32],    // workspace being joined
}

impl super::super::Describe for InviteAcceptedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "invite_event_id",
                super::super::short_id_b64(&self.invite_event_id),
            ),
            (
                "workspace_id",
                super::super::short_id_b64(&self.workspace_id),
            ),
        ]
    }
}

/// Wire format (105 bytes fixed):
/// [0]      type_code = 9
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  tenant_event_id (32 bytes)
/// [41..73] invite_event_id (32 bytes)
/// [73..105] workspace_id (32 bytes)
pub fn parse_invite_accepted(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_INVITE_ACCEPTED, INVITE_ACCEPTED_FIELDS, blob)?;

    Ok(ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        tenant_event_id: values[1].as_event_id().unwrap(),
        invite_event_id: values[2].as_event_id().unwrap(),
        workspace_id: values[3].as_event_id().unwrap(),
    }))
}

pub fn encode_invite_accepted(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ia = match event {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(ia.created_at_ms),
        FieldValue::EventId(ia.tenant_event_id),
        FieldValue::EventId(ia.invite_event_id),
        FieldValue::EventId(ia.workspace_id),
    ];

    Ok(encode_fields(
        EVENT_TYPE_INVITE_ACCEPTED,
        INVITE_ACCEPTED_FIELDS,
        &values,
    )?)
}

pub static INVITE_ACCEPTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INVITE_ACCEPTED,
    type_name: "invite_accepted",
    projection_table: "invites_accepted",
    share_scope: ShareScope::Local,
    dep_fields: &["tenant_event_id"],
    dep_field_type_codes: &[&[super::super::EVENT_TYPE_TENANT]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_invite_accepted,
    encode: encode_invite_accepted,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
