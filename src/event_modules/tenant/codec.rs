use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_TENANT};

pub const TENANT_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
];

pub const TENANT_WIRE_SIZE: usize = wire_size_for_fields(TENANT_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
}

impl super::super::Describe for TenantEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
            (
                "peer_id",
                hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
                    &self.public_key,
                )),
            ),
        ]
    }
}

pub fn parse_tenant(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_TENANT, TENANT_FIELDS, blob)?;

    Ok(ParsedEvent::Tenant(TenantEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
    }))
}

pub fn encode_tenant(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Tenant(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
    ];

    Ok(encode_fields(EVENT_TYPE_TENANT, TENANT_FIELDS, &values)?)
}

pub static TENANT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_TENANT,
    type_name: "tenant",
    projection_table: "tenants",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_tenant,
    encode: encode_tenant,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
