use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_SECRET};

pub const INVITE_SECRET_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("invite_event_id"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("private_key_bytes"),
];

/// InviteSecret (type 28): type(1) + created_at(8) + invite_event_id(32)
/// + workspace_id(32) + private_key_bytes(32) = 105
///
/// `workspace_id` was added in plan.md Stage 2 — chain-friendly migration.
/// The field carries the workspace this invite-secret is rooted in, so
/// the projection-table key can shift from `(recorded_by, event_id)` to
/// `(workspace_id, event_id)` without per-tenant duplication.
pub const INVITE_SECRET_WIRE_SIZE: usize = wire_size_for_fields(INVITE_SECRET_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteSecretEvent {
    pub created_at_ms: u64,
    pub invite_event_id: [u8; 32],
    /// Canonical workspace this invite-secret belongs to.
    /// (plan.md Stage 2 — drop `recorded_by` in favor of the event's
    /// own `workspace_id`).
    pub workspace_id: [u8; 32],
    pub private_key_bytes: [u8; 32],
}

impl super::super::Describe for InviteSecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "invite_event_id",
                super::super::short_id_b64(&self.invite_event_id),
            ),
            (
                "private_key",
                super::super::trunc_hex(&self.private_key_bytes, 16),
            ),
        ]
    }
}

pub fn parse_invite_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_INVITE_SECRET, INVITE_SECRET_FIELDS, blob)?;

    Ok(ParsedEvent::InviteSecret(InviteSecretEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        invite_event_id: values[1].as_event_id().unwrap(),
        workspace_id: values[2].as_event_id().unwrap(),
        private_key_bytes: values[3].as_event_id().unwrap(),
    }))
}

pub fn encode_invite_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::InviteSecret(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.invite_event_id),
        FieldValue::EventId(e.workspace_id),
        FieldValue::EventId(e.private_key_bytes),
    ];

    Ok(encode_fields(
        EVENT_TYPE_INVITE_SECRET,
        INVITE_SECRET_FIELDS,
        &values,
    )?)
}

pub fn deterministic_invite_secret_created_at_ms(
    invite_event_id: &[u8; 32],
    private_key_bytes: &[u8; 32],
) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-invite-privkey-created-at-v1");
    hasher.update(invite_event_id);
    hasher.update(private_key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_invite_secret_event(
    invite_event_id: [u8; 32],
    workspace_id: [u8; 32],
    private_key_bytes: [u8; 32],
) -> ParsedEvent {
    ParsedEvent::InviteSecret(InviteSecretEvent {
        created_at_ms: deterministic_invite_secret_created_at_ms(
            &invite_event_id,
            &private_key_bytes,
        ),
        invite_event_id,
        workspace_id,
        private_key_bytes,
    })
}

pub fn deterministic_invite_secret_event_id(
    invite_event_id: &[u8; 32],
    workspace_id: &[u8; 32],
    private_key_bytes: &[u8; 32],
) -> [u8; 32] {
    let event = deterministic_invite_secret_event(
        *invite_event_id,
        *workspace_id,
        *private_key_bytes,
    );
    let blob = super::super::encode_event(&event)
        .expect("deterministic invite_secret encoding should succeed");
    crate::crypto::hash_event(&blob)
}

pub static INVITE_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INVITE_SECRET,
    type_name: "invite_secret",
    projection_table: "invite_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_invite_secret,
    encode: encode_invite_secret,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
