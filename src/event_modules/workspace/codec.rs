use crate::event_modules::layout::common::NAME_BYTES;
use crate::event_modules::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent, EVENT_TYPE_WORKSPACE};

// ─── Layout (owned by this module) ───

pub const WORKSPACE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("public_key"),
    FieldSpec::Text("name", NAME_BYTES),
];

/// Workspace (type 8):
/// type(1) + created_at(8) + workspace_id(32) + public_key(32) + name(64) = 137
///
/// `workspace_id` is the canonical identifier of the workspace this event
/// roots. By convention, callers set it to the workspace's `public_key`
/// (a 32-byte Ed25519 verifying key); the projector reads `workspace_id`
/// directly to drive its writes (plan.md Stage 2 translation rule 4 —
/// drop `recorded_by` in favor of the event's own `workspace_id`).
pub const WORKSPACE_WIRE_SIZE: usize = wire_size_for_fields(WORKSPACE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub created_at_ms: u64,
    /// Canonical workspace_id this event roots. Workspace events are
    /// roots — every other event in this workspace carries the SAME
    /// `workspace_id` (poc-9 plan.md, "drop `recorded_by` in favor of the
    /// event's own `workspace_id`"). By convention this equals
    /// `public_key`, but the projector treats them as independent fields
    /// and uses `workspace_id` for the projection-table key.
    pub workspace_id: [u8; 32],
    pub public_key: [u8; 32], // Ed25519 verifying key for the workspace
    pub name: String,         // Workspace display name (64-byte text slot)
}

impl super::super::Describe for WorkspaceEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("name", self.name.clone()),
            (
                "workspace_id",
                super::super::trunc_hex(&self.workspace_id, 16),
            ),
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
        ]
    }
}

/// Wire format (137 bytes fixed):
/// [0]        type_code = 8
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    workspace_id (32 bytes)
/// [41..73]   public_key (32 bytes)
/// [73..137]  name (64 bytes, UTF-8 zero-padded)
pub fn parse_workspace(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_WORKSPACE, WORKSPACE_FIELDS, blob)?;

    Ok(ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        public_key: values[2].as_event_id().unwrap(),
        name: values[3].as_text().unwrap().to_string(),
    }))
}

pub fn encode_workspace(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ws = match event {
        ParsedEvent::Workspace(w) => w,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(ws.created_at_ms),
        FieldValue::EventId(ws.workspace_id),
        FieldValue::EventId(ws.public_key),
        FieldValue::Text(ws.name.clone()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_WORKSPACE,
        WORKSPACE_FIELDS,
        &values,
    )?)
}

pub static WORKSPACE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_WORKSPACE,
    type_name: "workspace",
    projection_table: "workspaces",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_workspace,
    encode: encode_workspace,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;
    #[test]
    fn offsets_consistent() {
        // name field starts at offset 73 (1+8+32+32), name(64) ends at 137
        // = WORKSPACE_WIRE_SIZE.
        assert_eq!(
            field_offset(WORKSPACE_FIELDS, 3) + NAME_BYTES,
            WORKSPACE_WIRE_SIZE
        );
    }
}
