use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_REMOVAL};

pub const MAX_REMOVAL_FRONTIER_REFS: usize = 4;

pub const REMOVAL_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("removed_member_ref"),
    FieldSpec::U8("parent_count"),
    FieldSpec::EventId("parent_1"),
    FieldSpec::EventId("parent_2"),
    FieldSpec::EventId("parent_3"),
    FieldSpec::EventId("parent_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("removed_by"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

pub const REMOVAL_WIRE_SIZE: usize = wire_size_for_fields(REMOVAL_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalEvent {
    pub created_at_ms: u64,
    /// Round-9 final sweep: workspace_id is now a real wire field on
    /// every event that scopes to a workspace. Removes the dependence on
    /// `ctx.accepted_workspace_id` for projection key derivation.
    pub workspace_id: [u8; 32],
    pub removed_member_ref: [u8; 32],
    pub parent_count: u8,
    pub parent_1: [u8; 32],
    pub parent_2: [u8; 32],
    pub parent_3: [u8; 32],
    pub parent_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub removed_by: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for RemovalEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "removed_member_ref",
                super::super::short_id_b64(&self.removed_member_ref),
            ),
            (
                "frontier_hash",
                super::super::short_id_b64(&self.frontier_hash),
            ),
        ]
    }
}

pub fn frontier_hash_from_refs(refs: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = refs.to_vec();
    sorted.sort_unstable();
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"poc7-removal-frontier-v1");
    hasher.update([sorted.len() as u8]);
    for event_id in &sorted {
        hasher.update(event_id);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

pub fn canonicalize_frontier_refs(refs: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, String> {
    let mut sorted = refs.to_vec();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err("frontier refs must be unique".to_string());
        }
    }
    Ok(sorted)
}

pub fn validate_canonical_frontier_refs(refs: &[[u8; 32]]) -> Result<(), String> {
    let sorted = canonicalize_frontier_refs(refs)?;
    if refs != sorted.as_slice() {
        return Err("frontier refs must be sorted in canonical order".to_string());
    }
    Ok(())
}

pub fn frontier_refs_from_slots(
    count: u8,
    slots: &[[u8; 32]; MAX_REMOVAL_FRONTIER_REFS],
) -> Result<Vec<[u8; 32]>, String> {
    let count = count as usize;
    if count > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "parent_count {} exceeds max {}",
            count, MAX_REMOVAL_FRONTIER_REFS
        ));
    }
    let mut refs = Vec::with_capacity(count);
    for (idx, slot) in slots.iter().enumerate() {
        let is_zero = *slot == [0u8; 32];
        if idx < count {
            if is_zero {
                return Err(format!(
                    "parent_{} missing within declared parent_count",
                    idx + 1
                ));
            }
            refs.push(*slot);
        } else if !is_zero {
            return Err(format!(
                "parent_{} must be zero when outside declared parent_count",
                idx + 1
            ));
        }
    }
    Ok(refs)
}

pub fn parse_removal(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_REMOVAL, REMOVAL_FIELDS, blob)?;
    Ok(ParsedEvent::Removal(RemovalEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        removed_member_ref: values[2].as_event_id().unwrap(),
        parent_count: values[3].as_u8().unwrap(),
        parent_1: values[4].as_event_id().unwrap(),
        parent_2: values[5].as_event_id().unwrap(),
        parent_3: values[6].as_event_id().unwrap(),
        parent_4: values[7].as_event_id().unwrap(),
        frontier_hash: values[8].as_event_id().unwrap(),
        removed_by: values[9].as_event_id().unwrap(),
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

pub fn encode_removal(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let removal = match event {
        ParsedEvent::Removal(event) => event,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(removal.created_at_ms),
        FieldValue::EventId(removal.workspace_id),
        FieldValue::EventId(removal.removed_member_ref),
        FieldValue::U8(removal.parent_count),
        FieldValue::EventId(removal.parent_1),
        FieldValue::EventId(removal.parent_2),
        FieldValue::EventId(removal.parent_3),
        FieldValue::EventId(removal.parent_4),
        FieldValue::EventId(removal.frontier_hash),
        FieldValue::EventId(removal.removed_by),
        FieldValue::EventId(removal.signed_by),
        FieldValue::U8(removal.signer_type),
        FieldValue::FixedBytes(removal.signature.to_vec()),
    ];
    Ok(encode_fields(EVENT_TYPE_REMOVAL, REMOVAL_FIELDS, &values)?)
}

pub static REMOVAL_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_REMOVAL,
    type_name: "removal",
    projection_table: "removals",
    share_scope: ShareScope::Shared,
    dep_fields: &["parent_1", "parent_2", "parent_3", "parent_4", "signed_by"],
    dep_field_type_codes: &[&[], &[], &[], &[], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_removal,
    encode: encode_removal,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};
