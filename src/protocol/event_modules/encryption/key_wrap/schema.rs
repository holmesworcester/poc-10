//! Schema for key-wrap rows.
//!
//! `KEY_WRAPS` is keyed by the desired wrap edge:
//! `workspace_id || removal_frontier_id || recipient_key_id || target`.
//! For the frontier root the target is the root marker; for retained history
//! nodes it is the node coordinate. That makes proactive and request-driven
//! paths converge on the same local row instead of accumulating duplicate
//! wraps. `PENDING_KEY_UNWRAPS` is the projected worker queue; `PENDING_WRAP_
//! RECONCILE` lets event projection schedule proactive wrap materialization
//! without doing active cryptographic work inside a projector.

use crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{
    KeyWrapEvent, KeyWrapRow, PendingKeyUnwrapRow, PendingWrapReconcileKind,
    PendingWrapReconcileRow, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};

pub const KEY_WRAPS: TableName = TableName::new("encryption.key_wraps");
pub const KEY_SECRET_COMMITMENTS: TableName = TableName::new("encryption.key_secret_commitments");
pub const PENDING_KEY_UNWRAPS: TableName = TableName::new("encryption.pending_key_unwraps");
pub const PENDING_WRAP_RECONCILE: TableName = TableName::new("encryption.pending_wrap_reconcile");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("encryption.key_wraps.v2", KEY_WRAPS),
    Schema::durable_row_table(
        "encryption.key_secret_commitments.v1",
        KEY_SECRET_COMMITMENTS,
    ),
    Schema::durable_row_table("encryption.pending_key_unwraps.v2", PENDING_KEY_UNWRAPS),
    Schema::durable_row_table(
        "encryption.pending_wrap_reconcile.v1",
        PENDING_WRAP_RECONCILE,
    ),
];

pub fn key_wrap_row(
    key_wrap_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_public_key: EventId,
    event: &KeyWrapEvent,
) -> TableRow {
    TableRow {
        table: KEY_WRAPS,
        key: key_wrap_key_for_event(event),
        value: encode_value(
            key_wrap_id,
            signer_endpoint_shared_id,
            signer_public_key,
            event,
        ),
    }
}

pub fn key_secret_commitment_row(event: &KeyWrapEvent) -> TableRow {
    TableRow {
        table: KEY_SECRET_COMMITMENTS,
        key: key_secret_commitment_key(event.workspace_id, event.removal_frontier_id),
        value: event.wrapped_secret_id.to_vec(),
    }
}

pub fn pending_key_unwrap_row(key_wrap_id: EventId, event: &KeyWrapEvent) -> TableRow {
    TableRow {
        table: PENDING_KEY_UNWRAPS,
        key: key_wrap_key_for_event(event),
        value: key_wrap_id.to_vec(),
    }
}

pub fn pending_recipient_key_reconcile_row(
    workspace_id: EventId,
    recipient_key_id: EventId,
) -> TableRow {
    pending_wrap_reconcile_row(
        workspace_id,
        PendingWrapReconcileKind::RecipientKey,
        recipient_key_id,
    )
}

pub fn pending_frontier_reconcile_row(
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> TableRow {
    pending_wrap_reconcile_row(
        workspace_id,
        PendingWrapReconcileKind::Frontier,
        removal_frontier_id,
    )
}

pub fn pending_wrap_reconcile_row(
    workspace_id: EventId,
    kind: PendingWrapReconcileKind,
    target_id: EventId,
) -> TableRow {
    TableRow {
        table: PENDING_WRAP_RECONCILE,
        key: pending_wrap_reconcile_key(workspace_id, kind, target_id),
        value: Vec::new(),
    }
}

pub fn key_wrap_key(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
    wrapped_secret_kind: WrappedSecretKind,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_WRAP_KEY_LEN);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key.extend_from_slice(&recipient_key_id);
    key.push(wrapped_secret_kind.as_u8());
    key.extend_from_slice(&range_start.to_be_bytes());
    key.extend_from_slice(&range_width.to_be_bytes());
    key.extend_from_slice(&bit_depth.to_be_bytes());
    key.extend_from_slice(&event_id_prefix);
    key
}

pub fn key_wrap_key_for_event(event: &KeyWrapEvent) -> Vec<u8> {
    key_wrap_key(
        event.workspace_id,
        event.removal_frontier_id,
        event.recipient_key_id,
        event.wrapped_secret_kind,
        event.range_start,
        event.range_width,
        event.bit_depth,
        event.event_id_prefix,
    )
}

pub fn frontier_root_key_wrap_key(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
) -> Vec<u8> {
    key_wrap_key(
        workspace_id,
        removal_frontier_id,
        recipient_key_id,
        WrappedSecretKind::FrontierRoot,
        0,
        0,
        0,
        [0; 32],
    )
}

pub fn history_node_key_wrap_key(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
) -> Vec<u8> {
    key_wrap_key(
        workspace_id,
        removal_frontier_id,
        recipient_key_id,
        WrappedSecretKind::HistoryNode,
        range_start,
        range_width,
        bit_depth,
        event_id_prefix,
    )
}

pub fn key_secret_commitment_key(workspace_id: EventId, removal_frontier_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key
}

pub const KEY_WRAP_KEY_LEN: usize = 32 + 32 + 32 + 1 + 8 + 8 + 2 + 32;

pub fn pending_wrap_reconcile_key(
    workspace_id: EventId,
    kind: PendingWrapReconcileKind,
    target_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.extend_from_slice(&workspace_id);
    key.push(kind.as_u8());
    key.extend_from_slice(&target_id);
    key
}

pub fn decode_key_wrap_row(key: &[u8], value: &[u8]) -> Result<KeyWrapRow, String> {
    if key.len() != KEY_WRAP_KEY_LEN {
        return Err("key wrap row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let mut recipient_key_id = [0; 32];
    recipient_key_id.copy_from_slice(&key[64..96]);
    let wrapped_secret_kind = WrappedSecretKind::from_u8(key[96])?;
    let range_start = u64::from_be_bytes(
        key[97..105]
            .try_into()
            .map_err(|_| "key wrap row range start malformed".to_string())?,
    );
    let range_width = u64::from_be_bytes(
        key[105..113]
            .try_into()
            .map_err(|_| "key wrap row range width malformed".to_string())?,
    );
    let bit_depth = u16::from_be_bytes(
        key[113..115]
            .try_into()
            .map_err(|_| "key wrap row bit depth malformed".to_string())?,
    );
    let mut event_id_prefix = [0; 32];
    event_id_prefix.copy_from_slice(&key[115..147]);

    let mut reader = Reader::new(value, "key wrap row");
    let key_wrap_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let wrapped_secret_id = reader.id()?;
    let wrapped_source_secret_id = reader.id()?;
    let wrapped_tombstone_node_id = reader.id()?;
    let sender_wrap_public_key = reader.id()?;
    let nonce = reader
        .bytes(XCHACHA20_POLY1305_NONCE_BYTES)?
        .try_into()
        .map_err(|_| "key wrap row nonce length mismatch".to_string())?;
    let ciphertext = reader
        .bytes(KEY_WRAP_CIPHERTEXT_BYTES)?
        .try_into()
        .map_err(|_| "key wrap row ciphertext length mismatch".to_string())?;
    reader.finish()?;
    Ok(KeyWrapRow {
        workspace_id,
        removal_frontier_id,
        recipient_key_id,
        key_wrap_id,
        created_at_ms,
        signer_endpoint_shared_id,
        signer_public_key,
        wrapped_secret_kind,
        wrapped_secret_id,
        wrapped_source_secret_id,
        wrapped_tombstone_node_id,
        range_start,
        range_width,
        bit_depth,
        event_id_prefix,
        sender_wrap_public_key,
        nonce,
        ciphertext,
    })
}

pub fn decode_pending_key_unwrap_row(
    key: Vec<u8>,
    value: &[u8],
) -> Result<PendingKeyUnwrapRow, String> {
    if key.len() != KEY_WRAP_KEY_LEN {
        return Err("pending key unwrap row key is malformed".to_string());
    }
    if value.len() != 32 {
        return Err("pending key unwrap row value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let mut recipient_key_id = [0; 32];
    recipient_key_id.copy_from_slice(&key[64..96]);
    let mut key_wrap_id = [0; 32];
    key_wrap_id.copy_from_slice(value);
    Ok(PendingKeyUnwrapRow {
        key,
        workspace_id,
        removal_frontier_id,
        recipient_key_id,
        key_wrap_id,
    })
}

pub fn decode_pending_wrap_reconcile_row(
    key: Vec<u8>,
    value: &[u8],
) -> Result<PendingWrapReconcileRow, String> {
    if key.len() != 65 {
        return Err("pending wrap reconcile row key is malformed".to_string());
    }
    if !value.is_empty() {
        return Err("pending wrap reconcile row value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let kind = PendingWrapReconcileKind::from_u8(key[32])?;
    let mut target_id = [0; 32];
    target_id.copy_from_slice(&key[33..65]);
    Ok(PendingWrapReconcileRow {
        key,
        workspace_id,
        kind,
        target_id,
    })
}

fn encode_value(
    key_wrap_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_public_key: EventId,
    event: &KeyWrapEvent,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        32 + 8
            + 32
            + 32
            + 32
            + 32
            + 32
            + 32
            + XCHACHA20_POLY1305_NONCE_BYTES
            + KEY_WRAP_CIPHERTEXT_BYTES,
    );
    out.id(&key_wrap_id);
    out.u64(event.created_at_ms);
    out.id(&signer_endpoint_shared_id);
    out.id(&signer_public_key);
    out.id(&event.wrapped_secret_id);
    out.id(&event.wrapped_source_secret_id);
    out.id(&event.wrapped_tombstone_node_id);
    out.id(&event.sender_wrap_public_key);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event(local_key_secret_id: EventId) -> KeyWrapEvent {
        KeyWrapEvent {
            workspace_id: [1; 32],
            created_at_ms: 1,
            removal_frontier_id: [2; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: local_key_secret_id,
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            event_id_prefix: [0; 32],
            recipient_key_id: [3; 32],
            sender_wrap_public_key: [4; 32],
            nonce: [5; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [6; KEY_WRAP_CIPHERTEXT_BYTES],
        }
    }

    #[test]
    fn commitment_row_enforces_one_key_secret_per_frontier() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("store");
        store
            .insert_table_rows(vec![key_secret_commitment_row(&event([7; 32]))])
            .expect("insert first commitment");

        let err = store
            .insert_table_rows(vec![key_secret_commitment_row(&event([8; 32]))])
            .expect_err("conflicting commitment must fail");

        assert!(err.to_string().contains("conflicting row for"));
    }
}
