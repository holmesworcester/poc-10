//! Projection rows for pending key requests.
//!
//! This table is a durable worker queue keyed by workspace, responder,
//! removal frontier, recipient key, and request event id. The value records
//! the requester endpoint and timestamp needed by the worker. Schema helpers
//! own byte layout only; they do not decide whether a request is authorized or
//! whether a wrap can be produced.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{KeyRequestEvent, PendingKeyRequestRow};

pub const PENDING_KEY_REQUESTS: TableName = TableName::new("encryption.pending_key_requests");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.pending_key_requests.v1",
    PENDING_KEY_REQUESTS,
)];

pub fn pending_key_request_row(
    key_request_id: EventId,
    requester_endpoint_shared_id: EventId,
    event: &KeyRequestEvent,
) -> TableRow {
    TableRow {
        table: PENDING_KEY_REQUESTS,
        key: pending_key_request_key(
            event.workspace_id,
            event.responder_endpoint_shared_id,
            event.removal_frontier_id,
            event.recipient_key_id,
            key_request_id,
        ),
        value: encode_value(requester_endpoint_shared_id, event.created_at_ms),
    }
}

pub fn pending_key_request_key(
    workspace_id: EventId,
    responder_endpoint_shared_id: EventId,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
    key_request_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(160);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&responder_endpoint_shared_id);
    key.extend_from_slice(&removal_frontier_id);
    key.extend_from_slice(&recipient_key_id);
    key.extend_from_slice(&key_request_id);
    key
}

pub fn decode_pending_key_request_row(
    key: Vec<u8>,
    value: &[u8],
) -> Result<PendingKeyRequestRow, String> {
    if key.len() != 160 {
        return Err("pending key request row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut responder_endpoint_shared_id = [0; 32];
    responder_endpoint_shared_id.copy_from_slice(&key[32..64]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[64..96]);
    let mut recipient_key_id = [0; 32];
    recipient_key_id.copy_from_slice(&key[96..128]);
    let mut key_request_id = [0; 32];
    key_request_id.copy_from_slice(&key[128..160]);

    let mut reader = Reader::new(value, "pending key request row");
    let requester_endpoint_shared_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    reader.finish()?;
    Ok(PendingKeyRequestRow {
        key,
        workspace_id,
        responder_endpoint_shared_id,
        removal_frontier_id,
        recipient_key_id,
        key_request_id,
        requester_endpoint_shared_id,
        created_at_ms,
    })
}

fn encode_value(requester_endpoint_shared_id: EventId, created_at_ms: u64) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 8);
    out.id(&requester_endpoint_shared_id);
    out.u64(created_at_ms);
    out.finish()
}
