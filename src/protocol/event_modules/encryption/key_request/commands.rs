//! Commands for signed key-request events.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::KeyRequestEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestKeys {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub requester_endpoint_shared_id: EventId,
    pub requester_private_key: Ed25519PrivateKey,
    pub responder_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestOutput {
    pub key_request_id: EventId,
    pub workspace_id: EventId,
    pub responder_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
}

pub fn request(input: RequestKeys) -> Result<CommandOutput<KeyRequestOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id(
        "requester_endpoint_shared_id",
        &input.requester_endpoint_shared_id,
    )?;
    validate_id(
        "responder_endpoint_shared_id",
        &input.responder_endpoint_shared_id,
    )?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("recipient_key_id", &input.recipient_key_id)?;

    let event = KeyRequestEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        responder_endpoint_shared_id: input.responder_endpoint_shared_id,
        removal_frontier_id: input.removal_frontier_id,
        recipient_key_id: input.recipient_key_id,
    };
    let payload = codec::encode(&event);
    let envelope = codec::sign(
        input.requester_endpoint_shared_id,
        &input.requester_private_key,
        payload,
    );
    if envelope.signer_public_key != crypto::ed25519_public_key(&input.requester_private_key) {
        return Err("key request signer public key mismatch".to_string());
    }
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = KeyRequestOutput {
        key_request_id: event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        responder_endpoint_shared_id: event.responder_endpoint_shared_id,
        removal_frontier_id: event.removal_frontier_id,
        recipient_key_id: event.recipient_key_id,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

pub(super) fn validate_event_ids(event: &KeyRequestEvent) -> Result<(), String> {
    for (name, id) in [
        ("key request workspace", &event.workspace_id),
        (
            "key request responder_endpoint_shared_id",
            &event.responder_endpoint_shared_id,
        ),
        (
            "key request removal_frontier_id",
            &event.removal_frontier_id,
        ),
        ("key request recipient_key_id", &event.recipient_key_id),
    ] {
        validate_id(name, id)?;
    }
    Ok(())
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}
