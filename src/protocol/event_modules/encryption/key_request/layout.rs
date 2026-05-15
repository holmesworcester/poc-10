//! Codec for signed key-request events.
//!
//! The wire shape is fixed-width and shared-scope. Decoding verifies the
//! signed envelope and exposes deterministic dependencies on requester,
//! workspace, responder, removal frontier, and recipient key. The layout owns
//! canonical bytes only; it does not validate endpoint authority or recipient
//! ownership because those invariants belong to projection.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{KeyRequestEvent, SignedKeyRequestEnvelope};

pub const TYPE_KEY_REQUEST: u8 = 28;
pub const TYPE_SIGNED_KEY_REQUEST: u8 = 29;
pub const KEY_REQUEST_WIRE_SIZE: usize = 1 + 32 + 8 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyRequestMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    responder_endpoint_shared_id: EventId,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
}

pub fn encode(event: &KeyRequestEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(KEY_REQUEST_WIRE_SIZE);
    out.u8(TYPE_KEY_REQUEST);
    out.id(&event.workspace_id);
    out.u64(event.created_at_ms);
    out.id(&event.responder_endpoint_shared_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.recipient_key_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<KeyRequestEvent, String> {
    let mut reader = Reader::new(bytes, "key request event");
    let tag = reader.u8()?;
    if tag != TYPE_KEY_REQUEST {
        return Err("expected key request event".to_string());
    }
    let event = KeyRequestEvent {
        workspace_id: reader.id()?,
        created_at_ms: reader.u64()?,
        responder_endpoint_shared_id: reader.id()?,
        removal_frontier_id: reader.id()?,
        recipient_key_id: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedKeyRequestEnvelope {
    let mut envelope = SignedKeyRequestEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedKeyRequestEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedKeyRequestEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed key request envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_KEY_REQUEST {
        return Err("expected signed key request envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = signature_bytes
        .try_into()
        .map_err(|_| "signed key request signature length mismatch".to_string())?;
    let event = SignedKeyRequestEnvelope {
        signer_endpoint_shared_id,
        signer_public_key,
        payload,
        signature,
    };
    validate_signed_payload(&event)?;
    if !crypto::ed25519_verify(
        &event.signer_public_key,
        &signing_bytes(&event),
        &event.signature,
    ) {
        return Err("signed key request signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedKeyRequestEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(5);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.responder_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.removal_frontier_id);
    push_unique(&mut dependencies, metadata.recipient_key_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: KEY_REQUEST_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<KeyRequestMetadata, String> {
    let event = decode(bytes)?;
    Ok(KeyRequestMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        responder_endpoint_shared_id: event.responder_endpoint_shared_id,
        removal_frontier_id: event.removal_frontier_id,
        recipient_key_id: event.recipient_key_id,
    })
}

fn validate_signed_payload(event: &SignedKeyRequestEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed key request payload is empty".to_string());
    };
    if actual_type != TYPE_KEY_REQUEST {
        return Err("signed key request payload is not a key request event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn write_signing_fields(out: &mut Writer, event: &SignedKeyRequestEnvelope) {
    out.u8(TYPE_SIGNED_KEY_REQUEST);
    out.id(&event.signer_endpoint_shared_id);
    out.id(&event.signer_public_key);
    out.sized_bytes(&event.payload);
}

fn signing_len(payload_len: usize) -> usize {
    1 + 32 + 32 + 4 + payload_len
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}
