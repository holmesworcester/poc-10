//! Codec for signed shared content events.
//!
//! The inner content payload is intentionally small in meaning and large in
//! bytes. Shared admission uses the signed envelope; raw content bytes are only
//! an inner payload and are not accepted by the protocol registry.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{ContentEvent, SignedContentEnvelope};

pub const TYPE_CONTENT: u8 = 1;
pub const TYPE_SIGNED_CONTENT: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentMetadata {
    workspace_id: EventId,
    timestamp: u64,
    payload_len: usize,
}

pub fn encode(event: &ContentEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 8 + 4 + event.payload.len());
    out.u8(TYPE_CONTENT);
    out.id(&event.workspace_id);
    out.u64(event.timestamp);
    out.sized_bytes(&event.payload);
    out.finish()
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedContentEnvelope {
    let mut envelope = SignedContentEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedContentEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedContentEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed content envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_CONTENT {
        return Err("expected signed content envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedContentEnvelope {
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
        return Err("signed content signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedContentEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<ContentEvent, String> {
    let mut reader = Reader::new(bytes, "content event");
    let tag = reader.u8()?;
    if tag != TYPE_CONTENT {
        return Err("unknown event type".to_string());
    }
    let workspace_id = reader.id()?;
    let timestamp = reader.u64()?;
    let payload = reader.sized_bytes()?;
    reader.finish()?;
    Ok(ContentEvent {
        workspace_id,
        timestamp,
        payload,
    })
}

pub fn validate(bytes: &[u8]) -> Result<(), String> {
    metadata(bytes).map(|_| ())
}

fn metadata(bytes: &[u8]) -> Result<ContentMetadata, String> {
    // Metadata parsing validates the full record but avoids allocating the
    // payload, which is useful when building the common event header.
    let mut reader = Reader::new(bytes, "content event");
    let tag = reader.u8()?;
    if tag != TYPE_CONTENT {
        return Err("unknown event type".to_string());
    }
    let workspace_id = reader.id()?;
    let timestamp = reader.u64()?;
    let payload = reader.sized_slice()?;
    let len = payload.len();
    reader.finish()?;

    Ok(ContentMetadata {
        workspace_id,
        timestamp,
        payload_len: len,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let metadata = metadata(&bytes)?;
    Ok(EventRecord {
        timestamp: metadata.timestamp,
        body_len: metadata.payload_len,
        canonical_bytes: bytes,
        dependencies: vec![metadata.workspace_id],
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
        receive: None,
    })
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(2);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    Ok(EventRecord {
        timestamp: metadata.timestamp,
        body_len: metadata.payload_len,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
        receive: None,
    })
}

fn validate_signed_payload(event: &SignedContentEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed content payload is empty".to_string());
    };
    if actual_type != TYPE_CONTENT {
        return Err("signed content payload is not content".to_string());
    }
    validate(&event.payload)
}

fn write_signing_fields(out: &mut Writer, event: &SignedContentEnvelope) {
    out.u8(TYPE_SIGNED_CONTENT);
    out.id(&event.signer_endpoint_shared_id);
    out.id(&event.signer_public_key);
    out.sized_bytes(&event.payload);
}

fn signing_len(payload_len: usize) -> usize {
    1 + 32 + 32 + 4 + payload_len
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed content signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}
