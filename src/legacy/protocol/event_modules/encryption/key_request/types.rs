//! Key-request event types.
//!
//! A key request is a shared, signed request from the recipient endpoint that
//! owns `recipient_key_id` to one responder endpoint. Targeting exactly one
//! responder is what keeps healing from turning into key amplification: only the
//! named responder materializes wraps.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::legacy::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub responder_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyRequestEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKeyRequestRow {
    pub key: Vec<u8>,
    pub workspace_id: EventId,
    pub responder_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
    pub key_request_id: EventId,
    pub requester_endpoint_shared_id: EventId,
    pub created_at_ms: u64,
}
