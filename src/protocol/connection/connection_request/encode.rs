//! Membership connection-request encoding and signing transcripts.
//!
//! This file turns the typed request into canonical wire bytes and owns the
//! endpoint signing transcript: the bytes the initiator endpoint signs to
//! authorize the request, and the verifier counterpart used to check that
//! signature against the initiator's `endpoint_shared` membership signing key.
//!
//! The request layout is fixed width: tag, endpoint ids, nonce, initiator
//! endpoint_shared fact id, initiator ephemeral secret fact id, initiator
//! ephemeral public key, an endpoint signature, and two fixed listen-address
//! blocks. Address blocks reuse the bootstrap request encoding so absent and
//! present addresses occupy identical widths. There is no invite material on
//! this path: authorization is membership, proved by the endpoint signature plus
//! a shared workspace.

use crate::core::crypto::{self, Ed25519PublicKey, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::bootstrap_request::create::{
    encode_optional_addr, ADDR_BLOCK_BYTES,
};

use super::fact::ConnectionRequestFact;

pub const TYPE_CONNECTION_REQUEST: u8 = 48;

pub const FACT_BYTES: usize = 1
    + 32 // from_endpoint
    + 32 // to_endpoint
    + 32 // nonce
    + 32 // initiator_endpoint_shared_id
    + 32 // initiator_ephemeral_secret_fact_id
    + 32 // initiator_ephemeral_public_key
    + ED25519_SIGNATURE_BYTES
    + ADDR_BLOCK_BYTES
    + ADDR_BLOCK_BYTES;

const SIGNING_TRANSCRIPT_LABEL: &[u8] =
    b"topo-membership-connection-request-endpoint-signing-transcript-v1";

pub fn encode_fact(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.nonce);
    out[97..129].copy_from_slice(&fact.initiator_endpoint_shared_id);
    out[129..161].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    out[161..193].copy_from_slice(&fact.initiator_ephemeral_public_key);
    let mut cursor = 193;
    out[cursor..cursor + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.endpoint_signature);
    cursor += ED25519_SIGNATURE_BYTES;
    let addr_bytes = encode_optional_addr(fact.from_listen_addr)?;
    out[cursor..cursor + ADDR_BLOCK_BYTES].copy_from_slice(&addr_bytes);
    cursor += ADDR_BLOCK_BYTES;
    let addr_bytes = encode_optional_addr(fact.to_listen_addr)?;
    out[cursor..cursor + ADDR_BLOCK_BYTES].copy_from_slice(&addr_bytes);
    Ok(out)
}

/// Canonical bytes the initiator endpoint signs to authorize the request.
pub fn endpoint_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(SIGNING_TRANSCRIPT_LABEL);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.initiator_endpoint_shared_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
    Ok(out)
}

/// Sign `request` in place with the initiator endpoint signing key.
pub fn sign_request(
    request: &mut ConnectionRequestFact,
    endpoint: &EndpointFact,
) -> Result<(), String> {
    if endpoint.endpoint != request.from_endpoint {
        return Err("membership connection request signer is not the initiator".to_string());
    }
    request.endpoint_signature = crypto::ed25519_sign(
        &endpoint.signing_secret,
        &endpoint_signing_transcript(request)?,
    );
    Ok(())
}

/// Verify the request endpoint signature against the initiator's membership
/// signing public key (taken from its `endpoint_shared` fact).
pub fn validate_endpoint_signature(
    request: &ConnectionRequestFact,
    signing_public_key: &Ed25519PublicKey,
) -> Result<(), String> {
    if !crypto::ed25519_verify(
        signing_public_key,
        &endpoint_signing_transcript(request)?,
        &request.endpoint_signature,
    ) {
        return Err(
            "membership connection request endpoint signature is not authorized".to_string(),
        );
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
