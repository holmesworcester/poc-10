//! Membership connection-request construction helpers.
//!
//! Commands use this module to sign the canonical request transcript with the
//! initiator endpoint signing key. Projectors and receive paths use the same
//! transcript to verify that signature against the initiator's `endpoint_shared`
//! signing public key. There is no invite material on this path: authorization
//! is membership, proved by the endpoint signature plus a shared workspace.
//!
//! Keep request-specific crypto transcripts here. `layout.rs` owns stable byte
//! order; `project.rs` owns admission and membership proofs.

use crate::core::crypto::{self, Ed25519PublicKey};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::bootstrap_request::create::encode_optional_addr;

use super::fact::ConnectionRequestFact;

const SIGNING_TRANSCRIPT_LABEL: &[u8] =
    b"topo-membership-connection-request-endpoint-signing-transcript-v1";

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
    request.endpoint_signature =
        crypto::ed25519_sign(&endpoint.signing_secret, &endpoint_signing_transcript(request)?);
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
        return Err("membership connection request endpoint signature is not authorized".to_string());
    }
    Ok(())
}
