//! Authority helpers shared by raw and signed message-like content facts.
//!
//! Content messages may arrive as raw local facts during command construction
//! or as signed envelopes when another endpoint authored them. Projection code
//! should not have to duplicate that split. This module unwraps either shape,
//! verifies signed envelopes when validation reaches the point where a payload
//! is meant to become durable state, and asks the context system for the
//! `endpoint_shared` fact that proves the signer belongs to the same workspace.
//!
//! Keep signer and envelope rules here. Message projection, file projection,
//! and deletion projection should decide what payload fields mean, but the
//! invariant that a signed payload names a real endpoint with the expected
//! signing public key is enforced through this module.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId};
use crate::core::projectors::ProjectionContext;
use crate::protocol::identity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayload {
    pub payload: Vec<u8>,
    pub signer: Option<SignedSigner>,
    pub envelope: Option<identity::signed_fact::fact::SignedFactEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFact<T> {
    pub payload: T,
    pub signer: Option<SignedSigner>,
    pub envelope: Option<identity::signed_fact::fact::SignedFactEnvelope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedSigner {
    pub signer_id: FactId,
    pub signer_public_key: [u8; 32],
}

/// Returns the payload a projector should decode, preserving the signer
/// evidence when the fact was wrapped in a signed envelope.
pub fn decode_raw_or_signed(
    fact: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if fact.bytes.first().copied() == Some(identity::signed_fact::layout::TYPE_SIGNED_FACT) {
        let envelope = identity::signed_fact::layout::decode_signed_fact(fact.body())
            .map_err(|err| format!("{label} signed fact is invalid: {err}"))?;
        if envelope.inner_type != expected_type {
            return Err(format!("signed fact does not contain a {label}"));
        }
        return Ok(DecodedPayload {
            payload: envelope.payload.clone(),
            signer: Some(SignedSigner {
                signer_id: envelope.signer_id,
                signer_public_key: envelope.signer_public_key,
            }),
            envelope: Some(envelope),
        });
    }

    Ok(DecodedPayload {
        payload: fact.bytes.clone(),
        signer: None,
        envelope: None,
    })
}

pub fn verify_signature<T>(decoded: &DecodedFact<T>, label: &str) -> Result<(), String> {
    verify_envelope(decoded.envelope.as_ref(), label)
}

pub fn verify_envelope(
    envelope: Option<&identity::signed_fact::fact::SignedFactEnvelope>,
    label: &str,
) -> Result<(), String> {
    let Some(envelope) = envelope else {
        return Ok(());
    };
    identity::signed_fact::layout::verify_signed_fact(envelope)
        .map_err(|err| format!("{label} signed fact is invalid: {err}"))
}

pub fn decode_raw_or_signed_fact<T>(
    fact: &Fact,
    expected_type: u8,
    label: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<DecodedFact<T>, String> {
    let decoded = decode_raw_or_signed(fact, expected_type, label)?;
    let payload = decode(&decoded.payload)?;
    Ok(DecodedFact {
        payload,
        signer: decoded.signer,
        envelope: decoded.envelope,
    })
}

pub fn signer_need(owner: FactId, signer: Option<SignedSigner>) -> Option<ContextNeed> {
    signer.map(|signer| {
        crate::core::context::ContextNeed::range(
            owner,
            "identity_endpoint_shared",
            crate::core::facts::FactScope::Global,
            signer.signer_id,
            signer.signer_id,
        )
    })
}

/// Checks that the context payload satisfying a signer need is the endpoint
/// authority the signed content relies on.
pub fn validate_signer_context(
    context: &ProjectionContext,
    need: &ContextNeed,
    signer: SignedSigner,
    workspace_id: FactId,
    author_user_id: Option<FactId>,
    label: &str,
) -> Result<bool, String> {
    let Some(payload) = context_payload(context, need, &format!("{label} signer"))? else {
        return Ok(false);
    };
    if payload.id != signer.signer_id {
        return Err(format!(
            "{label} signer endpoint context payload id mismatch"
        ));
    }
    let envelope = identity::signed_fact::layout::decode_signed_fact(payload.body())
        .map_err(|_| format!("{label} signer context is not a signed endpoint_shared"))?;
    if envelope.inner_type != identity::endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err(format!(
            "{label} signer context is not a signed endpoint_shared"
        ));
    }
    let endpoint = identity::endpoint_shared::decode_fact_payload(&envelope.payload)
        .map_err(|_| format!("{label} signer context is not an endpoint_shared"))?;
    if endpoint.workspace_id != workspace_id {
        return Err(format!(
            "{label} signer endpoint_shared workspace does not match {label}"
        ));
    }
    if endpoint.signing_public_key != signer.signer_public_key {
        return Err(format!(
            "{label} signer public key does not match endpoint_shared"
        ));
    }
    if author_user_id.is_some_and(|author| endpoint.user_authority_fact_id != author) {
        return Err(format!(
            "{label} signer endpoint is not authorized by the named author"
        ));
    }
    Ok(true)
}

pub fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    context.payload_for_checked(need, label)
}
