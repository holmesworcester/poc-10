use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId};
use crate::core::projection::ProjectionContext;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers;
use crate::event_modules::signed_fact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayload {
    pub payload: Vec<u8>,
    pub signer: Option<SignedSigner>,
    pub envelope: Option<signed_fact::fact::SignedFactEnvelope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedSigner {
    pub signer_id: FactId,
    pub signer_public_key: [u8; 32],
}

pub fn decode_raw_or_signed(
    fact: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if fact.bytes.first().copied() == Some(signed_fact::layout::TYPE_SIGNED_FACT) {
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
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

pub fn verify_signature(decoded: &DecodedPayload, label: &str) -> Result<(), String> {
    let Some(envelope) = decoded.envelope.as_ref() else {
        return Ok(());
    };
    signed_fact::layout::verify_signed_fact(envelope)
        .map_err(|err| format!("{label} signed fact is invalid: {err}"))
}

pub fn signer_need(owner: FactId, signer: Option<SignedSigner>) -> Option<ContextNeed> {
    signer.map(|signer| {
        identity_matchers::exact_need(
            owner,
            identity_matchers::endpoint_shared_role(),
            signer.signer_id,
        )
    })
}

pub fn validate_signer_context(
    context: &ProjectionContext,
    need: &ContextNeed,
    signer: SignedSigner,
    workspace_id: FactId,
    author_user_id: Option<FactId>,
    label: &str,
) -> Result<bool, String> {
    let Some(payload) = payload_for_need(context, need) else {
        return Ok(false);
    };
    if payload.id != signer.signer_id {
        return Err(format!(
            "{label} signer endpoint context payload id mismatch"
        ));
    }
    let envelope = signed_fact::layout::decode_signed_fact(&payload.bytes)
        .map_err(|_| format!("{label} signer context is not a signed endpoint_shared"))?;
    if envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
        return Err(format!(
            "{label} signer context is not a signed endpoint_shared"
        ));
    }
    let endpoint = endpoint_shared_layout::decode_fact(&envelope.payload)
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
    if author_user_id.is_some_and(|author| endpoint.user_authority_event_id != author) {
        return Err(format!(
            "{label} signer endpoint is not authorized by the named author"
        ));
    }
    Ok(true)
}

pub fn payload_for_need<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
) -> Option<&'a Fact> {
    // The wake loop guarantees `payload.id == offer.owner` because each
    // projector can only offer its own fact; no defensive equality check needed.
    context.payload_for(need)
}
