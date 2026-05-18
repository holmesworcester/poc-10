use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projection::{MatchedContext, ProjectionContext};
use crate::protocol::facts::identity;

use super::super::fact::{SealedMessageFact, SignerId};
use super::super::layout;
use crate::protocol::matchers;

pub(super) fn validate_signer_context(
    payload: &Fact,
    need: &ContextNeed,
    signer_id: SignerId,
    expected_public_key: Option<[u8; 32]>,
) -> Result<(), String> {
    if let Ok(signer) = layout::decode_signer_pubkey(payload.body()) {
        if payload.scope != need.scope {
            return Err("sealed-message signer context scope does not match need".to_string());
        }
        if signer.signer_id != signer_id {
            return Err("sealed-message signer context payload does not match need".to_string());
        }
        if expected_public_key.is_some_and(|public_key| signer.public_key != public_key) {
            return Err(
                "sealed-message signer context public key does not match signed envelope"
                    .to_string(),
            );
        }
        return Ok(());
    }

    let endpoint = endpoint_shared_signer(payload).ok_or_else(|| {
        "sealed-message signer context must be a signer pubkey or endpoint_shared".to_string()
    })?;
    if endpoint.workspace_id != scope_workspace_id(&need.scope)? {
        return Err("sealed-message signer endpoint workspace does not match need".to_string());
    }
    if endpoint.endpoint_id != signer_id {
        return Err("sealed-message signer endpoint id does not match need".to_string());
    }
    if expected_public_key.is_some_and(|public_key| endpoint.signing_public_key != public_key) {
        return Err(
            "sealed-message signer context public key does not match signed envelope".to_string(),
        );
    }
    Ok(())
}

pub(super) fn endpoint_shared_signer(
    payload: &Fact,
) -> Option<identity::endpoint_shared::fact::EndpointSharedFact> {
    if let Ok(endpoint) = identity::endpoint_shared::layout::decode_fact(payload.body()) {
        return Some(endpoint);
    }
    let envelope = identity::signed_fact::layout::decode_signed_fact(payload.body()).ok()?;
    if envelope.inner_type != identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED {
        return None;
    }
    let endpoint = identity::endpoint_shared::layout::decode_fact(&envelope.payload).ok()?;
    Some(endpoint)
}

fn scope_workspace_id(scope: &FactScope) -> Result<FactId, String> {
    match scope {
        FactScope::Scoped { kind, id } if kind.as_str() == "workspace" => Ok(*id),
        _ => Err("sealed-message signer need is not workspace scoped".to_string()),
    }
}

pub(super) fn validate_deletion_context(
    payload: &Fact,
    need: &ContextNeed,
    message: &SealedMessageFact,
) -> Result<(), String> {
    if payload.scope != need.scope {
        return Err("sealed-message deletion context scope does not match need".to_string());
    }
    let deletion = layout::decode_message_deletion(payload.body())
        .map_err(|_| "sealed-message deletion context must be a message deletion".to_string())?;
    if deletion.workspace_id != message.workspace_id
        || deletion.target_id != need.owner
        || deletion.author_user_id != message.author_user_id
    {
        return Err("sealed-message deletion context payload does not match need".to_string());
    }
    require_fact_scope(payload, &matchers::workspace_scope(deletion.workspace_id))?;
    Ok(())
}

pub(super) fn matched_secret_payload<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
) -> Result<Option<&'a Fact>, String> {
    let mut payload = None;
    for matched in context
        .matched_context()
        .iter()
        .filter(|matched| matched.need == *need)
    {
        validate_secret_context(matched, need)?;
        payload = Some(&matched.payload);
        break;
    }
    Ok(payload)
}

fn validate_secret_context(matched: &MatchedContext, need: &ContextNeed) -> Result<(), String> {
    if matched.offer.payload_ref != matched.payload.id {
        return Err("sealed-message secret context offer payload mismatch".to_string());
    }
    if !matchers::secret_offer_matches_need(need, &matched.offer) {
        return Err("sealed-message secret context offer does not match need".to_string());
    }
    if let Ok(secret) = layout::decode_secret_node(matched.payload.body()) {
        require_fact_scope(
            &matched.payload,
            &matchers::workspace_scope(secret.workspace_id),
        )?;
        let offer =
            matchers::decode_secret_offer_selector(&matched.offer.selector).ok_or_else(|| {
                "sealed-message secret context offer selector is malformed".to_string()
            })?;
        if secret.workspace_id != offer.workspace_id
            || secret.frontier_id != offer.frontier_id
            || secret.start_minute != offer.start_minute
            || secret.end_minute != offer.end_minute
            || secret.prefix_bytes != offer.prefix_bytes
            || secret.leaf_prefix != offer.leaf_prefix
        {
            return Err("sealed-message secret context payload does not match offer".to_string());
        }
    }
    Ok(())
}

pub(super) fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sealed-message fact scope does not match body workspace".to_string())
    }
}
