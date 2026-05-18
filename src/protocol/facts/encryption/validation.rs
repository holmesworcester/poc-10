use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::protocol::facts::content;
use crate::protocol::facts::identity;
use crate::protocol::matchers::{self, WrapSourceKind, WrapSourceSelector};

use super::layout;

pub(super) fn matching_wrap_sources_with_signer(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<Vec<(FactId, FactId, WrapSourceSelector)>, String> {
    projection_context
        .matched_payloads_for(need)
        .filter_map(|(offer, payload)| {
            matchers::wrap_source_offer_matches_need(need, offer)
                .map(|source| (offer, payload, source))
        })
        .map(|(offer, payload, source)| {
            let crate::core::context::ContextOffer { payload_ref, .. } = offer;
            validate_wrap_source_payload(payload, *payload_ref, &source)?;
            Ok(local_signer_secret_payload_ref(
                projection_context,
                need.owner,
                &need.scope,
                source.owner_endpoint_id,
            )
            .map(|signer_secret_fact_id| (*payload_ref, signer_secret_fact_id, source)))
        })
        .collect::<Result<Vec<_>, String>>()
        .map(|items| items.into_iter().flatten().collect())
}

pub(super) fn add_signer_needs_for_matching_sources(
    mut output: ProjectionOutput,
    projection_context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<ProjectionOutput, String> {
    for (offer, payload) in projection_context.matched_payloads_for(need) {
        let Some(source) = matchers::wrap_source_offer_matches_need(need, offer) else {
            continue;
        };
        let crate::core::context::ContextOffer { payload_ref, .. } = offer;
        validate_wrap_source_payload(payload, *payload_ref, &source)?;
        output = output.need(crate::protocol::matchers::local_signer_secret_need(
            need.owner,
            need.scope.clone(),
            source.owner_endpoint_id,
        ));
    }
    Ok(output)
}

fn local_signer_secret_payload_ref(
    projection_context: &ProjectionContext,
    owner: FactId,
    scope: &FactScope,
    signer_id: FactId,
) -> Option<FactId> {
    let need = crate::protocol::matchers::local_signer_secret_need(owner, scope.clone(), signer_id);
    projection_context
        .offer_payload_refs_matching(&need.role, &need.scope, &need.selector)
        .min()
}

pub(super) fn matched_payload_fact<'a>(
    projection_context: &'a ProjectionContext,
    need: &ContextNeed,
) -> Option<&'a Fact> {
    projection_context.payload_for(need)
}

pub(super) fn has_matching_signer_public_key(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
    signer_public_key: &[u8; 32],
) -> bool {
    projection_context
        .matched_payloads_for(need)
        .any(|(_, payload)| {
            if let Ok(signer) =
                content::sealed_message::layout::decode_signer_pubkey(payload.body())
            {
                return signer.signer_id.as_slice() == need.selector.as_bytes()
                    && signer.public_key == *signer_public_key;
            }
            let Ok(envelope) = identity::signed_fact::layout::decode_signed_fact(payload.body())
            else {
                return false;
            };
            if envelope.inner_type != identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED {
                return false;
            }
            let Ok(endpoint) = identity::endpoint_shared::layout::decode_fact(&envelope.payload)
            else {
                return false;
            };
            endpoint.endpoint_id.as_slice() == need.selector.as_bytes()
                && endpoint.signing_public_key == *signer_public_key
        })
}

pub(super) fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("encryption fact scope does not match body workspace".to_string())
    }
}

pub(super) fn require_local_scope(fact: &Fact) -> Result<(), String> {
    if fact.scope == FactScope::Local {
        Ok(())
    } else {
        Err("local encryption fact must have local scope".to_string())
    }
}

fn validate_wrap_source_payload(
    payload: &Fact,
    expected_payload_ref: FactId,
    source: &WrapSourceSelector,
) -> Result<(), String> {
    if payload.id != expected_payload_ref {
        return Err("wrap source context payload id mismatch".to_string());
    }
    if payload.scope != FactScope::Local {
        return Err("wrap source context must be local key material".to_string());
    }
    match source.kind {
        WrapSourceKind::FrontierRoot => {
            let root = layout::decode_local_key_secret(payload.body())
                .map_err(|_| "wrap source context is not a local root secret".to_string())?;
            if root.workspace_id != source.workspace_id
                || root.frontier_id != source.frontier_id
                || root.owner_endpoint_id != source.owner_endpoint_id
                || root.created_at_ms != source.frontier_created_at_ms
            {
                return Err("wrap source root payload does not match selector".to_string());
            }
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            let node = layout::decode_local_history_node_secret(payload.body())
                .map_err(|_| "wrap source context is not a local history node".to_string())?;
            if node.workspace_id != source.workspace_id
                || node.frontier_id != source.frontier_id
                || node.owner_endpoint_id != source.owner_endpoint_id
                || source.frontier_created_at_ms != 0
                || node.range_start != range_start
                || node.range_width != range_width
                || node.bit_depth != bit_depth
                || node.fact_id_prefix != fact_id_prefix
            {
                return Err("wrap source history payload does not match selector".to_string());
            }
        }
    }
    Ok(())
}
