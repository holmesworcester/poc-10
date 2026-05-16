use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::sealed_message;
use crate::event_modules::signed_fact;

use super::matchers::{self, WrapSourceSelector};

pub(super) fn matching_wrap_sources_with_signer(
    offers: &[ContextOffer],
    need: &ContextNeed,
) -> Vec<(FactId, FactId, WrapSourceSelector)> {
    offers
        .iter()
        .filter_map(|offer| {
            matchers::wrap_source_offer_matches_need(need, offer).and_then(|source| {
                local_signer_secret_payload_ref(
                    offers,
                    need.owner,
                    &need.scope,
                    source.owner_endpoint_id,
                )
                .map(|signer_secret_fact_id| (offer.payload_ref, signer_secret_fact_id, source))
            })
        })
        .collect()
}

pub(super) fn add_signer_needs_for_matching_sources(
    mut output: ProjectionOutput,
    offers: &[ContextOffer],
    need: &ContextNeed,
) -> ProjectionOutput {
    for offer in offers {
        let Some(source) = matchers::wrap_source_offer_matches_need(need, offer) else {
            continue;
        };
        output = output.need(signed_fact::matchers::local_signer_secret_need(
            need.owner,
            need.scope.clone(),
            source.owner_endpoint_id,
        ));
    }
    output
}

fn local_signer_secret_payload_ref(
    offers: &[ContextOffer],
    owner: FactId,
    scope: &FactScope,
    signer_id: FactId,
) -> Option<FactId> {
    let need = signed_fact::matchers::local_signer_secret_need(owner, scope.clone(), signer_id);
    offers
        .iter()
        .filter(|offer| offer.role == need.role && offer.selector == need.selector)
        .map(|offer| offer.payload_ref)
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
        .matched_context()
        .iter()
        .filter(|matched| matched.need.role == need.role && matched.need.selector == need.selector)
        .any(|matched| {
            sealed_message::layout::decode_signer_pubkey(&matched.payload.bytes)
                .map(|signer| {
                    signer.signer_id.as_slice() == need.selector.as_bytes()
                        && signer.public_key == *signer_public_key
                })
                .unwrap_or(false)
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
