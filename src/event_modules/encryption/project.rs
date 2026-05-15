//! Poc-10 encryption projector dispatcher and shared projection helpers.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::key_request::project::project_key_request;
use super::key_wrap::project::project_signed_key_wrap;
use super::local_secret::project::{project_local_history_node_secret, project_local_key_secret};
use super::recipient_key::project::{project_local_recipient_key, project_recipient_key};
use super::wrap_source::context::{self as wrap_source_context, WrapSourceSelector};
use super::wrap_source::project::project_removal_frontier;
use crate::event_modules::sealed_message;
use crate::event_modules::signed_fact;

#[derive(Debug, Clone, Default)]
pub struct EncryptionProjector;

impl EncryptionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EncryptionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(tag) if tag == super::recipient_key::layout::TYPE_RECIPIENT_KEY => {
                project_recipient_key(fact, context)
            }
            Some(tag) if tag == super::wrap_source::layout::TYPE_REMOVAL_FRONTIER => {
                project_removal_frontier(fact)
            }
            Some(tag) if tag == super::local_secret::layout::TYPE_LOCAL_KEY_SECRET => {
                project_local_key_secret(fact)
            }
            Some(tag) if tag == super::local_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET => {
                project_local_history_node_secret(fact)
            }
            Some(tag) if tag == super::recipient_key::layout::TYPE_LOCAL_RECIPIENT_KEY => {
                project_local_recipient_key(fact, context)
            }
            Some(tag) if tag == super::key_request::layout::TYPE_KEY_REQUEST => {
                project_key_request(fact, context)
            }
            Some(tag) if tag == signed_fact::layout::TYPE_SIGNED_FACT => {
                project_signed_key_wrap(fact, context)
            }
            _ => Err("unknown encryption fact type".to_string()),
        }
    }
}

pub(super) fn matching_wrap_sources_with_signer(
    offers: &[ContextOffer],
    need: &ContextNeed,
) -> Vec<(FactId, FactId, WrapSourceSelector)> {
    offers
        .iter()
        .filter_map(|offer| {
            wrap_source_context::wrap_source_offer_matches_need(need, offer).and_then(|source| {
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
        let Some(source) = wrap_source_context::wrap_source_offer_matches_need(need, offer) else {
            continue;
        };
        output = output.need(signed_fact::context::local_signer_secret_need(
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
    let need = signed_fact::context::local_signer_secret_need(owner, scope.clone(), signer_id);
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
    projection_context
        .matched_context()
        .iter()
        .find(|matched| matched.need.role == need.role && matched.need.selector == need.selector)
        .map(|matched| &matched.payload)
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
