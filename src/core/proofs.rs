//! Protocol-neutral proof certificates for projection plumbing.
//!
//! This module is the temporary trusted core proof boundary for projector proof
//! work. It must not know protocol roles such as `auth_workspace`,
//! `signature_proof`, or `content_message`; it only checks properties that core
//! owns in executable runtime values: matched payload ownership, selector
//! matching, owner-scoped projector output, and self-only purges.
//!
//! Future Verus work should replace these executable theorem helpers with
//! proof bodies over the matcher, context replacement, purge, and commit model
//! while preserving the same protocol-neutral postconditions.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::FactId;
use crate::core::project_fact::{ProjectionContext, ProjectionOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionContextSound;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedPayloadsAreOfferOwnerFacts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatcherPreservesRoleScopeSelector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionOutputOwnersAreSelf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgesAreSelfOnly;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoMaterializedOutput;

/// Core selector matching: same role, same scope, and inclusive range overlap.
pub fn matcher_preserves_role_scope_selector(need: &ContextNeed, offer: &ContextOffer) -> bool {
    need.role == offer.role
        && need.scope == offer.scope
        && need.start_key.as_bytes() <= offer.end_key.as_bytes()
        && offer.start_key.as_bytes() <= need.end_key.as_bytes()
}

/// Every matched payload reachable through `need` is loaded from the matched
/// offer owner and the matched offer preserves the core selector relation.
pub fn matched_payloads_are_offer_owner_facts(
    context: &ProjectionContext,
    need: &ContextNeed,
) -> bool {
    context.matched_payloads_for(need).all(|(offer, payload)| {
        offer.owner == payload.id && matcher_preserves_role_scope_selector(need, offer)
    })
}

/// Projection context soundness for the needs a projector actually declared.
///
/// The full core proof will quantify over every matched row loaded for a
/// projection. The executable shape takes the declared needs as witnesses
/// because `ProjectionContext` intentionally exposes matched payloads only
/// through need-anchored helpers.
pub fn projection_context_sound(context: &ProjectionContext, needs: &[ContextNeed]) -> bool {
    needs
        .iter()
        .all(|need| matched_payloads_are_offer_owner_facts(context, need))
}

pub fn projection_output_owners_are_self(
    output: &ProjectionOutput,
    current_fact_id: FactId,
) -> bool {
    output
        .needs
        .iter()
        .all(|need| need.owner == current_fact_id)
        && output
            .offers
            .iter()
            .all(|offer| offer.owner == current_fact_id)
        && output
            .time_wakes
            .iter()
            .all(|wake| wake.owner == current_fact_id)
        && purges_are_self_only(output, current_fact_id)
}

pub fn purges_are_self_only(output: &ProjectionOutput, current_fact_id: FactId) -> bool {
    output
        .effects
        .purged_facts
        .iter()
        .all(|purged| *purged == current_fact_id)
}

/// Missing-context projectors may leave needs, but no committed protocol
/// materialization should be present while authority context is absent.
pub fn no_materialized_output(output: &ProjectionOutput) -> bool {
    output.offers.is_empty()
        && output.time_wakes.is_empty()
        && output.effects.facts.is_empty()
        && output.effects.priority_facts.is_empty()
        && output.effects.incoming_facts.is_empty()
        && output.effects.incoming_fact_metadata.is_empty()
        && output.effects.purged_facts.is_empty()
        && output.effects.row_mutations.is_empty()
        && output.effects.intents.is_empty()
        && output.effects.local_intents.is_empty()
        && !output.effects.rebuild_derived_state
}

pub fn theorem_matcher_preserves_role_scope_selector(
    need: &ContextNeed,
    offer: &ContextOffer,
) -> Result<MatcherPreservesRoleScopeSelector, String> {
    matcher_preserves_role_scope_selector(need, offer)
        .then_some(MatcherPreservesRoleScopeSelector)
        .ok_or_else(|| "matched offer does not preserve role, scope, and selector".to_string())
}

pub fn theorem_matched_payloads_are_offer_owner_facts(
    context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<MatchedPayloadsAreOfferOwnerFacts, String> {
    matched_payloads_are_offer_owner_facts(context, need)
        .then_some(MatchedPayloadsAreOfferOwnerFacts)
        .ok_or_else(|| "matched context payload is not the matched offer owner fact".to_string())
}

pub fn theorem_projection_context_sound(
    context: &ProjectionContext,
    needs: &[ContextNeed],
) -> Result<ProjectionContextSound, String> {
    projection_context_sound(context, needs)
        .then_some(ProjectionContextSound)
        .ok_or_else(|| "projection context failed core soundness checks".to_string())
}

pub fn theorem_projection_output_owners_are_self(
    output: &ProjectionOutput,
    current_fact_id: FactId,
) -> Result<ProjectionOutputOwnersAreSelf, String> {
    projection_output_owners_are_self(output, current_fact_id)
        .then_some(ProjectionOutputOwnersAreSelf)
        .ok_or_else(|| "projection output contains a foreign owner".to_string())
}

pub fn theorem_purges_are_self_only(
    output: &ProjectionOutput,
    current_fact_id: FactId,
) -> Result<PurgesAreSelfOnly, String> {
    purges_are_self_only(output, current_fact_id)
        .then_some(PurgesAreSelfOnly)
        .ok_or_else(|| "projection output contains a foreign purge".to_string())
}

pub fn theorem_no_materialized_output(
    output: &ProjectionOutput,
) -> Result<NoMaterializedOutput, String> {
    no_materialized_output(output)
        .then_some(NoMaterializedOutput)
        .ok_or_else(|| "projection output materialized data while waiting for context".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextNeed, ContextOffer};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::project_fact::{MatchedContext, ProjectionOutput};

    #[test]
    fn matched_payload_theorem_requires_offer_owner_payload() {
        let owner = [1; 32];
        let payload = Fact::new(FactScope::Global, 1, b"payload".to_vec());
        let need = ContextNeed::range(owner, "proof_role", FactScope::Global, [5; 32], [5; 32]);
        let offer = ContextOffer::range(
            payload.id,
            "proof_role",
            FactScope::Global,
            [5; 32],
            [5; 32],
        );
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: need.clone(),
            offer,
            payload,
        }]);

        theorem_matched_payloads_are_offer_owner_facts(&context, &need)
            .expect("payload is the offer owner fact");
    }

    #[test]
    fn owner_scoped_output_theorem_rejects_foreign_context_owner() {
        let owner = [1; 32];
        let output = ProjectionOutput::new().offer(ContextOffer::range(
            [2; 32],
            "proof_role",
            FactScope::Global,
            [5; 32],
            [5; 32],
        ));

        let err = theorem_projection_output_owners_are_self(&output, owner)
            .expect_err("foreign offer owner must reject");
        assert!(err.contains("foreign owner"));
    }
}
