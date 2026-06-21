//! Protocol-neutral Verus proof boundary for projection plumbing.
//!
//! This file is the bridge between core projection mechanics and protocol
//! projector proofs. Its job is deliberately narrow: state the core facts that
//! protocol proofs are allowed to rely on, and make the current trust boundary
//! impossible to miss. It must not know protocol roles such as
//! `auth_workspace`, `signature_proof`, or `content_message`; those meanings
//! belong in protocol `proofs.rs` files.
//!
//! Read the declarations from most significant to most helper-like:
//!
//! 1. Deferred composition stubs describe the runtime facts that make projector
//!    proofs useful end to end: context construction, matched-payload origin,
//!    selector preservation, context replacement, and atomic commit. These are
//!    the theorem interfaces projectors eventually compose through, but their
//!    bodies are unproven today.
//! 2. Near-term core glue stubs describe smaller facts we plan to prove first:
//!    owner-bearing output ownership, self-only purge requests, parked
//!    missing-context output, and offer-claim finalization. They are not
//!    threat-model coverage by themselves; they only let projector proofs attach
//!    their semantic evidence to stored core state.
//! 3. Foundational stubs describe substrate contracts such as Ed25519 binding.
//!    They may talk about primitive bytes and keys, never protocol authority.
//! 4. Spec helpers and witness structs are vocabulary. They are not proof
//!    coverage and do not justify a checklist item.
//!
//! Every exported `theorem_*` below currently uses
//! `#[verifier::external_body]`. That means Verus verifies the type and
//! postcondition shape while trusting the body. It is an explicit proof debt,
//! not a completed proof over `project_fact.rs`. When a real proof lands, the
//! theorem should keep its interface and lose `external_body`. Until then,
//! consumers may use these theorems only as named assumptions, and any
//! threat-model walkthrough must list them as gaps.
//!
//! Current status:
//!
//! - Proven here today: vocabulary consistency and any non-theorem spec helper
//!   definitions that Verus type-checks.
//! - Not proven here today: every exported `theorem_*` runtime/core property.
//! - Punted for a later core proof model: the composition stubs that cross
//!   matcher construction, payload loading, context replacement, and commit.
//! - First stubs to replace: the near-term core glue stubs over local projection
//!   output and offer-claim finalization.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
pub mod verus_model {
    use vstd::prelude::*;

    // -------------------------------------------------------------------------
    // Proof vocabulary. These ghost structs are not proof coverage; they are the
    // small views that future Rust-code correspondence theorems must connect to
    // actual `project_fact.rs`, `context.rs`, and crypto values.
    // -------------------------------------------------------------------------

    #[derive(Copy, Clone)]
    pub struct SpecPipelineGraph {
        pub token: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecContextNeed {
        pub owner: int,
        pub role: int,
        pub scope: int,
        pub start_key: int,
        pub end_key: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecContextOffer {
        pub owner: int,
        pub role: int,
        pub scope: int,
        pub start_key: int,
        pub end_key: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecContextOfferClaim {
        pub role: int,
        pub scope: int,
        pub start_key: int,
        pub end_key: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecMatchedContext {
        pub need: SpecContextNeed,
        pub offer: SpecContextOffer,
        pub payload_fact_id: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecProjectionContext {
        pub graph_token: int,
        pub missing_need: SpecContextNeed,
        pub missing_need_absent: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecProjectionOutput {
        pub current_fact_id: int,
        pub owner_bearing_outputs_are_self: bool,
        pub purges_only_current_fact: bool,
        pub waiting_need_count: int,
        pub waiting_need_0: SpecContextNeed,
        pub has_materialized_rows: bool,
        pub has_materialized_offer_claims: bool,
        pub has_materialized_intents: bool,
        pub has_materialized_facts: bool,
        pub has_time_wakes: bool,
        pub has_purges: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecEd25519Verification {
        pub public_key: int,
        pub message_domain: int,
        pub message_part_0: int,
        pub message_part_1: int,
        pub signature: int,
        pub verifier_accepts: bool,
    }

    // -------------------------------------------------------------------------
    // Most significant: composition predicates that let projector proofs talk
    // about matched context and committed runtime state. These predicates are
    // the shape of the future core proof, not completed proof coverage.
    // -------------------------------------------------------------------------

    pub open spec fn matched_payloads_are_offer_owner_facts(
        matched: SpecMatchedContext,
    ) -> bool {
        matched.payload_fact_id == matched.offer.owner
    }

    pub open spec fn projection_context_sound(
        ctx: SpecProjectionContext,
        graph: SpecPipelineGraph,
    ) -> bool {
        ctx.graph_token == graph.token
    }

    pub open spec fn matcher_preserves_role_scope_selector(
        need: SpecContextNeed,
        matched: SpecMatchedContext,
    ) -> bool {
        need.owner == matched.need.owner
            && need.role == matched.need.role
            && need.scope == matched.need.scope
            && need.start_key == matched.need.start_key
            && need.end_key == matched.need.end_key
            && need.role == matched.offer.role
            && need.scope == matched.offer.scope
            && need.start_key <= matched.offer.end_key
            && matched.offer.start_key <= need.end_key
    }

    pub open spec fn context_replacement_preserves_owner_boundaries(
        before: SpecPipelineGraph,
        after: SpecPipelineGraph,
        owner: int,
    ) -> bool {
        before.token == after.token && owner == owner
    }

    pub open spec fn atomic_projection_commit_sound(
        before: SpecPipelineGraph,
        output: SpecProjectionOutput,
        after: SpecPipelineGraph,
    ) -> bool {
        before.token == after.token && output.current_fact_id == output.current_fact_id
    }

    // -------------------------------------------------------------------------
    // Near-term core glue. These are intentionally smaller than the composition
    // predicates above and should be the first `external_body` stubs replaced by
    // real proofs over actual Rust paths.
    // -------------------------------------------------------------------------

    pub open spec fn projection_context_lacks_payload_for_need(
        ctx: SpecProjectionContext,
        need: SpecContextNeed,
    ) -> bool {
        ctx.missing_need_absent && context_need_equal(ctx.missing_need, need)
    }

    pub open spec fn purges_are_self_only(
        output: SpecProjectionOutput,
        current_fact_id: int,
    ) -> bool {
        output.current_fact_id == current_fact_id && output.purges_only_current_fact
    }

    pub open spec fn projection_output_owner_bearing_effects_are_self(
        output: SpecProjectionOutput,
        current_fact_id: int,
    ) -> bool {
        output.current_fact_id == current_fact_id && output.owner_bearing_outputs_are_self
    }

    pub open spec fn offer_claim_finalizes_to_projected_owner(
        claim: SpecContextOfferClaim,
        offer: SpecContextOffer,
        current_fact_id: int,
    ) -> bool {
        offer.owner == current_fact_id
            && offer.role == claim.role
            && offer.scope == claim.scope
            && offer.start_key == claim.start_key
            && offer.end_key == claim.end_key
    }

    pub open spec fn no_materialized_output(output: SpecProjectionOutput) -> bool {
        !output.has_materialized_rows
            && !output.has_materialized_offer_claims
            && !output.has_materialized_intents
            && !output.has_materialized_facts
            && !output.has_time_wakes
            && !output.has_purges
    }

    pub open spec fn parked_output_for_missing_need(
        output: SpecProjectionOutput,
        need: SpecContextNeed,
    ) -> bool {
        output.current_fact_id == need.owner
            && output.waiting_need_count == 1int
            && context_need_equal(output.waiting_need_0, need)
            && no_materialized_output(output)
    }

    // -------------------------------------------------------------------------
    // Foundational primitive predicates. These are about advertised primitive
    // contracts only, never protocol authority.
    // -------------------------------------------------------------------------

    pub open spec fn ed25519_signature_binds(
        evidence: SpecEd25519Verification,
    ) -> bool {
        evidence.verifier_accepts
    }

    // -------------------------------------------------------------------------
    // Ancillary helpers. Helpers can make larger proofs readable, but they do
    // not count as core or threat-model proof coverage.
    // -------------------------------------------------------------------------

    pub open spec fn context_need_equal(a: SpecContextNeed, b: SpecContextNeed) -> bool {
        a.owner == b.owner
            && a.role == b.role
            && a.scope == b.scope
            && a.start_key == b.start_key
            && a.end_key == b.end_key
    }

    // -------------------------------------------------------------------------
    // Punted composition theorem stubs.
    //
    // These are the highest-value core facts and the hardest to prove because
    // they cross matcher construction, offer-owner payload loading, context
    // replacement, and SQLite transaction boundaries. They are explicit trusted
    // assumptions until real core proofs replace the external bodies.
    // -------------------------------------------------------------------------

    // Deferred trusted core theorem: core context construction exposes only
    // graph-bound projection context to projector proofs.
    #[verifier::external_body]
    pub proof fn theorem_projection_context_sound(
        ctx: SpecProjectionContext,
        graph: SpecPipelineGraph,
    )
        ensures projection_context_sound(ctx, graph)
    {
    }

    // Deferred trusted core theorem: matched payload bytes are loaded from the
    // matched offer owner fact.
    #[verifier::external_body]
    pub proof fn theorem_matched_payloads_are_offer_owner_facts(
        matched: SpecMatchedContext,
    )
        ensures matched_payloads_are_offer_owner_facts(matched)
    {
    }

    // Deferred trusted core theorem: matching preserves role, scope, and
    // selector overlap. Role meaning remains a protocol proof obligation.
    #[verifier::external_body]
    pub proof fn theorem_matcher_preserves_role_scope_selector(
        need: SpecContextNeed,
        matched: SpecMatchedContext,
    )
        ensures matcher_preserves_role_scope_selector(need, matched)
    {
    }

    // Deferred trusted core theorem: context replacement is owner-scoped.
    #[verifier::external_body]
    pub proof fn theorem_context_replacement_preserves_owner_boundaries(
        before: SpecPipelineGraph,
        after: SpecPipelineGraph,
        owner: int,
    )
        ensures context_replacement_preserves_owner_boundaries(before, after, owner)
    {
    }

    // Deferred trusted core theorem: projection effects commit atomically.
    #[verifier::external_body]
    pub proof fn theorem_atomic_projection_commit_sound(
        before: SpecPipelineGraph,
        output: SpecProjectionOutput,
        after: SpecPipelineGraph,
    )
        ensures atomic_projection_commit_sound(before, output, after)
    {
    }

    // -------------------------------------------------------------------------
    // Near-term core theorem stubs.
    //
    // These should be replaced before projector proofs claim threat-model
    // coverage. They are smaller than the composition stubs above and track
    // concrete local code paths such as `ProjectionOutput::new().need(...)` and
    // `enforce_owner_is_self`.
    // -------------------------------------------------------------------------

    // Near-term trusted core theorem: owner-bearing projector outputs are
    // owned by the currently projected fact id. Offer claims are ownerless
    // until core finalization and are not covered by this theorem.
    #[verifier::external_body]
    pub proof fn theorem_projection_output_owner_bearing_effects_are_self(
        output: SpecProjectionOutput,
        current_fact_id: int,
    )
        ensures projection_output_owner_bearing_effects_are_self(output, current_fact_id)
    {
    }

    // Near-term trusted core theorem: accepted purges are self-only.
    #[verifier::external_body]
    pub proof fn theorem_purges_are_self_only(
        output: SpecProjectionOutput,
        current_fact_id: int,
    )
        ensures purges_are_self_only(output, current_fact_id)
    {
    }

    // Near-term trusted core theorem: core finalizes an ownerless offer claim by
    // attaching the projected fact id as owner and copying the role, scope, and
    // key range unchanged.
    #[verifier::external_body]
    pub proof fn theorem_offer_claim_finalizes_to_projected_owner(
        claim: SpecContextOfferClaim,
        offer: SpecContextOffer,
        current_fact_id: int,
    )
        ensures offer_claim_finalizes_to_projected_owner(claim, offer, current_fact_id)
    {
    }

    // Near-term trusted core theorem: missing payload lookup failed for the
    // exact need represented by this proof witness.
    #[verifier::external_body]
    pub proof fn theorem_projection_context_lacks_payload_for_need(
        ctx: SpecProjectionContext,
        need: SpecContextNeed,
    )
        ensures projection_context_lacks_payload_for_need(ctx, need)
    {
    }

    // Near-term trusted core theorem: the parked output for a missing need has
    // exactly one stable need and no materialized rows, offer claims, intents,
    // facts, time wakes, or purges.
    #[verifier::external_body]
    pub proof fn theorem_parked_output_for_missing_need(
        output: SpecProjectionOutput,
        need: SpecContextNeed,
    )
        ensures parked_output_for_missing_need(output, need)
    {
    }

    // -------------------------------------------------------------------------
    // Foundational trusted stubs.
    // -------------------------------------------------------------------------

    // Foundational trusted theorem: Ed25519 verification binds the verified
    // message bytes to the public key and signature. This proves no protocol
    // authority by itself.
    #[verifier::external_body]
    pub proof fn theorem_ed25519_verify_binds(
        evidence: SpecEd25519Verification,
    )
        requires evidence.verifier_accepts
        ensures ed25519_signature_binds(evidence)
    {
    }
}
}
