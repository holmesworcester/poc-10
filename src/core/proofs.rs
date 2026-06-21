//! Protocol-neutral Verus proof boundary for projection plumbing.
//!
//! This module is the temporary trusted core proof boundary for projector proof
//! work. It must not know protocol roles such as `auth_workspace`,
//! `signature_proof`, or `content_message`; it only states properties that core
//! owns: matched payload ownership, selector matching, parked missing-context
//! output shape, owner-scoped projector output, self-only purges, context
//! replacement, and atomic projection commit.
//!
//! The theorem bodies are intentionally trusted stubs for this proof phase.
//! Projector proofs may consume these theorem functions, but protocol meaning
//! must stay in protocol proof modules.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
pub mod verus_model {
    use vstd::prelude::*;

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
        pub all_output_owners_are_self: bool,
        pub purges_only_current_fact: bool,
        pub waiting_need_count: int,
        pub waiting_need_0: SpecContextNeed,
        pub has_materialized_rows: bool,
        pub has_materialized_offers: bool,
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

    pub open spec fn context_need_equal(a: SpecContextNeed, b: SpecContextNeed) -> bool {
        a.owner == b.owner
            && a.role == b.role
            && a.scope == b.scope
            && a.start_key == b.start_key
            && a.end_key == b.end_key
    }

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

    pub open spec fn projection_context_lacks_payload_for_need(
        ctx: SpecProjectionContext,
        need: SpecContextNeed,
    ) -> bool {
        ctx.missing_need_absent && context_need_equal(ctx.missing_need, need)
    }

    pub open spec fn context_replacement_preserves_owner_boundaries(
        before: SpecPipelineGraph,
        after: SpecPipelineGraph,
        owner: int,
    ) -> bool {
        before.token == after.token && owner == owner
    }

    pub open spec fn purges_are_self_only(
        output: SpecProjectionOutput,
        current_fact_id: int,
    ) -> bool {
        output.current_fact_id == current_fact_id && output.purges_only_current_fact
    }

    pub open spec fn projection_output_owners_are_self(
        output: SpecProjectionOutput,
        current_fact_id: int,
    ) -> bool {
        output.current_fact_id == current_fact_id && output.all_output_owners_are_self
    }

    pub open spec fn no_materialized_output(output: SpecProjectionOutput) -> bool {
        !output.has_materialized_rows
            && !output.has_materialized_offers
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

    pub open spec fn atomic_projection_commit_sound(
        before: SpecPipelineGraph,
        output: SpecProjectionOutput,
        after: SpecPipelineGraph,
    ) -> bool {
        before.token == after.token && output.current_fact_id == output.current_fact_id
    }

    pub open spec fn ed25519_signature_binds(
        evidence: SpecEd25519Verification,
    ) -> bool {
        evidence.verifier_accepts
    }

    // Temporary trusted core assumption: core context construction exposes only
    // graph-bound projection context to projector proofs.
    #[verifier::external_body]
    pub proof fn theorem_projection_context_sound(
        ctx: SpecProjectionContext,
        graph: SpecPipelineGraph,
    )
        ensures projection_context_sound(ctx, graph)
    {
    }

    // Temporary trusted core assumption: matched payload bytes are loaded from
    // the matched offer owner fact.
    #[verifier::external_body]
    pub proof fn theorem_matched_payloads_are_offer_owner_facts(
        matched: SpecMatchedContext,
    )
        ensures matched_payloads_are_offer_owner_facts(matched)
    {
    }

    // Temporary trusted core assumption: matching preserves role, scope, and
    // selector overlap; role meaning remains a protocol proof obligation.
    #[verifier::external_body]
    pub proof fn theorem_matcher_preserves_role_scope_selector(
        need: SpecContextNeed,
        matched: SpecMatchedContext,
    )
        ensures matcher_preserves_role_scope_selector(need, matched)
    {
    }

    // Temporary trusted core assumption: context replacement is owner-scoped.
    #[verifier::external_body]
    pub proof fn theorem_context_replacement_preserves_owner_boundaries(
        before: SpecPipelineGraph,
        after: SpecPipelineGraph,
        owner: int,
    )
        ensures context_replacement_preserves_owner_boundaries(before, after, owner)
    {
    }

    // Temporary trusted core assumption: projector output owners are the
    // currently projected fact id.
    #[verifier::external_body]
    pub proof fn theorem_projection_output_owners_are_self(
        output: SpecProjectionOutput,
        current_fact_id: int,
    )
        ensures projection_output_owners_are_self(output, current_fact_id)
    {
    }

    // Temporary trusted core assumption: accepted purges are self-only.
    #[verifier::external_body]
    pub proof fn theorem_purges_are_self_only(
        output: SpecProjectionOutput,
        current_fact_id: int,
    )
        ensures purges_are_self_only(output, current_fact_id)
    {
    }

    // Temporary trusted core assumption: projection effects commit atomically.
    #[verifier::external_body]
    pub proof fn theorem_atomic_projection_commit_sound(
        before: SpecPipelineGraph,
        output: SpecProjectionOutput,
        after: SpecPipelineGraph,
    )
        ensures atomic_projection_commit_sound(before, output, after)
    {
    }

    // Temporary trusted foundational assumption: Ed25519 verification binds the
    // verified message bytes to the public key and signature. This proves no
    // protocol authority by itself.
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
