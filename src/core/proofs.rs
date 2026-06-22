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
//!    proofs useful end to end: context construction, matched-offer provenance,
//!    selector preservation, route dispatch,
//!    projected table write confinement, context replacement, and atomic commit. These
//!    are the theorem interfaces projectors eventually compose through, but
//!    their bodies are unproven today.
//! 2. Near-term core glue stubs describe smaller facts we plan to prove first:
//!    owner-bearing output ownership, self-only purge requests, parked
//!    missing-context output, and offer-claim finalization. They are not
//!    threat-model coverage by themselves; they only let projector proofs attach
//!    their semantic evidence to stored core state.
//! 3. Foundational stubs describe substrate contracts such as Ed25519 binding.
//!    They may talk about primitive bytes, keys, and cryptographic possession
//!    properties. They must never decide protocol authority such as membership,
//!    admin status, or deletion authorship.
//! 4. Spec helpers and witness structs are vocabulary. They are not proof
//!    coverage, do not justify a checklist item, and do not retire a theorem
//!    stub unless a separate correspondence theorem ties them to production
//!    Rust code.
//!
//! Every exported `theorem_*` below currently uses
//! `#[verifier::external_body]`. That means Verus verifies the type and
//! postcondition shape while trusting the body. It is an explicit proof debt,
//! not a completed proof over `project_fact.rs`. When a real proof lands, the
//! theorem should keep its interface and lose `external_body`. Until then,
//! consumers may use these theorems only as named assumptions, and any
//! threat-model walkthrough must list them as gaps.
//!
//! Proof debt summary:
//!
//! - Proven here today: vocabulary consistency and any non-theorem spec helper
//!   definitions that Verus type-checks.
//! - Proven in production Rust today:
//!   `projected_owner_matches(owner, fact_id)` bytewise accepts if and only if
//!   `owner == fact_id`; the verified scan helpers use this production
//!   decision for each owner they inspect.
//! - Proven in production Rust today:
//!   `projected_purge_owners_are_self`, `projected_need_owners_are_self`, and
//!   `projected_time_wake_owners_are_self` accept if and only if every scanned
//!   purge id, need owner, or time-wake owner equals the projected fact id;
//!   `enforce_owner_is_self` branches on these verified production scans.
//! - Proven in production Rust today:
//!   `projected_output_owners_are_self` composes the three owner scans and
//!   accepts if and only if every scanned purge id, need owner, and time-wake
//!   owner equals the projected fact id; `enforce_owner_is_self` branches on
//!   this aggregate helper before returning success or a diagnostic error.
//! - Proven in production Rust today:
//!   `projected_owner_status` returns accepted, foreign purge, foreign need, or
//!   foreign time-wake exactly according to those owner predicates;
//!   `enforce_owner_is_self` branches on this verified production status.
//! - Proven in production Rust today:
//!   `owner_status_allows_projection(status)` accepts if and only if `status`
//!   is exactly `OWNER_CHECK_ACCEPTED`, so the success branch is not an
//!   unproved interpretation of the status byte.
//! - Proven in production Rust today:
//!   `projection_output_owner_status(output, fact_id)` applies the same
//!   accepted/foreign-purge/foreign-need/foreign-time-wake classification to
//!   the actual `ProjectionOutput` object consumed by `enforce_owner_is_self`.
//! - Proven in production Rust today:
//!   `projection_output_owner_enforcement_accepts(output, fact_id)` accepts if
//!   and only if every purge id, need owner, and time-wake owner in the actual
//!   `ProjectionOutput` is the projected fact id. `enforce_owner_is_self` uses
//!   this helper for its success branch; diagnostic rejection strings remain
//!   ordinary Rust.
//! - Proven in production Rust today:
//!   `ContextOfferClaim::into_offer(claim, owner).owner == owner`.
//! - Proven in production Rust today:
//!   `ContextOfferClaim::into_offer(claim, owner) preserves role/scope/start/end/value`.
//! - Proven in production Rust today:
//!   `owned_offers_from_claims(claims, owner)` returns one offer per claim and
//!   every returned offer has `owner` plus the same role, scope, start key, end key, and offer value as the same-index claim.
//! - Proven in production Rust today:
//!   `context_set_from_projection_parts(needs, claims, owner)` carries needs
//!   unchanged and builds same-index owned offers from the claims.
//! - Proven in production Rust today:
//!   `clone_context_needs(needs)` preserves the need sequence, and
//!   `projection_output_context_set_parts(output, owner)` preserves output needs
//!   while building same-index owned offers from output claims.
//! - Proven in production Rust today:
//!   `projection_context_offers_match_claims(context, claims, owner)` accepts
//!   only if every final, normalized context offer matches some output claim
//!   after core stamps `owner` onto that claim's role, scope, range, and value.
//!   This is a final-output guard, not a semantic role proof.
//! - Proven in production Rust today:
//!   `projection_route_evidence(fact_id, effective_tag, route_tag,
//!   projector_info, storage_requirement)` returns `ProjectionRouteEvidence`
//!   with exactly those same field values. This proves route-evidence field
//!   stamping, not route selection.
//! - Proven in production Rust today:
//!   `selected_route_evidence(fact_id, effective_tag, stamp)` builds evidence
//!   from the selected route's proof-relevant `FactRouteStamp`; when the selected
//!   stamp tag equals the effective tag, the evidence route tag is that same
//!   effective tag and the projector info/storage requirement come from the
//!   stamp. This helper does not, by itself, prove metadata search or the
//!   projector function pointer call.
//! - Proven in production Rust today:
//!   `select_route_stamp(stamps, effective_tag)` searches the actual
//!   proof-relevant route metadata slice. If it returns `Some`, the selected
//!   stamp is the first stamp in the slice with `tag == effective_tag`; if it
//!   returns `None`, no stamp in the slice has that tag. This proves metadata
//!   search only; executable route/stamp alignment is enforced by runtime check
//!   and tests, not by Verus today.
//! - Proven in production Rust today:
//!   `routed_projection_from_selected_route(fact_id, effective_tag, stamp,
//!   output)` attaches that selected-stamp route evidence to the actual
//!   projector output value passed to it and preserves the output unchanged.
//!   This still does not prove executable route/stamp alignment or the
//!   projector function pointer call.
//! - Proven in production Rust today:
//!   `runtime_effects_with_storage_requirement(effects, requirement)` sets
//!   `RuntimeEffects.storage_requirement` to the selected route requirement
//!   while preserving emitted facts, priority facts, incoming facts and
//!   metadata, purges, row mutations, intents, local intents, and the version
//!   replay rebuild flag. `RuntimeEffects::with_storage_requirement` uses this
//!   verified production helper; the remaining route gap is proving the
//!   dispatcher applied it to the selected projector output.
//! - Proven in production Rust today:
//!   `runtime_effects_with_intent_row_mutation(effects, mutation)` appends
//!   exactly one `IntentRowMutation` to `RuntimeEffects.row_mutations` while
//!   preserving storage requirement, facts, priority facts, incoming facts and
//!   metadata, purges, intents, local intents, and the version replay rebuild
//!   flag. `RuntimeEffects::row_mutation` uses this verified production helper;
//!   table allowlist and raw-SQL confinement remain separate proof work.
//! - Proven in production Rust today:
//!   `ProjectedRowMutation::table` and `IntentRowMutation::table` return
//!   exactly the table embedded in the insert/delete mutation payload. This
//!   connects row validation's extracted table-name list to the actual row
//!   mutation payload, but it still does not prove raw-SQL confinement.
//! - Proven in production Rust today:
//!   `row_mutation_table_is_allowed(table, allowed)` accepts if and only if the
//!   table name occurs in the allowed table slice, and
//!   `row_mutation_tables_are_allowed(tables, allowed)` accepts if and only if
//!   every table in the extracted table-name list is allowed. Projection and
//!   intent row validation use this verified production helper for their
//!   success branch. Raw-SQL confinement remains separate proof work.
//! - Proven in production Rust today:
//!   `runtime_effects_with_version_replay_rebuild(effects)` sets
//!   `RuntimeEffects.version_replay_rebuild` while preserving storage
//!   requirement, facts, priority facts, incoming facts and metadata, purges,
//!   row mutations, intents, and local intents. Admission rules for what may
//!   coexist with that flag are proved separately.
//! - Proven in production Rust today:
//!   `version_replay_rebuild_shape_allowed(version_replay_rebuild, needs, offers,
//!   wakes)` accepts if and only if the projection is ordinary, or it is a
//!   version replay rebuild with no standing needs, offers, or time wakes.
//! - Proven in production Rust today:
//!   `version_replay_rebuild_shape_status(version_replay_rebuild, needs, offers,
//!   wakes)` returns accepted or standing-output exactly from that predicate,
//!   and `version_replay_rebuild_shape_status_allows_projection(status)` accepts
//!   if and only if the status is exactly
//!   `VERSION_REPLAY_REBUILD_SHAPE_ACCEPTED`.
//! - Proven in production Rust today:
//!   `version_replay_rebuild_projection_status(context, wakes, effects)`
//!   applies the same accepted/standing-output classification to the actual
//!   prepared projection shape consumed by
//!   `validate_version_replay_rebuild_projection_shape`.
//! - Proven in production Rust today:
//!   `version_replay_rebuild_projection_accepts(context, wakes, effects)`
//!   accepts if and only if the projection is ordinary, or it is a version
//!   replay rebuild whose prepared context and time wakes contain no standing
//!   output. `validate_version_replay_rebuild_projection_shape` uses this
//!   verified helper for its success branch.
//! - Proven in production Rust today:
//!   `version_replay_rebuild_effect_has_no_fact_or_intent_work(effects)`
//!   accepts if and only if a version replay rebuild effect is absent, or it
//!   is present with no emitted facts, priority facts, incoming facts, durable
//!   intents, or local intents. The runtime effect validator uses this verified
//!   helper for its success branch. Projected marker rows are still allowed
//!   through `ProjectionOutput::row_mutation` so a version-upgrade fact can
//!   record the surviving version row after the wipe/replay.
//! - Proven in production Rust today:
//!   `projection_output_with_projected_row_mutation(output, mutation)` appends
//!   exactly one `ProjectedRowMutation` to `ProjectionOutput::row_mutations`,
//!   preserves needs, offers, time wakes, retention, and effects, and leaves
//!   `RuntimeEffects.row_mutations` unchanged. `ProjectionOutput::row_mutation`
//!   uses this verified production helper, so that builder cannot smuggle
//!   intent-owned row mutations into projector output.
//! - Proven in production Rust today:
//!   `projection_effects_have_no_intent_row_mutations(effects)` accepts if and
//!   only if `RuntimeEffects.row_mutations` is empty.
//!   `validate_no_intent_row_mutations_from_projection` uses this verified
//!   helper for its success branch, so projector runtime effects cannot carry
//!   intent-owned row mutations past projection admission.
//! - Proven in production Rust today:
//!   `routed_offer_parts_accept(offer, producer_route)` accepts if and only if
//!   the offer owner equals the producer-route fact id, and
//!   `routed_offer_from_checked_parts` returns exactly those fields after that
//!   check. `matched_context_parts_accept(offer, payload, producer_route)`
//!   accepts if and only if the offer owner, payload fact id, and producer-route
//!   fact id all agree; `matched_context_from_checked_parts` returns exactly
//!   the checked need, routed offer, and payload while satisfying the local
//!   routed-provenance predicate. `RoutedOffer::new` and
//!   `MatchedContext::with_route` use these verified production helpers for
//!   their success branches; diagnostic strings remain ordinary Rust.
//! - Proven in production Rust today:
//!   `matched_context_owner_matches_payload(matched)` accepts if and only if
//!   the routed matched offer owner equals the loaded payload fact id, and
//!   `routed_offer_owner_matches_producer(routed_offer)` accepts if and only if
//!   the offer owner equals the producer route fact id. The combined helper
//!   `matched_context_has_routed_provenance(matched)` accepts if and only if
//!   both links hold for one matched context. `RoutedOffer::owner_matches_producer`
//!   and `MatchedContext::has_routed_provenance` expose the same production
//!   decisions to the context accessors, and `ProjectionContext` now exposes
//!   attested routed offers as the core-provenance surface. Runtime tests also
//!   exercise the SQL pending-context loader path that asks the dispatcher for
//!   producer route evidence while loading matched owner facts. This proves
//!   local core provenance only; route-local semantic offer theorems and the
//!   whole-loader theorem are still open.
//! - Proven in production Rust today:
//!   `matched_contexts_all_have_routed_provenance(matched)` accepts if and only if
//!   every matched context in the slice has the local routed-provenance link,
//!   and `prepare_projection` calls the corresponding `ProjectionContext`
//!   guard before dispatching to the projector. This blocks malformed local
//!   provenance from becoming projector input; it does not prove semantic
//!   offer validity or the whole SQL-loader construction theorem.
//! - Assumed only to call production code: the Verus contracts for the derived
//!   `ContextOfferClaim::clone` and `ContextNeed::clone` calls say clone
//!   preserves the whole value. The contracts for derived equality on `Role`,
//!   `FactScope`, `ContextKey`, and `ContextOfferValue` say equality returns
//!   value equality. These assumptions are Rust trait boundary helpers, not
//!   runtime theorems over projection.
//! - Refactored but not yet proved: `ProjectionDispatcher::dispatch_projection`
//!   now returns `RoutedProjection`, which is a plain `ProjectionOutput` plus
//!   router-stamped `ProjectionRouteEvidence` from the same route selection that
//!   calls the projector. `PreparedProjection` carries that route evidence.
//!   The route metadata search, field-stamping, selected-stamp helper, and
//!   routed-output constructor are verified, but the executable route/stamp
//!   alignment check, function-pointer call, and `PreparedProjection`
//!   correspondence theorem are not complete yet.
//! - Refactored but not yet proved: projected row output and intent row output
//!   now use separate Rust types, separate `RuntimeDescription` table lists, and
//!   separate DB apply helpers. This gives
//!   `projected_table_writes_are_project_fact_only` a realistic production-code
//!   target, but it is not the theorem yet; the proof must still tie
//!   validation, commit routing, and raw-SQL confinement to the split lists.
//!   The local guard rejecting intent row mutations from projector effects is
//!   proved.
//! - Not proven here today: every exported `theorem_*` runtime/core property.
//! - Not proven yet for offer finalization: `prepare_projection` call order.
//!   The unnormalized bridge from `ProjectionOutput` to `ContextSet` is proved,
//!   and the final normalized offers are checked by a verified production guard.
//! - Not proven yet for owner enforcement: the exported theorem tying
//!   `enforce_owner_is_self` `Result` wrapper diagnostic rejection branches and
//!   `prepare_projection` call order to the verified status and allow helpers.
//!   The accepted-output decision is proved.
//! - Not proven yet for version replay rebuild admission: the
//!   `validate_version_replay_rebuild_projection_shape` `Result` wrapper and
//!   `prepare_projection` call order around the verified prepared-shape accept
//!   helper.
//! - Punted for a later core proof model: the composition stubs that cross
//!   matcher construction, offer loading, route dispatch, projected-table
//!   write ownership, context replacement, and commit.
//! - First stubs to replace: the near-term core glue stubs over local projection
//!   output and offer-claim finalization.
//! - First core proof milestone: remove `external_body` from the core theorem
//!   surface before using projector proofs to claim high-level threat-model
//!   coverage.

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
        pub projected_table_epoch: int,
        pub offer_provenance_epoch: int,
        pub projected_table_writes_confined_to_project_fact: bool,
        pub authority_reads_confined_to_proven_views: bool,
        pub runtime_side_effects_deferred_until_commit: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecFact {
        pub id: int,
        pub fact_type: int,
        pub body_hash: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecFactRoute {
        pub fact_id: int,
        pub fact_type: int,
        pub route_id: int,
        pub registered_fact_type: int,
        pub dispatched_fact_id: int,
        pub dispatched_route_id: int,
        pub dispatched_by_project_fact: bool,
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
        pub loaded_fact_id: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecProjectionContext {
        pub graph_token: int,
        pub offer_provenance_epoch: int,
        pub offer_provenance_records_route: bool,
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
    pub struct SpecProjectionCommit {
        pub current_fact_id: int,
        pub lifecycle_settled_for_current_fact: bool,
        pub context_replaced_for_current_fact: bool,
        pub projected_rows_committed: bool,
        pub emitted_facts_committed: bool,
        pub emitted_intents_committed: bool,
        pub purges_committed: bool,
        pub all_effects_share_one_transaction: bool,
        pub no_authority_visible_before_commit: bool,
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

    pub open spec fn matched_offer_loads_owner_fact(
        matched: SpecMatchedContext,
    ) -> bool {
        matched.loaded_fact_id == matched.offer.owner
    }

    pub open spec fn projection_context_sound(
        ctx: SpecProjectionContext,
        graph: SpecPipelineGraph,
    ) -> bool {
        ctx.graph_token == graph.token
    }

    pub open spec fn projection_context_records_offer_provenance(
        ctx: SpecProjectionContext,
        graph: SpecPipelineGraph,
    ) -> bool {
        projection_context_sound(ctx, graph)
            && ctx.offer_provenance_epoch == graph.offer_provenance_epoch
            && ctx.offer_provenance_records_route
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

    pub open spec fn project_fact_dispatches_owner_route(
        fact: SpecFact,
        route: SpecFactRoute,
    ) -> bool {
        route.fact_id == fact.id
            && route.fact_type == fact.fact_type
            && route.registered_fact_type == fact.fact_type
            && route.dispatched_fact_id == fact.id
            && route.dispatched_route_id == route.route_id
            && route.dispatched_by_project_fact
    }

    pub open spec fn projected_table_writes_are_project_fact_only(
        before: SpecPipelineGraph,
        after: SpecPipelineGraph,
    ) -> bool {
        before.projected_table_epoch <= after.projected_table_epoch
            && after.projected_table_writes_confined_to_project_fact
    }

    pub open spec fn atomic_projection_commit_sound(
        before: SpecPipelineGraph,
        commit: SpecProjectionCommit,
        after: SpecPipelineGraph,
    ) -> bool {
        before.token == after.token
            && commit.lifecycle_settled_for_current_fact
            && commit.context_replaced_for_current_fact
            && commit.projected_rows_committed
            && commit.emitted_facts_committed
            && commit.emitted_intents_committed
            && commit.purges_committed
            && commit.all_effects_share_one_transaction
            && commit.no_authority_visible_before_commit
            && after.runtime_side_effects_deferred_until_commit
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
    // contracts only. They can describe cryptographic possession/binding, but
    // never decide protocol authority.
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
    // they cross matcher construction, offer-owner payload loading,
    // offer-provenance recording, route dispatch, projected-table write
    // ownership, context replacement, and SQLite transaction boundaries. They
    // are explicit trusted assumptions until real core proofs replace the
    // external bodies.
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

    // Deferred trusted core theorem: offer provenance records in projection
    // context come from route-backed projection output. This proves no protocol
    // authority or semantic offer validity; consumers still need projector
    // theorems for role meaning.
    #[verifier::external_body]
    pub proof fn theorem_projection_context_records_offer_provenance(
        ctx: SpecProjectionContext,
        graph: SpecPipelineGraph,
    )
        ensures projection_context_records_offer_provenance(ctx, graph)
    {
    }

    // Deferred trusted core theorem: matched offer loading resolves the owner fact.
    #[verifier::external_body]
    pub proof fn theorem_matched_offer_loads_owner_fact(
        matched: SpecMatchedContext,
    )
        ensures matched_offer_loads_owner_fact(matched)
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

    // Deferred trusted core theorem: project_fact dispatches an owner fact
    // through the route registered for that fact type before committing that
    // route's output.
    #[verifier::external_body]
    pub proof fn theorem_project_fact_dispatches_owner_route(
        fact: SpecFact,
        route: SpecFactRoute,
    )
        ensures project_fact_dispatches_owner_route(fact, route)
    {
    }

    // Deferred trusted core theorem: projected tables and projection-owned
    // certificate tables are mutated only through the project_fact commit path.
    #[verifier::external_body]
    pub proof fn theorem_projected_table_writes_are_project_fact_only(
        before: SpecPipelineGraph,
        after: SpecPipelineGraph,
    )
        ensures projected_table_writes_are_project_fact_only(before, after)
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
        commit: SpecProjectionCommit,
        after: SpecPipelineGraph,
    )
        ensures atomic_projection_commit_sound(before, commit, after)
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
