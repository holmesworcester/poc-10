# Verus Proof Strategy

This document defines the first poc-10 Verus strategy for proving strong
projector invariants from the threat model while leaving core proof work out of
scope. The initial proof boundary treats core guarantees as trusted theorems.
Projector proofs consume those theorems through one explicit core proof module
instead of scattering local assumptions through protocol proof files.

The goal is not to prove core yet. The goal is to let projector proofs make
real progress against authority, deletion, shareability, and transport
invariants while keeping every unproved core claim visible, named, and
replaceable.

## Scope

The first proof phase covers projector and handler-facing security invariants:
which rows, context offers, deferred intents, sync-share contributions, and
self-purges may be emitted from valid facts and valid matched context.

Core proof bodies are out of scope for this phase. Core matching, context
replacement, purge enforcement, and atomic commit properties are assumed true as
theorem-shaped proof functions. Those assumptions must live in one module and
must be documented as trusted stubs until core proofs replace them.

Projector proofs remain responsible for protocol meaning. Core assumptions never
prove that an admin is valid, an endpoint may sign content, a deletion is
authorized, a receipt grants authority, or a fact is sendable. They prove only
protocol-neutral plumbing properties that projectors can use as evidence.

## Trusted Core Module

Use a dedicated proof module for the temporary trust boundary:

```text
src/core/assumed_proof.rs
```

If the crate already exposes a proof facade, `src/core/proof.rs` may re-export
this module, but the trusted bodies should stay in `assumed_proof.rs` while they
are assumptions. The name is intentionally blunt: reviewers should not mistake
these stubs for completed core proofs.

Normal Rust builds must not compile proof modules. The module should be behind
the same dedicated Verus gate used by the rest of the proof surface:

```rust
#[cfg(feature = "verus-proof")]
pub mod assumed_proof;
```

Projector proof modules may import theorem functions from this module. They
must not call `assume(...)` directly for core behavior. The only direct
assumptions for core behavior belong inside the theorem stubs in
`src/core/assumed_proof.rs`.

## Assumed Core Theorems

The first assumed theorem surface should be small and protocol-neutral:

| Predicate or theorem | Assumed guarantee | Explicit non-guarantee |
| --- | --- | --- |
| `projection_context_sound(ctx, graph)` | The projection context was assembled from standing needs, matched offers, and offer-owner payloads in the graph. | Does not prove any role-specific authority or semantic validity. |
| `matched_payloads_are_offer_owner_facts(ctx, graph)` | A matched payload exposed to a projector is the fact bytes owned by the matched offer owner. | Does not prove the consuming projector may trust the payload's protocol meaning without cross-checks. |
| `matcher_preserves_role_scope_selector(need, matched)` | A match preserves requested role, scope, owner boundaries, and exact or range selector relation. | Does not prove that the role's producer emitted semantically valid evidence. |
| `context_replacement_preserves_owner_boundaries(before, after, owner)` | Reprojection replaces context only for the current owner and does not rewrite unrelated owners. | Does not prove the replacement context is sufficient for any protocol output. |
| `purges_are_self_only(output, current_fact_id)` | Projector output cannot request a purge for any fact other than the fact currently being projected. | Does not prove the self-purge is authorized by deletion, close, retirement, expiry, or retention context. |
| `atomic_projection_commit_sound(before, output, after)` | Context replacement, rows, queued intents, facts, sync-share contributions, and accepted purges commit atomically. | Does not prove those effects satisfy a fact-family predicate. |

The theorem names can be adjusted once the Verus runner lands, but the split
must remain: core theorems establish plumbing soundness, and projector theorems
establish protocol meaning.

## Stub Shape

The exact Verus attribute syntax should follow the runner when it is added, but
the proof shape should look like this:

```rust
#[cfg(feature = "verus-proof")]
pub mod assumed_proof {
    use vstd::prelude::*;

    verus! {
        pub struct SpecPipelineGraph { /* proof-only graph model */ }
        pub struct SpecProjectionContext { /* proof-only context model */ }
        pub struct SpecContextNeed { /* proof-only need model */ }
        pub struct SpecMatchedContext { /* proof-only match model */ }
        pub struct SpecProjectionOutput { /* proof-only output model */ }
        pub struct SpecFactId { /* proof-only fact id model */ }

        pub open spec fn projection_context_sound(
            ctx: SpecProjectionContext,
            graph: SpecPipelineGraph,
        ) -> bool;

        pub open spec fn matched_payloads_are_offer_owner_facts(
            ctx: SpecProjectionContext,
            graph: SpecPipelineGraph,
        ) -> bool;

        pub open spec fn matcher_preserves_role_scope_selector(
            need: SpecContextNeed,
            matched: SpecMatchedContext,
        ) -> bool;

        pub open spec fn context_replacement_preserves_owner_boundaries(
            before: SpecPipelineGraph,
            after: SpecPipelineGraph,
            owner: SpecFactId,
        ) -> bool;

        pub open spec fn purges_are_self_only(
            output: SpecProjectionOutput,
            current_fact_id: SpecFactId,
        ) -> bool;

        pub open spec fn atomic_projection_commit_sound(
            before: SpecPipelineGraph,
            output: SpecProjectionOutput,
            after: SpecPipelineGraph,
        ) -> bool;

        #[verifier::external_body]
        pub proof fn theorem_projection_context_sound(
            ctx: SpecProjectionContext,
            graph: SpecPipelineGraph,
        )
            ensures projection_context_sound(ctx, graph)
        {
        }

        #[verifier::external_body]
        pub proof fn theorem_matched_payloads_are_offer_owner_facts(
            ctx: SpecProjectionContext,
            graph: SpecPipelineGraph,
        )
            ensures matched_payloads_are_offer_owner_facts(ctx, graph)
        {
        }
    }
}
```

Every trusted theorem stub must have a name beginning with `theorem_`, an
`ensures` clause that states the core property being assumed, and a short
comment naming it as a temporary trusted core assumption. Stub bodies should not
include protocol predicates.

## Projector Proof Contract

Projector proofs should consume core theorems as certificates and then prove
the fact-family predicate for each output.

For a producer projector:

```text
projector emits Offer(role = R, owner = F)
  -> valid_R_offer(offer, owner_fact, graph)
```

For core matching:

```text
theorem_projection_context_sound(ctx, graph)
theorem_matched_payloads_are_offer_owner_facts(ctx, graph)
theorem_matcher_preserves_role_scope_selector(need, matched)
  -> projector may know the matched payload source and selector relation
```

For a consumer projector:

```text
projection_context_sound(ctx, graph)
valid_R_offer(offer, payload, graph)
consumer validates type, workspace, signer, endpoint, key coordinate,
receipt path, deletion coordinate, or protocol-specific relation
  -> emitted row, offer, intent, sync-share contribution, or self-purge
     satisfies the target predicate
```

The consumer step is where threat-model invariants become strong. A matched
receipt remains only a receipt until the receiving projector proves the
relationship it needs. A matched admin offer remains only an admin certificate
until the consuming projector proves the workspace, signer, and target
relationship for its own output.

## Induction Shape

Once one or more projector theorems exist, runtime-level reasoning can use this
shape:

```text
standing_context_sound(before)
+ assumed core theorem for projection context construction
+ projector theorem for the current fact
+ assumed core theorem for context replacement and atomic commit
= standing_context_sound(after)
  and every committed row, authority offer, sync-share contribution,
  deferred intent, and purge has a valid derivation
```

The induction initially depends on trusted core theorems. That is acceptable
only because the assumptions are centralized and named. Replacing a trusted core
stub with a real core proof must not require projector theorem rewrites unless
the assumed statement was too broad.

## Review Rules

Use these rules when adding projector proofs under this strategy:

1. Add or update module-local semantic predicates for every protected output.
2. Import core theorem functions from `src/core/assumed_proof.rs`; do not create
   local copies of core assumptions.
3. Keep protocol authority in the projector proof. Core theorems may establish
   payload origin and selector matching, not role meaning.
4. Make missing-context and mismatched-context cases explicit: missing context
   parks with stable needs, and mismatched context rejects or emits no
   materialized output.
5. Pair runtime changes with realistic Rust tests. Pure proof-only changes run
   the Verus target once the runner exists.
6. Document any additional assumptions, especially cryptographic primitive
   soundness and byte-canonicalization assumptions.

## Migration To Real Core Proofs

When core proof work begins, replace the trusted theorem bodies in place:

```text
trusted theorem stub
  -> real proof over matcher, context replacement, purge, or commit model
  -> same theorem name and postcondition
  -> projector proofs continue to call the theorem
```

If a core theorem turns out to be too strong, narrow the theorem and update the
projector proofs that were relying on the extra claim. Do not preserve an
overbroad theorem just to avoid proof churn.
