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
src/core/proofs.rs
```

For this phase, proof code lives only in `proofs.rs` files: the centralized
core theorem surface is `src/core/proofs.rs`, and fact-family or producer
certificates live in their existing `src/protocol/<scope>/<family>/proofs.rs`
files. Do not add proof directories, static-analysis proof fixtures, or
parallel source files for proof work in this phase.

Normal Rust builds may compile executable proof predicates while the Verus
runner is absent, but they must be ordinary checks over runtime values. Once
Verus-only syntax lands, that syntax must be behind the same dedicated Verus
gate used by the rest of the proof surface:

```rust
#[cfg(feature = "verus-proof")]
pub mod proofs;
```

Projector proof modules may import theorem functions from this module. They
must not call `assume(...)` directly for core behavior. The only direct
assumptions for core behavior belong inside the theorem stubs in
`src/core/proofs.rs`.

## Assumed Core Theorems

The first assumed theorem surface should be small and protocol-neutral:

| Predicate or theorem | Assumed guarantee | Explicit non-guarantee |
| --- | --- | --- |
| `projection_context_sound(ctx, graph)` | The projection context was assembled from standing needs, matched offers, and offer-owner payloads in the graph. | Does not prove any role-specific authority or semantic validity. |
| `matched_payloads_are_offer_owner_facts(ctx, graph)` | A matched payload exposed to a projector is the fact bytes owned by the matched offer owner. | Does not prove the consuming projector may trust the payload's protocol meaning without cross-checks. |
| `matcher_preserves_role_scope_selector(need, matched)` | A match preserves requested role, scope, owner boundaries, and exact or range selector relation. | Does not prove that the role's producer emitted semantically valid evidence. |
| `context_replacement_preserves_owner_boundaries(before, after, owner)` | Reprojection replaces context only for the current owner and does not rewrite unrelated owners. | Does not prove the replacement context is sufficient for any protocol output. |
| `purges_are_self_only(output, current_fact_id)` | Projector output cannot request a purge for any fact other than the fact currently being projected. | Does not prove the self-purge is authorized by deletion, close, retirement, expiry, or retention context. |
| `projection_output_owners_are_self(output, current_fact_id)` | Projector-emitted needs, offers, time wakes, and purges are owned by the current projected fact. | Does not prove emitted rows, offers, or intents are semantically valid. |
| `no_materialized_output(output)` | A waiting projector output contains no rows, offers, intents, facts, time wakes, or purges. | Does not prove the waiting needs are the right protocol needs. |
| `atomic_projection_commit_sound(before, output, after)` | Context replacement, rows, queued intents, facts, sync-share contributions, and accepted purges commit atomically. | Does not prove those effects satisfy a fact-family predicate. |

The theorem names can be adjusted once the Verus runner lands, but the split
must remain: core theorems establish plumbing soundness, and projector theorems
establish protocol meaning.

## Stub Shape

The exact Verus attribute syntax should follow the runner when it is added, but
the proof shape should look like this:

```rust
#[cfg(feature = "verus-proof")]
pub mod proofs {
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
2. Import core theorem functions from `src/core/proofs.rs`; do not create
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
7. Do not rely on static source analysis as proof. Tests that inspect source
   text may guard layout policy, but proof claims must be predicates or theorems
   over the executable values the runtime actually passes between core,
   projectors, and handlers.
8. Do not cheat by placing protocol conclusions in core. A core theorem may be
   difficult to prove over SQLite-backed projection machinery, but it must be a
   logically coherent theorem about core-owned mechanics. If a theorem would
   need to know that an admin, endpoint, receipt, deletion, key wrap, content
   signer, or workspace is semantically valid, it belongs in the owning
   protocol proof instead.
9. Foundational axioms may assume SQLite transactions, cryptographic
   primitives, BLAKE3 content addressing, byte parsers, and other substrate
   tools satisfy their advertised contracts. Those axioms should be named at the
   boundary where they are used and should not smuggle in protocol authority.
10. Commit the completed work on that same worktree branch before handoff or
    review.

## Threat Model Checklist

Work through `THREAT_MODEL.md` in order. A checked item means this strategy has
at least one executable projector proof slice for that invariant; it does not
mean the full cross-projector invariant is complete unless the note says so.

- [x] TM-M1 root workspace slice: `auth::workspace` proves a workspace row,
  `auth_workspace` offer, and sync-share intent materialize only after matching
  signature evidence and local identity-scoped invite acceptance. Remaining:
  user, admin, invite, endpoint, content-signer, recipient-key, and connection
  authority projectors.
- [x] TM-M2 workspace carrier boundary slice: workspace proof consumes
  `signature_proof` and local `auth_workspace_accepted` predicates; carrier
  facts alone do not satisfy the projector's authority needs. Remaining:
  connection receipt/frame projectors and sync carrier projectors.
- [x] TM-M3 root workspace scope slice: workspace proof keys the row, offer,
  signature need, accepted need, and sync-share workspace id to the projected
  workspace fact id. Remaining: all cross-workspace auth, key, content, and
  connection projectors.
- [ ] TM-M4: prove admin/user/device/invite issuer escalation paths in
  `auth::admin`, `auth::user_invite`, `auth::device_invite`,
  `auth::endpoint`, and `auth::endpoint_shared`.
- [ ] TM-M5: prove removal, recipient-key supersession, frontier retirement,
  and retention-floor gates before future shareability or key-wrap creation.
- [ ] TM-C1: prove encrypted content projectors and connection frames never
  expose plaintext without local key material.
- [x] TM-C2 workspace local-bootstrap slice: workspace sync-share proof rejects
  the local `invite_accepted` payload as sync context. Remaining: all local
  secret fact families and connection sendability filters.
- [ ] TM-C3: prove sync shareability, dependency closure, range request, and
  connection send paths stay inside authorized non-local workspace visibility.
- [ ] TM-C4: prove key-wrap creation validates recipient, source secret,
  signer, frontier, source coordinate, workspace, and retirement state.
- [ ] TM-C5: prove message, reaction, file, and file-slice opening requires
  content authority plus local secret coverage and deletion/retirement checks.
- [ ] TM-I1: prove content authorship is signer-bound for message, reaction,
  file, file-slice, deletion, and retention-policy rows.
- [ ] TM-I2: prove admin authority does not imply content-signing authority.
- [ ] TM-I3: prove replayed facts cannot alter accepted sender, body, deletion
  target, key coordinate, or workspace.
- [x] TM-I4 workspace evidence slice: workspace proof treats signature and
  invite-accepted facts as evidence that must satisfy producer predicates before
  root workspace materialization. Remaining: connection receipts, observations,
  requests, connections, and frame projectors.
- [ ] TM-D1: prove deletion facts publish purge context only for authorized
  exact targets and target projectors self-purge only themselves.
- [ ] TM-D2: prove target deletion removes or retracts user-visible rows and
  shareability before live send paths can expose purged bytes.
- [ ] TM-D3: prove root and recipient private material retirement removes
  deleted-content derivation paths while preserving surviving content coverage.
- [ ] TM-D4: prove replayed carrier data cannot resurrect locally deleted
  content after target-owned deletion commits.
- [ ] TM-D5: compose content deletion, root retirement, retained-node coverage,
  sync retraction, and local/private send rejection against deletion collusion.
- [ ] TM-D6: prove post-retirement key healing wraps only surviving path nodes,
  not retired roots, deleted leaves, or superseded recipient keys.

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
