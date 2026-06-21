# Verus Proof Strategy

This document defines the first poc-10 Verus strategy for proving strong
invariants from the threat model over the actual Rust codebase. The eventual
goal is a whole-codebase proof of every threat-model invariant, not a proof of a
parallel Verus model. The initial proof boundary proves small protocol-neutral
core glue where possible and keeps the remaining core guarantees as centralized
trusted theorems. Projector proofs consume those theorems through one explicit
core proof module instead of scattering local assumptions through protocol proof
files.

The near-term goal is to prove the small protocol-neutral core properties that
the offer-claim model makes tractable, then use them as composition glue for
projector proofs against authority, deletion, shareability, and transport
invariants. Core properties that still require matcher, SQLite, or commit
modeling remain visible, named, and replaceable trusted stubs. A deferred core
proof is still a claim about the real core Rust behavior. It is not permission
to prove an unrelated model and count that as threat-model coverage.

## Scope

The first proof phase covers projector and handler-facing security invariants:
which rows, context offer claims, deferred intents, sync-share contributions,
and self-purges may be emitted from valid facts and valid matched context. It
also covers the small core properties needed to compose those proofs, starting
with offer-claim finalization, owner-bearing output ownership, self-only purges,
parked missing-context output, and missing-payload lookup.

Core matching, offer-owner payload loading, context replacement, and atomic
commit proofs are still deferred. Those trusted theorem stubs must live in one
module and must be documented as trusted stubs until real core proofs replace
them. Every trusted core theorem must be a realistic statement about actual core
Rust behavior or a foundational substrate contract. If the theorem would not be
a cogent future proof obligation over core code, do not add it.

Projector proofs remain responsible for protocol meaning. Core assumptions never
prove that an admin is valid, an endpoint may sign content, a deletion is
authorized, a receipt grants authority, or a fact is sendable. They prove only
protocol-neutral plumbing properties that projectors can use as evidence.

## Core Proof Module

Use a dedicated proof module for the core theorem surface:

```text
src/core/proofs.rs
```

For this phase, proof code lives only in `proofs.rs` files: the centralized
core theorem surface is `src/core/proofs.rs`, and fact-family or producer
theorem modules live in their existing `src/protocol/<scope>/<family>/proofs.rs`
files. Do not add proof directories, static-analysis proof fixtures, parallel
source files, or normal Rust proof-certificate APIs for proof work in this
phase.

Runtime predicates, certificate structs, unit tests, and static source analysis
do not count as proof coverage. Do not add normal Rust `theorem_*` shims or
certificate structs in `proofs.rs`; threat-model checklist coverage requires
Verus proof functions that verify with the Verus runner.

Verus-only proof code is gated with `cfg(verus_keep_ghost)` so normal Rust
builds continue to compile without a Verus dependency:

```rust
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
    // spec and proof declarations
}
```

Projector proof modules may import theorem functions from this module. They
must not call `assume(...)` directly for core behavior. The only direct
assumptions for core behavior belong inside the theorem stubs in
`src/core/proofs.rs`.

## Core Theorem Surface

Keep the core theorem surface small and protocol-neutral. These names are proof
interfaces, not proof coverage by themselves. Each entry must carry a status:
`prove now` for neutral Rust code that the current refactor makes tractable,
`trusted until core model` for SQLite, matcher, or commit machinery that still
needs a real core proof model, or `foundational assumption` for substrate
contracts such as crypto, parsers, content addressing, and transactions.

| Predicate or theorem | Status | Guarantee | Explicit non-guarantee |
| --- | --- | --- | --- |
| `offer_claim_finalizes_to_projected_owner(claim, offer, current_fact_id)` | prove now | `ProjectionOutput::context_set(current_fact_id)` stores every emitted `ContextOfferClaim` as a `ContextOffer` with `owner = current_fact_id` and unchanged role, scope, start key, and end key. | Does not prove the claim is semantically valid for its role. |
| `projection_output_owner_bearing_effects_are_self(output, current_fact_id)` | prove now | Owner-bearing projector outputs such as needs, time wakes, and purges are owned by the current projected fact. Offer claims are ownerless until core finalization. | Does not prove emitted rows, offer claims, or intents are semantically valid. |
| `purges_are_self_only(output, current_fact_id)` | prove now | Projector output cannot request a purge for any fact other than the fact currently being projected. | Does not prove the self-purge is authorized by deletion, close, retirement, expiry, or retention context. |
| `parked_output_for_missing_need(output, need)` | prove now | The actual `ProjectionOutput::new().need(need)` waiting path contains exactly the stable need and no materialized rows, offer claims, intents, facts, time wakes, or purges. | Does not prove the missing need is the right protocol dependency. |
| `projection_context_lacks_payload_for_need(ctx, need)` | prove now after Rust-view bridge | The actual `ProjectionContext::payload_for(&need)` path returned `None` for that need. | Does not prove the projector chose the right need or that waiting is semantically sufficient. |
| `projection_context_sound(ctx, graph)` | trusted until core model | The actual `ProjectionContext` was assembled from standing needs, matched offers, and offer-owner payloads in the graph. | Does not prove any role-specific authority or semantic validity. |
| `matched_payloads_are_offer_owner_facts(matched)` | trusted until core model | A matched payload exposed to a projector is the fact bytes owned by the matched offer owner. | Does not prove the consuming projector may trust the payload's protocol meaning without cross-checks. |
| `matcher_preserves_role_scope_selector(need, matched)` | trusted until core model | A match preserves requested role, scope, owner boundaries, and exact or range selector relation. | Does not prove that the role's producer emitted semantically valid evidence. |
| `context_replacement_preserves_owner_boundaries(before, after, owner)` | trusted until core model | Reprojection replaces context only for the current owner and does not rewrite unrelated owners. | Does not prove the replacement context is sufficient for any protocol output. |
| `atomic_projection_commit_sound(before, output, after)` | trusted until core model | Context replacement, rows, queued intents, facts, sync-share contributions, and accepted purges commit atomically. | Does not prove those effects satisfy a fact-family predicate. |

The status can move only when the theorem verifies with Verus against the actual
Rust path or a verified Rust-code view. Core theorems establish plumbing
soundness. Projector theorems establish protocol meaning.

## Foundational Crypto Theorems

Cryptographic theorem stubs are allowed only for primitive-level facts. They
may state that an advertised verifier result binds a public key, message, and
signature according to the primitive's contract. They must not state protocol
authority.

Allowed shape:

```text
theorem_ed25519_verify_binds(evidence)
  requires evidence.verifier_accepts
  ensures ed25519_signature_binds(evidence)
```

Forbidden shape:

```text
ed25519 verifies -> signer is a workspace admin
ed25519 verifies -> content may be admitted
ed25519 verifies -> fact is sync-shareable
```

Protocol modules must consume crypto binding as one input and still prove the
workspace, target, signer, endpoint, content-author, deletion, or key-coordinate
relationship required by the threat model.

## Verification Command

Proof modules must verify with Verus before a checklist item can move out of
`Pending`. The test suite invokes the installed verifier with this shape:

```text
VERUS=/path/to/verus cargo test verus_projector_proof_modules_verify
```

The current workspace default is:

```text
/home/holmes/verus-install/verus-x86-linux/verus --crate-type=lib --cfg verus_keep_ghost src/protocol/auth/workspace/proofs.rs
```

## Stub Shape

Trusted core stubs use Verus `#[verifier::external_body]` theorem functions.
They are the only place where this phase may assume unproved core mechanics:

```rust
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
    pub mod verus_model {
        use vstd::prelude::*;

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
            matched: SpecMatchedContext,
        ) -> bool;

        pub open spec fn matcher_preserves_role_scope_selector(
            need: SpecContextNeed,
            matched: SpecMatchedContext,
        ) -> bool;

        pub open spec fn projection_context_lacks_payload_for_need(
            ctx: SpecProjectionContext,
            need: SpecContextNeed,
        ) -> bool;

        pub open spec fn parked_output_for_missing_need(
            output: SpecProjectionOutput,
            need: SpecContextNeed,
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
            matched: SpecMatchedContext,
        )
            ensures matched_payloads_are_offer_owner_facts(matched)
        {
        }
    }
}
```

Every trusted theorem stub must have a name beginning with `theorem_`, an
`ensures` clause that states the core property being assumed, and a short
comment naming it as a temporary trusted core assumption. Stub bodies should not
include protocol predicates. Do not add a theorem that asserts
`no_materialized_output(output)` for an arbitrary output. A missing-context
theorem must be tied to the actual `ProjectionContext::payload_for(&need)`
absence and the actual parked output shape, such as
`ProjectionOutput::new().need(need)`. Entries marked `prove now` should be
replaced with real Verus proofs before they are used to claim threat-model
coverage.

## Projector Proof Contract

Projector proofs should consume core theorems as proof functions and then prove
the fact-family predicate for each output.

The security bar for threat-model coverage is the only-if direction over the
actual Rust projector code path:

```text
Rust projector function or verified Rust-code relation(fact, context, output)
+ output materializes authority offer claims, rows, shareability, plaintext,
  key material, or purge effects
  -> the required authority evidence existed
     and the output is exactly the allowed canonical shape
     and no forbidden effect exists
```

Full iff theorems are useful when the spec can characterize the exact Rust
projector relation:

```text
projector materializes proof-relevant output
  <-> required authority evidence exists and canonical output is emitted
```

The `->` half is mandatory for threat-model safety. The `<-` half is
completeness/liveness and should not be counted as security coverage unless the
only-if half is also proved.

For a producer projector:

```text
projector emits ContextOfferClaim(role = R, selector = K)
  -> valid_R_offer_claim(claim, owner_fact, graph)
```

For core offer finalization:

```text
prepare_projection(fact = F, output.offers = claims)
  -> committed ContextOffer for each claim has owner = F.id
     and copies claim.role, claim.scope, claim.start_key, claim.end_key exactly
```

For core matching:

```text
theorem_projection_context_sound(ctx, graph)
theorem_matched_payloads_are_offer_owner_facts(matched)
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

The producer theorem proves ownerless claims. The consumer theorem reasons from
matched, finalized `ContextOffer`s after core has attached the projected fact id
as owner.

The consumer step is where threat-model invariants become strong. A matched
receipt remains only a receipt until the receiving projector proves the
relationship it needs. A matched admin offer remains only an admin certificate
until the consuming projector proves the workspace, signer, and target
relationship for its own output.

Model-only projector relations are not proof work for this repo. Do not add or
keep a disconnected Verus model of a projector as a substitute for proving the
actual Rust code. Spec and ghost helper types are allowed only as abstractions
of actual Rust values or functions, and only when they are tied to those values
by a Rust-code correspondence theorem or a named trusted boundary theorem that
precisely describes that code path. Any theorem over only `Spec*` data is a
helper lemma, not a projector proof.

## Induction Shape

Once one or more projector theorems exist, runtime-level reasoning can use this
shape:

```text
standing_context_sound(before)
+ core theorem for projection context construction
+ projector theorem for the current fact
+ core theorem for context replacement and atomic commit
= standing_context_sound(after)
  and every committed row, finalized authority offer, sync-share contribution,
  deferred intent, and purge has a valid derivation
```

The induction initially depends on trusted core theorems. That is acceptable
only because the assumptions are centralized and named. Replacing a trusted core
stub with a real core proof must not require projector theorem rewrites unless
the assumed statement was too broad.

## Current Execution Plan

1. Finish the universal offer-claim runtime boundary. Projectors emit
   `ContextOfferClaim`s; core finalizes them into stored `ContextOffer`s with
   the projected fact id as owner. This is required before any producer
   projector theorem can be trusted as an offer certificate.
2. Prove the tractable core boundary first, not as threat-model coverage but as
   composition glue: offer-claim finalization, owner-bearing output ownership,
   self-only purge requests, parked missing-context output, and missing-payload
   lookup. These are protocol-neutral and should not remain trusted stubs after
   the Rust-view bridge exists.
3. Leave matcher graph construction, offer-owner payload loading, context
   replacement, and atomic SQLite commit as centralized trusted core theorems
   until their real core proof model exists.
4. Start projector coverage with the smallest high-value authority producer:
   the root workspace or signature-proof path, depending on which has the
   cleanest Rust-code view. The proof must show dangerous output implies
   decoded fact bytes, required matched context, primitive crypto binding, and
   exact canonical offer-claim or row output.
5. Compose outward through the threat model: workspace authority, admin/user
   delegation, endpoint/content signer authority, connection receipts,
   shareability, deletion/self-purge, and key-material retirement. Checklist
   items stay unchecked until the composed only-if theorem verifies.

## Review Rules

Use these rules when adding projector proofs under this strategy:

1. Add or update module-local semantic predicates for every protected output.
2. Proofs must target actual Rust code. The top-level projector theorem must
   quantify over real Rust inputs and outputs, or over a verified view extracted
   from those inputs and outputs by an explicit correspondence theorem.
   Standalone `Spec*` duplicates are forbidden as proof targets.
3. Import core theorem functions from `src/core/proofs.rs`; do not create
   local copies of core assumptions.
4. Keep protocol authority in the projector proof. Core theorems may establish
   payload origin and selector matching, not role meaning.
5. Make missing-context and mismatched-context cases explicit: missing context
   parks with stable needs, and mismatched context rejects or emits no
   materialized output.
6. Pair runtime changes with realistic Rust tests, and pair proof changes with
   a Verus verification run. A Rust test can prevent regressions, but it cannot
   move a proof checklist item by itself.
7. Prove the safety direction before claiming coverage: materialized
   proof-relevant output implies required authority evidence and exact allowed
   effects.
8. Use iff only for exact projector characterization. Never let the easy
   completeness direction substitute for the only-if safety direction.
9. Constructor lemmas are not checklist coverage by themselves. A theorem that
   starts with valid inputs and a constructed output may support another proof,
   but the checklist requires a dangerous-output-implies-authority theorem.
10. Document any additional assumptions, especially cryptographic primitive
   soundness and byte-canonicalization assumptions.
11. Keep crypto stubs primitive-level. They may prove byte/key/signature binding,
   not workspace authority, content authority, deletion authority, or
   shareability.
12. Do not rely on static source analysis as proof. Tests that inspect source
   text may guard layout policy, but proof claims must be predicates or theorems
   over the executable values the runtime actually passes between core,
   projectors, and handlers.
13. Do not cheat by placing protocol conclusions in core. A core theorem may be
   difficult to prove over SQLite-backed projection machinery, but it must be a
   logically coherent theorem about core-owned mechanics. If a theorem would
   need to know that an admin, endpoint, receipt, deletion, key wrap, content
   signer, or workspace is semantically valid, it belongs in the owning
   protocol proof instead.
14. Foundational axioms may assume SQLite transactions, cryptographic
   primitives, BLAKE3 content addressing, byte parsers, and other substrate
   tools satisfy their advertised contracts. Those axioms should be named at the
   boundary where they are used and should not smuggle in protocol authority.
15. Every proof change must include a walkthrough before handoff. The
    walkthrough must name the theorem shape, trusted stubs or assumptions,
    proof steps, what the theorem really proves, and the remaining gaps against
    the threat model.
16. Commit the completed work on that same worktree branch before handoff or
    review.

## Threat Model Checklist

Work through `THREAT_MODEL.md` in order. A checked item requires a Verus
only-if safety theorem over the actual Rust code path, or over a verified view
that has an explicit correspondence theorem back to that Rust code path. A
named trusted theorem may stand for foundational core, SQLite, parser, or
crypto behavior, but it must precisely describe that boundary and must not
encode protocol authority. Disconnected model-level slices are not accepted and
should be removed or replaced with Rust-backed proof work before any checklist
item is claimed.

- [ ] TM-M1 root workspace slice: prove that actual `WorkspaceProjector`
  materialization implies decoded global workspace evidence, valid signature
  evidence, local identity-scoped invite acceptance, and canonical row/offer/
  sync-share output. Blocked until a theorem over the Rust projector inputs and
  outputs exists; then cover user, admin, invite, endpoint, content-signer,
  recipient-key, and connection authority projectors.
- [ ] TM-M2 workspace carrier boundary slice: prove over the Rust workspace
  projector path that signature proof and local accepted-invite evidence are
  required, and carrier facts alone cannot satisfy authority needs. Blocked
  until Rust-code correspondence exists; then compose with connection
  receipt/frame projectors and sync carrier projectors.
- [ ] TM-M3 root workspace scope slice: prove over the Rust workspace projector
  path that the row, offer, signature need, accepted need, and sync-share
  workspace id are all keyed to the projected workspace fact id. Blocked until
  Rust-code correspondence exists; then compose with cross-workspace auth, key,
  content, and connection projectors.
- [ ] TM-M4: prove admin/user/device/invite issuer escalation paths in
  `auth::admin`, `auth::user_invite`, `auth::device_invite`,
  `auth::endpoint`, and `auth::endpoint_shared`.
- [ ] TM-M5: prove removal, recipient-key supersession, frontier retirement,
  and retention-floor gates before future shareability or key-wrap creation.
- [ ] TM-C1: prove encrypted content projectors and connection frames never
  expose plaintext without local key material.
- [ ] TM-C2 workspace local-bootstrap slice: prove over the Rust workspace
  projector path that sync-share output cannot be justified by the local
  `invite_accepted` payload. Blocked until Rust-code correspondence exists; then
  cover all local secret fact families and connection sendability filters.
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
- [ ] TM-I4 workspace evidence slice: prove over the Rust workspace projector
  path that signature and invite-accepted facts must satisfy producer predicates
  before root workspace materialization. Blocked until Rust-code correspondence
  exists; then compose with connection receipts, observations, requests,
  connections, and frame projectors.
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
