# Verus Proof Plan

This plan describes how poc-10 can use Verus to prove meaningful projection and
context invariants without turning context matchers into hidden authority logic.

## Goal

The target invariant is:

```text
Every materialized row, emitted authority offer, and emitted deferred intent has
a derivation from valid facts and valid matched context.
```

For projectors this means proving more than shape preservation. The useful proof
is that a projector cannot emit an offer, row intent, or deferred intent unless
the module-specific authority predicate for that output is satisfied.

For context matching this means proving less than authority. A matcher only
finds candidate context. The consuming projector still proves fact type, scope,
workspace, signer, endpoint, role, and protocol meaning before producing output.

## File Layout

Verus proof code should live close to the code whose invariant it proves, with a
small shared proof surface in core.

```text
src/core/proof.rs
src/core/context/proof.rs            # if context grows into a directory
src/core/matchers/proof.rs           # if matchers grows into a directory
src/core/projection/proof.rs         # if projection grows into a directory
src/core/wake_loop/proof.rs          # if wake_loop grows into a directory

src/event_modules/<module>/proof.rs
src/event_modules/<module>/proof/
  mod.rs
  layout.rs
  projector.rs
  offers.rs
  rows.rs
```

A single proof file per event/fact module is allowed and preferred at first:

```text
src/event_modules/connection_request/proof.rs
src/event_modules/connection_response/proof.rs
src/event_modules/identity_admin/proof.rs
```

Proofs should not live directly in `project.rs`, `commands.rs`, `create.rs`, or
`rows.rs` as a default. Those files are the production implementation surface.
They should remain readable as protocol code: decode, validate, emit needs,
offers, intents, or command facts.

The exception is small specification hooks that must sit on the executable item
being verified. For example, a pure helper may carry a Verus precondition,
postcondition, or ghost-free spec reference if that is the least invasive way to
verify it. Larger lemmas, induction arguments, proof-only wrappers, model types,
and role certificates belong in `proof.rs`.

Split a module's proof into `proof/` subfiles only after the file becomes hard to
review. The split should follow invariants, not generic names. For example,
`projector.rs`, `handshake.rs`, and `authority.rs` are useful; `helpers.rs` is
not.

Normal Rust builds should not compile proof files. Module manifests should gate
proof modules behind a dedicated cfg or feature:

```rust
#[cfg(verus)]
pub mod proof;
```

or, if Cargo feature gating is easier for the local toolchain:

```rust
#[cfg(feature = "verus-proof")]
pub mod proof;
```

The exact gate can be chosen when the Verus runner is introduced, but production
code must not depend on proof modules.

## Shared Core Proof Surface

`src/core/proof.rs` owns protocol-neutral specification types and lemmas:

```text
SpecFact
SpecContextNeed
SpecContextOffer
SpecMatchedContext
SpecProjectionOutput
SpecGraph
```

Core predicates:

```text
context_set_normalized(set)
exact_match_sound(need, offer)
projection_context_sound(ctx, graph)
standing_offers_sound(graph)
atomic_intents_sound(output, graph)
```

Core lemmas:

```text
exact matcher returns only same role, scope, and selector
context replacement preserves ownership boundaries
unchanged needs/offers do not create new wakes
new matching offers wake only need owners
matched payloads are loaded from offer.payload_ref
```

These core proofs intentionally do not know protocol roles such as
`identity_admin` or `connection_request`.

## Event Module Proof Contract

Each event module owns its semantic predicates. A module proof file should define
the certificates for the context offers and rows that module emits.

Example shape:

```text
valid_connection_request_fact(fact)
valid_connection_request_offer(offer, payload, graph)
valid_connection_request_row(row, fact, graph)

lemma_request_projector_waits_without_materializing(...)
lemma_request_projector_offer_is_valid(...)
lemma_request_projector_row_is_valid(...)
```

Projector proof obligations:

```text
1. Decode failure emits no output.
2. Missing required context emits stable needs and no materialized rows/intents.
3. Invalid matched context fails projection or emits no materialized output.
4. Every emitted offer satisfies that role's semantic offer predicate.
5. Every emitted row intent satisfies that table's row predicate.
6. Every emitted deferred intent satisfies that intent's input/authority predicate.
```

Matcher proof obligations:

```text
1. A returned match has the requested role.
2. A returned match satisfies the role's selector relation.
3. A returned match preserves need owner, offer owner, and payload_ref exactly.
4. The matcher does not claim protocol authority.
```

## Stringing Proofs Across Context

Proof composition should use offer predicates as certificates.

For a producer projector:

```text
projector emits Offer(role = R, payload_ref = F)
  -> valid_R_offer(offer, F, graph)
```

For a matcher:

```text
need and offer match
  -> matched context contains the offer payload
  -> no semantic authority conclusion yet
```

For a consumer projector:

```text
projection_context_sound(ctx, graph)
ctx contains matched offer for role R
valid_R_offer(offer, payload, graph)
consumer validates module-specific cross-checks
  -> consumer output predicate holds
```

For `WakeLoop`:

```text
standing_offers_sound(before)
projector theorem for current fact
context replacement for current owner
matcher soundness for newly added context
  -> standing_offers_sound(after)
  -> materialized rows/intents remain sound
```

This gives an induction over projection steps instead of a one-off proof about a
single projector.

## Auth DAG Strategy

Auth relationships should be modeled as a least authorized closure, not as broad
store queries.

Identity predicates:

```text
valid_workspace_offer(workspace_offer, workspace_fact)
valid_admin_offer(admin_offer, admin_fact, graph)
valid_user_offer(user_offer, user_fact, graph)
valid_endpoint_offer(endpoint_offer, endpoint_fact, graph)
```

Admin closure:

```text
workspace root
  -> bootstrap admin
  -> delegated admin
  -> user / invite / endpoint authority
```

The proof should show that an `identity_admin` offer can appear only from one of
two cases:

```text
bootstrap:
  workspace exists
  admin.authority_fact_id == workspace_id
  admin.user_fact_id == workspace_id
  admin.public_key == workspace.public_key

delegated:
  valid_admin_offer(authority_admin)
  authority_admin.workspace_id == admin.workspace_id
  valid_user_offer(user)
  user.workspace_id == admin.workspace_id
  user.public_key == admin.public_key
```

Cycles of admin facts do not bootstrap authority because the induction requires
an already valid authority offer before a delegated admin offer can be emitted.

Current caveat: identity signed-envelope validation is still a known parity gap.
The Verus proof should not claim final shared authority soundness until
`signed_fact` verification is part of these projector contracts.

## Connection Handshake Slice

The first vertical proof slice should be the connection handshake. It has a small
surface, crosses several context roles, and exercises the exact composition
model.

Predicates:

```text
valid_invite_secret_offer(offer, invite_secret)
valid_ephemeral_secret_offer(offer, ephemeral_secret)
valid_transit_received_offer(offer, receive_fact)
valid_connection_request_offer(offer, request_fact, graph)
valid_connection_row(row, response_fact, graph)
```

Proof chain:

```text
connection_ephemeral_secret projector
  -> local secret offer implies public key matches private key

transit_received projector
  -> receive offer implies local provenance for received_fact_id

connection_request projector
  -> invite context is present
  -> invite signature transcript verifies
  -> local branch has matching local ephemeral secret
  -> received branch has matching bootstrap receive provenance
  -> emitted connection_request offer is valid

connection_response projector
  -> request offer is valid
  -> invite context matches request bootstrap hash
  -> endpoint direction reverses request
  -> public handshake hash matches transcript
  -> local branch has responder ephemeral secret
  -> received branch has handshake receive provenance and initiator secret
  -> emitted connection row is valid
```

Known implementation issue to resolve before the end-to-end handshake proof:
connection request/response projectors currently need the
`connection_invite_secret` role, while the invite-secret projector emits
`identity_invite_secret`. Tests can manufacture the context directly, but a
runtime proof should require the producer and consumer roles to line up.

## Runner And Build Plan

Introduce proof execution in stages:

```text
scripts/run_verus.sh
verus.toml or equivalent local runner config
```

The runner should verify only proof-enabled modules first:

```text
core context/matcher lemmas
connection_ephemeral_secret proof
transit_received proof
connection_request proof
connection_response proof
identity_admin proof
```

Keep Rust tests and Verus proofs complementary:

```text
Rust tests prove concrete behavior and regressions.
Verus proofs prove universal invariants over all inputs accepted by the spec.
```

Every proof task should still include realistic executable tests when it changes
runtime behavior. Pure proof-only changes should run the Verus runner and any
nearby Rust tests affected by the proof refactor.

## Worktree Task Template

Use this template when assigning proof work to a worktree:

```text
1. Work only in the named worktree.
2. Define or update the module-local semantic predicates for the target role.
3. Add or update the Verus lemmas for the changed projector/matcher behavior.
4. Add or update realistic Rust tests if runtime behavior changes.
5. Run the relevant Verus target and nearby Rust tests.
6. Document any proof assumptions, especially opaque crypto assumptions.
7. Commit the completed work on that same worktree branch before handoff or review.
```

## Initial Milestones

1. Add the Verus runner and a tiny core proof target for exact selector matching.
2. Prove projection context plumbing for exact matches and payload refs.
3. Prove local connection ephemeral-secret offer validity.
4. Prove transit receive provenance offer validity.
5. Fix the invite-secret role mismatch for connection proof composition.
6. Prove connection request offer validity.
7. Prove connection response row validity.
8. Add identity admin closure predicates after signed-fact validation lands.
