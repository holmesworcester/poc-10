# Fact Authenticators

## Status And Scope

Status: projector-local validation is the current model. Core routes raw facts
to projectors, and each projector owns the local sequence for its fact family:
decode the body, validate the fact boundary, adapt any compatibility shape, and
project semantic effects. Core owns queues, matched context, replacement needs,
append-only offers, wake fanout, replay mode, and effect commits.

This note was originally named "fact validators." The durable design point
still matters: the pre-projector layer should not claim full protocol validity.
It proves that a fact's bytes are canonical for a family and cryptographically
authentic enough to interpret. The projector still proves contextual validity:
authority, relationships, deletion, purge, retention, materialization, and
normal needs/offers.

## Purpose

A non-trivial projector should make three boundaries obvious:

1. **STRUCTURAL / AUTHENTICATED** - the fact is the right tag, well-formed,
   content-addressed, signed or opened as required, and carries an intrinsic
   payload.
2. **CONTEXT** - authority and relationships proven from other facts: signer,
   author, membership, deletion, retention, secrets, receipts, and time.
3. **MATERIALIZE** - read-model rows, context offers, time wakes, intents, and
   self-purge.

The role boundaries remain useful even without core-owned stages:

- `encode.rs` owns canonical bytes.
- `project.rs` owns projector-local `decode`, `authenticate`, and `adapt`
  modules. `decode` parses bytes and rejects wrong tags, lengths, padding, enum
  values, and malformed fixed slots. `authenticate` proves fact id, signature or
  container proof, and intrinsic single-fact rules. `adapt` maps source values to
  the active semantic shape and is an identity helper until a version split needs
  real conversion.
- `project.rs` also owns scope, context, authority, rows, offers, needs, time
  wakes, emitted facts, intents, deletion, retention, and purge.
- `author.rs` owns local construction: assembly, signing, encryption,
  deterministic nonce use, and calls to `encode.rs`.
- `api.rs` owns command snapshots and receipts. It queries pre-command
  state through protocol-owned query helpers, reads the injected command clock,
  calls `author.rs`, and lets runtime submission route the authored bytes
  through protocol-local checks before storage.

Why keep this split:

- It makes "are these bytes canonical and authentic for this family?" a small,
  reviewable function over bytes and supplied context.
- It keeps raw primary decoding and signature proof in the owning fact module,
  not spread through materialization code.
- It gives versioning a stable place for source-value conversion without moving
  the projector boundary again.

## Boundary Contract

Fact-boundary validation does:

- decode the fixed layout through the owning module's parser;
- recompute and check the fact id against the canonical bytes;
- verify intrinsic cryptographic authenticity when that proof belongs to the
  current fact boundary;
- enforce intrinsic single-fact rules that need no other fact;
- return a typed source value or an error.

Fact-boundary validation does not:

- decide semantic authority that requires other facts;
- decide whether the fact is displayable, unpurged, undeleted, or meaningful in
  the current graph;
- query the store, call handlers, emit rows, emit offers, purge, enqueue
  intents, perform IO, or read clocks.

Missing context is represented by projector needs. The projector builds the
exact `ContextNeed`, returns a non-error `ProjectionOutput`, and later reads the
matched offer value from `ProjectionContext` when core wakes the fact. A present
value must still be checked for consistency with the current fact before it is
accepted.

## Signatures, Encryption, And Container Facts

Not every cryptographic check belongs in the same place.

- **Signed facts with public encrypted fields.** Content messages, reactions,
  and file descriptors can verify their signatures over the public envelope
  without decrypting user-visible payload fields. Decryption remains
  projector/materialization work because it depends on secret context and
  produces read-model meaning.
- **Facts whose verifier key is external.** The projector may first ask for the
  verifier-key context and then call the module validation helper once that
  context is present. That key's presence is not authority; authority stays in
  the projector. Verifier key placement is a fact-version choice: a family may
  embed the public key when self-contained verification is worth the bytes, or
  it may carry a compact key reference and use context when key material is
  supplied. Do not make embedded public keys mandatory.
- **Encrypted carrier facts.** Connection frames and sealed handshake facts are
  containers. The projector asks for the opener context, opens the carrier, and
  materializes recovered inner fact bytes plus receipts. The inner facts are
  admitted back through the normal projector route by their own tags.
- **Signatures inside encryption wrappers.** If a wire wrapper encrypts a
  canonical signed fact, the signature is "inside" the wrapper only while in
  transit. After the wrapper opens, the recovered canonical fact bytes go
  through their owning admission and projector path.

Purge, deletion, retention, and all materialization effects stay
projector-owned. A purge fact may be authentic forever, but whether a target
observes it, removes rows, retracts sync sharing, or calls `purge_self` is
target interpretation.

## Pipeline Boundary

The active read path is:

```text
raw fact -> tag route -> projector -> ProjectionOutput -> commit
```

The route metadata names the projector only. The projector is the reviewable
call site for the local flow: decode, validate, adapt, project. Repetition is
acceptable when it keeps the boundary visible. Shared helpers should stay
protocol-local and should make an individual projector easier to read.

Context offer values are hydrated by core through matched needs/offers. The
consuming projector decodes the value through the owning module's typed helper
when it needs fields. It does not scan the store or re-run the producer's full
policy; the offer exists because the owner already projected enough to publish
that context. The consumer still proves relationships, role, scope, range, and
compatibility.

## Write-Side Twin

Creation is the write-side twin of projection:

```text
cli args -> command args -> command fn -> queries -> author -> encode -> protocol self-check -> AuthoredFacts -> submit
```

The command function is the authoring boundary: load the needed store/key
snapshot through query helpers, enforce command-local preflight policy, read the
command clock, and call the selected author. It should not parse CLI argv,
handcraft wire bytes, enqueue work, or drive projection/intent drains.

`author.rs` performs local semantic construction: it signs, encrypts, assembles
the typed fact, and returns the authored value plus scope/timestamp/admission
metadata. `encode.rs` owns canonical bytes. Signatures and encryption consume
canonical bytes produced by the encoder, while the actual signing/encryption
operation stays in `author.rs`.

Before a command reports success or returns a fact id, the write path runs
protocol-local self-checks over the authored bytes. Success admits; a byte, id,
signature, or intrinsic-rule error is a synchronous author/encode bug; missing
local context must be reported explicitly rather than bypassed.

## Required Tests And Checks

The final change is not review-ready until all of these pass:

- `cargo fmt --check`
- `cargo test --test poc10_protocol_registry_test`
- `cargo test --test poc10_intent_cleanliness_test`
- `cargo test --test poc10_architecture_boundary_test`
- `cargo test --test documentation_layout_test`
- `cargo test`
- `git diff --check`

Add or update tests while converting:

- per-family validation tests for canonical acceptance and malformed rejection;
- context-dependent projector tests proving park-before-context and
  resume-after-matched-context;
- projector tests that enter through `Projector::project` over real
  authored/encoded bytes, not hand-built semantic values only;
- registry tests that assert projector-only route metadata;
- guardrails that prove the removed core staged API names do not return.

## Final Success Criteria

Success means all of the following are true:

- every routed fact family has reviewable projector-local `decode`,
  `authenticate`, and `adapt` modules inside `project.rs`, plus `encode.rs` /
  `author.rs` where facts are locally authored;
- every route points to a projector and exposes no decode/auth/adapt metadata to
  core route declarations;
- projectors call plain protocol-local helpers directly and do not hide the old
  staged model behind a new generic helper;
- context-dependent projectors park by emitting precise needs and resume from
  matched context carried on pending projection work;
- no live code imports the old compatibility facade;
- docs and guardrails describe only the projector-local final model;
- the complete required check suite passes.
