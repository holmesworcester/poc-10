# Rules

These rules describe the current poc-10 architecture. Runtime behavior belongs
in `src/core` or `src/protocol`.

## Architecture Boundary

- The durable graph is made of facts. Fact ids are deterministic hashes of
  canonical fact bytes.
- Persistence and replay are independent axes. A fact is durable (on disk) or
  ephemeral (transient pipeline input); a durable fact is replayed (re-projected
  by a from-scratch rebuild) or not. Durable protocol *truth* — identities,
  membership, content, key wraps, learned addresses — is replayed and rebuilds
  deterministically. A durable fact whose projection materializes live *session*
  state — a connection request and the connection itself, carrying a secret that
  is dead after a restart — is **not replayed**: it is kept on disk but a rebuild
  skips it, so replay wipes its session rows and never resurrects a dead
  connection. Each projector route declares this with `not_replayed`, the
  fact-level mirror of a handler route's `runs_during_replay`. Replay state
  digests therefore cover durable truth, not transport.
- Projectors are pure functions over one fact plus provided context. They return
  context needs, context offers, and intents.
- Context is explicit. Needs and offers describe relationships that should wake
  projection when matched by a context matcher. Core stores and matches them;
  projectors decide what they mean.
- Core runtime and pipeline code own admission, pending projection, context
  matching, projection drain, row mutations, deferred intent queueing, handler
  dispatch, and persistence.
- Intent handlers own bounded stateful work. They consume intents and exact
  declared fact inputs, then return facts, purged fact ids, and follow-up
  intents. They must not own protocol fact layouts or read-model projection
  rows.
- Intents are flat: an intent does not chain another intent. A handler whose job
  is to create a fact does exactly that and stops — it must not also enqueue a
  follow-on intent that does qualitatively different (especially non-replayable)
  work. The single visible place an intent is enqueued in reaction to a fact is
  that fact's **projector**, so "what does admitting this fact enqueue?" is
  answerable by reading one projector, and a replayable intent can never smuggle
  in a non-replayable one. Concretely, `create_bootstrap_response` and
  `create_connection_response` create responder ephemeral, response-sent, and
  `connection_established` facts; the response-sent fact's projector emits the
  network send.
- Replayability decides where a send is emitted. A response send is reactive to
  a received request and is emitted by the response-sent fact's projector. A *request*
  send is operational liveness, not durable truth: a projector-emitted request
  send would be a live-only intent that replay suppresses and never re-issues, so
  request sends are driven by the live recurring `maintain_connections` loop,
  which re-queries unanswered local outbound request rows each tick. Operational
  repetition belongs in a recurring intent, not a wall-clock time wake or a
  projector-scheduled retry.
- The product-facing binary is `con`. `src/context_app.rs` should stay a thin
  app boundary around the core runtime and protocol registry.

## File Ownership

- `src/core/` contains protocol-neutral mechanics only: facts, context,
  matchers, projection contracts, intents, handler dispatch, store, wire,
  crypto, network queues, TCP, clock, and schema declarations.
- `src/protocol/<scope>/<fact_family>/` owns fact shape, fixed wire layout,
  primary-fact authentication (`authenticate.rs`), command constructors,
  projection, rows, queries, and context helpers for one fact family.
- `src/protocol/<scope>/<verb_object>.rs` owns one deferred effect boundary.
  Handler subdirectories, `driver.rs`, and handler-local `intent.rs` files are
  forbidden.
- Shared command context/output types live in `src/core/command_context.rs`.
  Concrete command constructors live in the fact module that owns the emitted
  fact.
- There is no `mod.rs`. Root manifest files such as `src/core.rs`,
  `src/protocol.rs`, and `src/protocol/<scope>.rs` are declaration-only.
- Schema declarations live beside their owners in `src/core/schema.rs`,
  `src/core/network.rs`, and `src/protocol/registry.rs`.
- Broad names are suspect inside protocol scopes unless they are one of the
  standard fact-family role files. Avoid files or directories named `state`,
  `jobs`, `cli_commands`, or `codec.rs` in target code.

## Documentation Style

Project documentation describes the current system in terms of purpose,
mechanism, invariants, and ownership boundaries. Open with the model before
implementation details: say what the component is for, then explain the data
shape or runtime flow it owns.

Documentation should make maintenance routing obvious. For each subsystem,
scope, module, public boundary type, or important helper, answer:

1. What does this component own?
2. How does it work at the important data-flow or commit-boundary level?
3. What invariants, ordering rules, idempotence rules, replacement rules, or
   security conditions does it rely on or preserve?
4. What does this component not know or do?
5. Where should a future related change be made?

Explain redundant or surprising state instead of merely naming it. Examples
include `facts` versus `local_fact_admissions`, durable versus local intents,
network bytes versus connection facts, and scope rows versus cross-scope
context. The prose should say why both forms exist and what each one owns.

Keep mechanism concrete. Prefer "claims one queued intent, loads declared fact
inputs, calls the handler, and commits output atomically with queue deletion" to
"handles dispatch." Inline comments should attach to real invariants,
non-obvious matching semantics, ownership rules, and security conditions; they
should not narrate obvious code.

Write docs in current-code terms. Do not refer to branch names, task slices,
abandoned plan filenames, or past implementation states unless the document is
explicitly archived or the user asks for history.

## Projectors

- Projectors interpret an already-authenticated fact in context; they do not
  authenticate and do not do IO. Primary decode, the fact-id check, the
  fact-boundary signature, and intrinsic single-fact field rules belong to the
  family `authenticate.rs`; core runs it before the projector, so a projector
  receives an `AuthenticatedFact` and never parses raw primary bytes.
- Projectors do not verify signatures. The primary fact's signature is proven by
  its authenticator, and any fact reached through context was authenticated
  before it could offer that context, so its authenticity is guaranteed. A
  projector decodes a context fact through the owning module's typed helper to
  read its fields and prove relationships, but never re-verifies its signature.
- Scope is interpretation, not authentication: the projector checks the fact's
  admission scope, because scope is unsigned local metadata, not part of the
  authenticated bytes.
- Projectors may use `core::crypto` when encryption or decryption is pure over
  the fact and supplied context. Decrypting a payload with a secret from context
  is materialization, not authentication.
- Projectors must not query the store, call handlers, call other projectors,
  submit facts, open network sockets, read clocks, mutate process-local state,
  or perform broad scans.
- A projector that cannot proceed emits a standing context need. A projector
  that learns useful context emits an offer. Missing context is not a separate
  "blocked" state in target code.
- Projectors look up matched context by the concrete `ContextNeed` they just
  constructed, using `ProjectionContext::payload_for`,
  `payload_for_checked`, or `matched_payloads_for`. Direct
  `matched_context()` scans are exceptional compatibility code and must be
  explicitly justified by a guardrail allowlist.
- Deletion, supersession, connection fact receipts, key availability, and dependency
  availability are context offers or facts, not labels or side channels.

### Projector Style

Non-trivial projectors should make their proof shape obvious to a reviewer:

1. Authenticate in `authenticate.rs`: a numbered policy (layout, fact id,
   signature, intrinsic field rules) that returns an `AuthenticatedFact`. Keep
   its shape uniform and reviewable; it owns no context, authority, or rows.
2. Implement `Projector::project()` as a small call through
   `core::projectors::project_authenticated::<ModuleAuthenticator, _>()`.
3. Put the real proof in
   `AuthenticatedProjector<ModuleAuthenticator>::project_authenticated()`,
   binding `let (fact, payload) = authenticated.into_parts();` and beginning at
   the section it owns — scope/context (`// 2.`) or, for a minimal projector that
   only writes rows, materialize (`// 3.`) — with matching numbered markers. The
   top-of-file policy still names every section; the structural/authentication
   ones now live in `authenticate.rs`.
4. Name every security-sensitive context need in a small struct or local
   binding. Avoid positional `needs[0]` contracts.
5. Split real authority branches into path-specific functions whose names say
   what authority path they prove.
6. Emit row mutations through module-owned row helpers and schema-owned tables.

### Deletion Pattern

Deletion is target-owned. A deletion, close, or retirement fact publishes
context with an offer; a due time wake supplies time context. The target fact
keeps the matching need or wake in its normal projection output. When that
context matches, the target projector validates the payload when there is one,
deletes only rows it owns, and then calls `ProjectionOutput::purge_self` for
its own fact id.

Do not build parent-owned child scans or generic cascade handlers. A parent
projector may publish deletion context, but reaction, file, slice, secret, and
connection-material projectors are responsible for observing that context and
removing themselves. The only purge a projector may emit is its own fact id;
core rejects cross-fact purges from projector output.

### Context Proof Style

Projectors must read matched context by the exact `ContextNeed` they declared.
Use:

- `payload_for(&need)` for one exact payload.
- `payload_for_checked(&need, label)` when the module wants the shared
  offer/payload consistency check.
- `matched_payloads_for(&need)` for intentional multi-match roles, such as
  connection fact receipts or range roots.

Do not call `matched_context()` from protocol projectors. Do not scan
`context.offers()` to infer whether a declared need is satisfied. A matched
offer's payload is the offer owner's fact; projectors should reach it only
through the `ProjectionContext` helper anchored to the need they emitted.

### Typed Facts And Foreign Context

Core persists facts as opaque bytes. The owning fact module supplies a small
`FactCodec`; its `authenticate.rs` decodes through that codec, checks the id and
the signature, and produces an `AuthenticatedFact`. Core runs the authenticator
before the projector, so `project_authenticated()` receives the typed,
authenticated payload. Do not call a raw layout decoder on the primary fact
outside the module codec, and do not decode or authenticate the primary fact in
the projector.

Foreign context fact bytes are different. A projector should not import another
fact module's raw layout codec. It should call a module-owned typed helper that
keeps wire formatting centralized inside the owning fact module while letting
projector policy read as typed facts and named witnesses. It trusts the
authenticity of any fact it reaches through context — that fact was
authenticated before it could offer the context — so it decodes for fields and
proves relationships, but never re-verifies the signature.

### Parking And Errors

Missing context parks. Mismatched context rejects.

Parking returns the current standing needs so the context matcher can wake the
fact later. A projector should return an error only when supplied data violates
the fact's structural, signature, authority, or cross-field policy.

### Schema And Rows

Projectors may decide when a row should be materialized. They do not own the row
shape. Durable table ownership belongs in the explicit SQL schema declarations
in `core::schema`, `core::network`, or `protocol::registry`; row construction
belongs in module-owned row helpers. Projectors emit row mutations through those
helpers rather than declaring table names, column sets, or opaque row shapes
inline.

Patterns to avoid in projector files:

- `matched_context()` or direct raw context-offer scans.
- Positional context proof vectors for authority-sensitive paths.
- Generic `validate_authority` helpers that hide branch-specific policy.
- Hidden-state context wrappers that auto-track consulted needs.
- Declarative check arrays where an interpreter becomes the real logic.
- Projector-owned row tables, row shapes, SQL, file IO, network IO, or CLI
  parsing.

## Intents And Handlers

- Intent payloads are small, fixed or bounded wire records plus an idempotence
  key. The payload must name exact fact inputs when the handler needs fact
  context.
- Intent type determines whether work is atomic or deferred.
- Row mutations are bounded read-model mutations and are applied by
  the core pipeline during projection drain.
- Deferred handlers must be retry-safe: if required inputs or external effects
  are unavailable, return an error so the intent remains queued.
- Handlers must not construct shared fact wire layouts inline. If a handler
  needs to create a protocol fact, the owning event module provides a
  `create.rs` helper.
- Handlers must not become logic dumping grounds. They validate their intent,
  load exact inputs through handler context, perform one bounded effect, and
  return facts/intents/purges.

### Intent Handler Style

Handlers are the only place for bounded stateful protocol work. A handler
decodes its own intent payload, asks core for exact input fact ids through
`input_fact_ids`, reads those facts through `HandlerContext`, performs one
bounded effect, and returns `PipelineEffects`. It must be retry-safe: transient
absence of required input or external IO returns `retry_intent`, leaving the
queue row in place.

Handlers may call deterministic `create.rs` constructors owned by the fact
module they are emitting. They must not inline shared fact wire layouts, mutate
projection rows directly, run projectors, or become a second command layer.

## Wire And Schema

- Wire layouts are fixed length unless a fact explicitly stores an opaque
  bounded slot with canonical zero padding.
- Use `core::wire` primitives for fixed ids, hashes, keys, signatures, nonces,
  integers, tags, and bounded slots.
- Decoders reject wrong tags, wrong lengths, trailing bytes, non-canonical
  padding, and invalid enum values.
- Store code is a generic row substrate. It must not learn protocol table
  meaning, sync ranges, connection routes, or context semantics.

### Wire And Codec Style

Wire layouts are protocol contracts. Keep tag checks, byte lengths, enum
validation, canonical padding, and transcript construction in the owning fact
module's `layout.rs` or narrow typed helper. Core wire primitives supply syntax;
the fact module supplies meaning.

## Sync And Connection Frames

- Connection frames are opaque fixed-size envelopes until opened by the
  connection-frame projector with exact connection context.
- A connection fact receipt is a local fact plus context offer about the
  recovered shared fact. It is not a projector argument side channel.
- Sync is event-layer protocol work. Missing keys are represented by facts,
  needs, offers, and request/response facts, not trusted server-side sync
  shortcuts.
- Dep-aware sync must include out-of-range context facts needed to project
  in-range facts, especially key wraps and retained key nodes for encrypted
  content.
- The untrusted server may help compare ranges, but key requests and key
  responses happen as facts.

### Connection Frame Style

Connection frames are transport envelopes until a connection projector opens
them with exact connection context. Network handlers move opaque bytes through
core queues; connection frame projectors and handlers decide whether the bytes
name a request, response, receipt, bundle, or shared fact.

### Fact Sealing

Sealing is a property of the fact type, not a runtime mode. Every connection
fact that travels on the wire — `bootstrap_request`, `connection_request`, the
connection (response) fact, and the established frame facts — owns its own
sealing end to end, in its own modules. There is no seal-mode discriminator and
no separate envelope or transit-wrapper fact in another module.

- `create.rs` seals a fact when it generates it: sealing is wrapping, and
  wrapping is `create.rs`'s job. Handshake facts are sealed asymmetrically to
  the recipient endpoint; established frames are sealed with the
  `connection_secret`.
- Unsealing is a context need. A receiver opens a sealed connection fact in that
  fact's own projector, which declares a context need for its unseal key —
  `auth_local_endpoint` (the local endpoint secret) for handshake facts,
  `connection_established` (the `connection_secret`) for established frames — and
  unseals from it, exactly as the established-frame projector already does. The
  receive boundary admits the typed wire bytes and does no unsealing itself;
  there is no inline unseal handler and no key plumbing at the boundary.

## Forward Secrecy Requires Recipient Key Rotation On Root Loss

When a deletion, expiry, or floor advance makes a frontier root unavailable for
future sharing, the local recipient key must rotate. Peers should stop sending
new wraps to superseded recipient keys, and local private material for those
keys must be purged after exact supersession proof.

Post-deletion key healing must not resurrect the removed root. Explicit key
requests for a frontier whose root is gone may wrap retained path nodes that
cover surviving content. Duplicate requests for the same deterministic edge
must converge on one wrap and must not introduce request entropy that amplifies
keys.

Forward secrecy here means post-retirement disk compromise cannot decrypt the
retired content from remaining local material. It does not revoke plaintext or
keys already observed before retirement.

## Commands

- Commands are pure constructors over explicit parameters and a narrow
  `CommandContext`.
- Commands may read allowed local capabilities such as signer or encryption
  secrets from the context. They must not mint capabilities unless the owning
  auth fact module explicitly owns that command.
- Commands do not write the store, drive the runtime pipeline, dispatch
  handlers, call workers, parse CLI argv, or format user output.
- Any invariant required for accepting received/shared facts must be enforced by
  layout decoding, projector validation, context matching, or handler
  validation, not only by command preflight checks.

## Tests And Proof

- Functional behavior is proven by black-box `con` CLI/network tests or by
  focused target projector/handler tests.
- Boundary tests are part of the architecture. If a new file shape or import is
  correct, update the boundary test with the rule that makes it correct.
- Tests should not seed protocol rows directly unless they are explicitly unit
  tests for that row codec.
- Guardrails should fail when production code routes work outside the declared
  fact, context, time-wake, projection, intent, and schema-owned row surfaces.

### Simplicity Guardrails

Production work is represented with immutable facts, standing context,
time-wake schedules, pending projection, durable intents, and ephemeral intents.
Protocol progress is visible through those mechanisms and through schema-owned
rows. The declared runtime pipeline is the complete work surface: production
state enters that pipeline as facts, context, time wakes, intents, or
schema-owned rows. If a new file shape or import is correct, update the
boundary test with the rule that makes it correct.

## In-Line Documentation

Inline comments should explain ownership, invariants, security conditions,
non-obvious matching semantics, and why a choice exists. They should not narrate
obvious code.

Do not reference transient delivery state in source comments: branch names,
commit hashes, task numbers, slice numbers, "before/after merge" phrasing, or
abandoned plan filenames. Stable architecture docs such as `README.md`, this
file, and scope READMEs under `src/protocol/` may be referenced when the
comment is pinning a lasting invariant.
