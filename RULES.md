# Rules

These rules describe the poc-10 target architecture. Anything under
`src/legacy/` is compatibility code kept only until the `match` production path
is fully cut over to the target model.

## Architecture Boundary

- The durable graph is made of facts. Fact ids are deterministic hashes of
  canonical fact bytes.
- Projectors are pure functions over one fact plus provided context. They return
  context needs, context offers, and intents.
- Context is explicit. Needs and offers describe relationships that should wake
  projection when matched by a context matcher. Core stores and matches them;
  projectors decide what they mean.
- `WakeLoop` owns admission, pending projection, context matching, projection
  drain, atomic row intents, deferred intent queueing, handler dispatch, and
  persistence.
- Intent handlers own bounded stateful work. They consume intents and exact
  declared fact inputs, then return facts, purged fact ids, and follow-up
  intents. They must not own protocol fact layouts or read-model projection
  rows.
- The product-facing binary is `match`. `src/match_app.rs` is a temporary bridge
  to `src/legacy/` until the target runtime facade owns the production path.
- `src/legacy/` is one deletion island: old app shell, daemon loop, protocol
  tree, round-robin scheduler, and worker tree. New code must not add behavior
  there unless it is required to keep unchanged legacy tests passing during
  cutover.

## File Ownership

- `src/core/` contains protocol-neutral mechanics only: facts, context,
  matchers, projection contracts, intents, handler dispatch, store, wire,
  crypto, network queues, TCP, clock, and schema DSL.
- `src/event_modules/<module>/` owns fact shape, fixed wire layout, command
  constructors, projection, rows, and context helpers for one fact family.
- `src/handlers/<handler_name>.rs` owns one deferred effect boundary. Handler
  subdirectories, `driver.rs`, and handler-local `intent.rs` files are
  forbidden.
- `src/commands/` owns only shared command context/output types. Concrete
  command constructors live in the fact module that owns the emitted fact.
- There is no `mod.rs`. Root manifest files such as `src/core.rs`,
  `src/event_modules.rs`, and `src/handlers.rs` are declaration-only.
- Schema declarations exist only in `src/core/schema.p8sql`,
  `src/event_modules/schema.p8sql`, and `src/handlers/schema.p8sql`.
- Broad names are suspect. Avoid files or directories named `runtime`, `state`,
  `jobs`, `cli_commands`, `schema.rs`, `codec.rs`, or `cli.rs` in target code.

## Projectors

- Projectors do protocol validation, not IO.
- Projectors may use `core::crypto` when encryption or decryption is pure over
  the fact and supplied context.
- Projectors must not query the store, call handlers, call other projectors,
  submit facts, open network sockets, read clocks, mutate process-local state,
  or perform broad scans.
- A projector that cannot proceed emits a standing context need. A projector
  that learns useful context emits an offer. Missing context is not a separate
  "blocked" state in target code.
- Deletion, supersession, receive provenance, key availability, and dependency
  availability are context offers or facts, not labels or side channels.

## Intents And Handlers

- Intent payloads are small, fixed or bounded wire records plus an idempotence
  key. The payload must name exact fact inputs when the handler needs fact
  context.
- Intent type determines whether work is atomic or deferred.
- Atomic row intents are bounded read-model mutations and are applied by
  `WakeLoop` during projection drain.
- Deferred handlers must be retry-safe: if required inputs or external effects
  are unavailable, return an error so the intent remains queued.
- Handlers must not construct shared fact wire layouts inline. If a handler
  needs to create a protocol fact, the owning event module provides a
  `create.rs` helper.
- Handlers must not become logic dumping grounds. They validate their intent,
  load exact inputs through handler context, perform one bounded effect, and
  return facts/intents/purges.

## Wire And Schema

- Wire layouts are fixed length unless a fact explicitly stores an opaque
  bounded slot with canonical zero padding.
- Use `core::wire` primitives for fixed ids, hashes, keys, signatures, nonces,
  integers, tags, and bounded slots.
- Decoders reject wrong tags, wrong lengths, trailing bytes, non-canonical
  padding, and invalid enum values.
- Store code is a generic row substrate. It must not learn protocol table
  meaning, sync ranges, transit routes, or context semantics.

## Sync And Transit

- Transit frames are opaque fixed-size envelopes until opened by a transit
  handler with exact connection context.
- Receive provenance is a local fact plus context offer about the recovered
  shared fact. It is not a projector argument side channel.
- Sync is event-layer protocol work. Missing keys are represented by facts,
  needs, offers, and request/response facts, not trusted server-side sync
  shortcuts.
- Dep-aware sync must include out-of-range context facts needed to project
  in-range facts, especially key wraps and retained key nodes for encrypted
  content.
- The untrusted server may help compare ranges, but key requests and key
  responses happen as facts.

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
  identity/encryption fact module explicitly owns that command.
- Commands do not write the store, drive `WakeLoop`, dispatch handlers, call
  workers, parse CLI argv, or format user output.
- Any invariant required for accepting received/shared facts must be enforced by
  layout decoding, projector validation, context matching, or handler
  validation, not only by command preflight checks.

## Tests And Proof

- Functional behavior is proven by black-box `match` CLI/network tests or by
  focused target projector/handler tests.
- Boundary tests are part of the architecture. If a new file shape or import is
  correct, update the boundary test with the rule that makes it correct.
- Tests should not seed protocol rows directly unless they are explicitly unit
  tests for that row codec or legacy compatibility.
- Guardrails should fail on old vocabulary in target code: labels, blockers,
  ready queues, canonical ingress queues, worker catalogs, handler subdirs, and
  direct protocol/worker imports.

## In-Line Documentation

Inline comments should explain ownership, invariants, security conditions,
non-obvious matching semantics, and why a choice exists. They should not narrate
obvious code.

Do not reference transient delivery state in source comments: branch names,
commit hashes, task numbers, slice numbers, "before/after merge" phrasing, or
abandoned plan filenames. Stable architecture docs such as this file,
`new_architecture.md`, and `encryption.md` may be referenced when the comment is
pinning a lasting invariant.
