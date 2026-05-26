# Context Architecture

This repository is the poc-10 implementation of Context. The current
architecture has a small vocabulary:

```text
facts
context needs
context offers
projectors
intents
intent handlers
runtime pipelines
protocol scopes
```

The system has one fact store, one context matching surface, one projection
scheduler, one intent scheduling surface, and one product-facing binary:
`con`.

## Architecture Principles

The current architecture is described by these boundaries:

- Core owns protocol-neutral mechanics: facts, context, command context,
  byte-range context matching,
  generic runtime/app mechanics, pending fact processing, context wake fanout,
  intent dispatch, storage mechanics, wire field primitives, network queues,
  TCP, clock, and crypto helpers.
- Protocol scopes own fact semantics: layouts, projectors, context
  roles/ranges, command constructors, read-model rows, queries, CLI adapters,
  and protocol validation rules.
- `src/protocol.rs` and `src/protocol/<scope>.rs` are manifests. A scope
  manifest declares its fact families and intent handlers in one place.
- Intent handlers own bounded stateful work and handler checkpoint state.
- Projectors return needs, offers, time wakes, row mutations, and intents.
- Intent handlers return facts, purged facts, row mutations, and intents.
  Purge output remains a bounded core-owned escape hatch for exact fact
  removal, not a broad storage API.
- No fact module, intent handler, command, schema, or wire layout reaches
  around core to call another stage directly.
- Runtime coordination is explicit and durable where it needs to survive
  restart: pending facts, time wakes, durable intents, and ephemeral intents are
  named queue surfaces rather than hidden callbacks.
- Schema declarations are explicit SQL DDL in the owning Rust modules:
  `src/core/schema.rs`, `src/core/network.rs`, and
  `src/protocol/registry.rs`.
- Wire layouts are declarative and fixed length. There are no variable payload
  slots except bounded, canonical slots explicitly modeled by a fact layout.

## Rules

These repository rules keep the architecture mechanically visible:

- There is no event-bus layer. The runtime coordinates explicit SQL-backed
  queues: pending facts, time wakes, durable intents, and ephemeral intents.
- There is no product `demo` or `smoke` command. Smoke coverage belongs in
  black-box CLI tests against the real `con` binary.
- There is no root `src/commands` module. The command context lives in
  `src/core/command_context.rs`.
- There is no `mod.rs` anywhere in the repository.
- Boundary tests fail if dumping-ground files, ad hoc SQL, ad hoc codecs,
  broad projector reads, direct handler calls, or direct network/store side
  effects appear.

## Runtime Shape

`src/main.rs` delegates to the product app boundary. The app supplies a
`ProtocolDescription`; core opens the declared runtime, runs the declared daemon
tick, and dispatches registered protocol commands without knowing their names
or behavior.

Runtime work moves through these core-owned queues:

```text
command or handler output
  -> facts / intents / row mutations
  -> pending_projection
  -> projector
  -> context replacement + row mutations + follow-up intents
  -> durable or ephemeral intent queue
  -> registered handler
  -> committed PipelineEffects
```

Network input is staged as core-owned opaque bytes, converted by the daemon
declaration into an ephemeral protocol intent, and then handled through the
same intent dispatch path. Network output is produced by protocol handlers as
opaque byte rows and written by the core TCP pump.

## Scope Layout

Protocol state is organized by scope:

```text
src/protocol.rs
src/protocol/registry.rs

src/protocol/auth.rs
src/protocol/auth/

src/protocol/content.rs
src/protocol/content/

src/protocol/connection.rs
src/protocol/connection/

src/protocol/sync.rs
src/protocol/sync/
```

Each fact family owns its fact type, fixed wire layout, command constructors,
projector, rows, queries, and CLI adapter if it has one. Each intent handler is
a verb-named file directly under its scope.

## Protocol Function Boundaries

The protocol separates durable data, deterministic derivation, bounded
stateful work, byte syntax, and transport sessions. Keeping those functions
separate makes it clear which component is allowed to interpret bytes, wait for
context, touch external IO, or commit state.

### Projectors

Projectors are the deterministic derivation path from one fact to local state.
They decode the primary fact, check scope and structure, declare exact context
needs, validate matched context, and return the complete replacement context
plus materialization effects. They are separate from handlers because missing
context parks projection, while IO and retryable stateful work belongs in
queued intents.

Deletion is target-owned: a target fact keeps the need or time wake that can
remove it, and when that context appears it deletes only its own rows and may
purge only itself.

### Intent Handlers

Intent handlers are the bounded stateful work path. They decode one queued
intent, name exact fact inputs for core to load, perform one effect, and return
`PipelineEffects`. They are separate from projectors so network sends,
key-wrap creation, sync responses, and other retryable work have an idempotent
queue identity and an atomic commit boundary with queue consumption.

### Wire Layouts And Codecs

Wire layout code is the byte syntax boundary. It uses `core::wire` primitives
for fixed ids, hashes, keys, signatures, nonces, integers, tags, and bounded
slots, and it rejects wrong tags, wrong lengths, trailing bytes,
non-canonical padding, and invalid enum values. It is separate from projection
so byte compatibility stays local to the owning fact module while semantic
admission remains in the projector.

### Connection Frames

Connection frames are the transport envelope boundary. They are opaque
fixed-size byte envelopes until opened by a connection projector with exact
connection context. They are separate from auth, content, and sync semantics:
frames move bytes and produce receipts, while the owning fact projector
validates every recovered fact.

### Simplicity Guardrails

Production work is represented with immutable facts, standing context,
time-wake schedules, pending projection, durable intents, and ephemeral intents.
Protocol progress is visible through those mechanisms and through schema-owned
rows. The declared runtime pipeline is the complete work surface: production
state enters that pipeline as facts, context, time wakes, intents, or
schema-owned rows.

## Documentation

Active design and maintenance docs are:

- `README.md`: architecture overview and protocol function boundaries.
- `docs/RULES.md`: architecture rules, projector rules, and guardrails.
- `src/core/README.md`: core/runtime responsibility boundaries.
- `src/core/pipeline/README.md`: projection and handler commit boundaries.
- `src/protocol/*/README.md`: fact-scope responsibilities, facts, handlers,
  row state, and cross-scope interfaces.
- `verus_plan.md`: verification plan.

Planning notes live under `docs/archived/`.
