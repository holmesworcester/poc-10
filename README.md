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

Protocol state is organized by scope, not by old layer names:

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

## Style Rules

### Projector Style

Projectors are pure functions over one fact plus supplied context. A projector
does protocol validation, not IO. It decodes the primary fact through the
typed adapter, checks scope and structure, declares exact context needs, reads
matched context through `ProjectionContext` helpers, validates authority, and
returns the complete replacement context plus materialization effects.

Missing context parks. Mismatched context rejects. Deletion is target-owned: a
target fact keeps the need or time wake that can remove it, and when that
context appears it deletes only its own rows and may purge only itself.

### Intent Handler Style

Handlers own bounded stateful work. They decode their intent, name exact input
facts for core to load, perform one effect, and return `PipelineEffects`.
Retryable absence of input or IO returns retry so the queue row remains. A
handler may call the owning fact module's `create.rs` helpers, but it must not
inline shared fact layouts, run projectors, or mutate read-model rows outside
the pipeline effect boundary.

### Wire And Codec Style

Use `core::wire` primitives for fixed ids, hashes, keys, signatures, nonces,
integers, tags, and bounded slots. Decoders reject wrong tags, wrong lengths,
trailing bytes, non-canonical padding, and invalid enum values. Store code is a
generic row substrate and must not learn protocol table meaning.

### Connection Frame Style

Connection frames are opaque fixed-size envelopes until opened by the
connection-frame projector with exact connection context. Connection fact
receipts are local facts plus context offers about recovered shared facts, not
projector side channels.

### Simplicity Guardrails

No old labels, blocker tables, ready queues, canonical ingress queues,
recently-valid queues, pending reprojection queues, or worker catalogs remain.
These names are legacy/removal vocabulary only. They must not reappear in
target code paths except in tests or documentation.

## Documentation

Live design and maintenance docs live under `docs/`:

- `docs/README.md` indexes the live and archived documentation sets.
- `docs/RULES.md` records architecture rules and projector style.
- `docs/documentation_guide.md` records documentation style.
- `docs/auth.md` records auth and key-material invariants.
- `docs/negentropy_recs.md` records dep-aware sync recommendations.

Superseded planning notes live under `docs/archived/`. `verus_plan.md` remains
at the repository root because it is a separate verification plan.
