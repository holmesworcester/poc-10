# Core

Core is the protocol-neutral runtime substrate. A different protocol should be
able to reuse it unchanged: core stores immutable facts, matches context ranges,
runs projectors, dispatches queued intents, commits effect batches, hosts CLI
and daemon loops, and moves opaque network bytes. It must not know what a
workspace, message, invite, key wrap, sync range, or connection fact means.

## Interface To Protocol

Protocol code enters core through declarations and effect values:

- `runtime::RuntimeDescription` declares protocol schema sources, allowed row
  mutation tables, the projector factory, registered intent handlers, and
  command-excluded handler names.
- `app::ProtocolDescription` adds the product name, daemon declarations, CLI
  command table, and command context constructor.
- `projectors::Projector` receives one `Fact` plus a `ProjectionContext` and
  returns a `ProjectionOutput`.
- `intents::IntentHandler` receives one idempotent `Intent` plus a
  `HandlerContext` containing only declared input facts and returns
  `PipelineEffects`.
- `command_context::CommandContext` gives user-facing commands read-only store
  access, a monotonic timestamp source, and identity-owned local capabilities.
- `effects::PipelineEffects` is the shared language for facts to admit,
  ephemeral facts, purges, row mutations, durable intents, and local intents.
- `store::SchemaSource` lets core, network IO, and protocol registry code
  declare their own SQL DDL and opaque row-table allowlists.

Data leaves core through the same narrow surfaces: commands receive
`CliOutput`, protocol queries read schema-owned rows through `Store`, daemon
handlers receive inbound frames as local intents, and network sends consume
opaque outbound rows from `network`.

## Data Flow

```text
CLI command / daemon / handler
  -> PipelineEffects
  -> fact admission and pending_projection
  -> projector
  -> context needs/offers, time wakes, rows, intents
  -> intent queue
  -> handler
  -> PipelineEffects
```

Facts can enter through commands, handlers, sync, or ephemeral daemon input.
Core records their bytes, admission scope, and timestamp, then queues them for
projection. Projection is the only path from fact bytes to standing context,
read-model rows, time wakes, and follow-up work.

Network bytes enter as `network_in` rows, become ephemeral protocol intents via
the daemon declaration, and then pass through ordinary handler dispatch.
Outbound bytes are produced by protocol handlers, staged as `network_out` rows,
and written by core's TCP pump without parsing frame payloads.

Time enters through daemon-owned `DaemonTimeWake` declarations. Core selects
due `time_wakes`, attaches the due `TimeRange` to projection context, and lets
the owning projector decide whether that time proves anything.

## Invariants

- Fact ids are deterministic BLAKE3 hashes of immutable fact bytes. Scope and
  timestamp are local admission metadata, not part of content identity.
- Context rows are standing state owned by one fact. A projection output
  replaces the previous needs, offers, and time wakes for that owner.
- Context matching is protocol-blind range overlap over `(role, scope,
  start_key, end_key)`. Projectors must decode and validate matched payloads.
- Projectors do not query the store, perform IO, call handlers, or mutate
  process-local state.
- Intent queue identity is `(kind, idempotence_key)`. Re-emitting the same
  payload is idempotent; conflicting payloads for the same identity reject.
- Handler output commits atomically with deletion of the handled queue row.
  Retry errors leave the row queued.
- Row mutations are accepted only for tables declared by the selected runtime.
  The module that builds a row owns its columns, key bytes, and semantics.
- Store is below policy. It applies schemas, transactions, and row helpers; it
  does not interpret protocol rows, facts, context roles, or sync ranges.

## Responsibility Boundary

Change core when the reusable runtime mechanics change: queue ordering,
projection scheduling, context overlap matching, transaction boundaries,
effect validation, wire primitives, store behavior, network byte pumping,
daemon scheduling, or CLI hosting.

Change protocol when the meaning of a fact, row, context role, command, sync
range, invite, key, message, or connection frame changes. Protocol modules may
use core syntax and contracts, but core must not import their semantic rules.

## Module Map

- `app.rs`: generic CLI/application runner over a `ProtocolDescription`.
- `cli.rs`: small command registry, argument helpers, and text output type.
- `clock.rs`: store-local monotonic timestamp helper.
- `command_context.rs`: read-only command boundary plus identity capability
  traits.
- `context.rs`: public context vocabulary and canonical key helpers.
- `crypto.rs`: protocol-neutral cryptographic primitives.
- `daemon.rs`: process lifecycle, daemon tick ordering, time wake admission,
  and inbound network staging.
- `effects.rs`: shared `PipelineEffects` returned by commands, projectors, and
  handlers.
- `fact_store.rs`: fact admission, local admission metadata, ephemeral
  projection inputs, and purge helpers.
- `facts.rs`: fact ids, scopes, and immutable fact bytes.
- `intents.rs`: intent identity, row mutation types, and handler contracts.
- `network.rs`: opaque inbound/outbound network queues and TCP frame pump.
- `pipeline.rs`: facade for SQL-backed queue workers.
- `perf_profile.rs`: env-gated phase timing helpers for command and pipeline
  performance profiling.
- `projectors.rs`: projection contract, projection context, output, time wakes,
  and typed fact adapters.
- `runtime.rs`: executable core engine for one protocol description.
- `schema.rs`: core-owned SQL tables and table constants.
- `store.rs`: SQLite substrate, schema application, transactions, and opaque
  row helpers.
- `wire.rs`: fixed-layout wire reader/writer primitives.

## Example Runtime Graph

```text
content message fact
  -> pending_projection
  -> content message projector
     needs endpoint authority and key coverage
  -> context matcher wakes it when auth offers arrive
  -> projector emits message rows and share_fact_with_sync intent
  -> sync handler records leaf contribution
  -> connection handler later frames the shared fact for a peer
```

Core owns the arrows and atomic commits in this graph. Auth, content, sync, and
connection own the meaning of the facts and rows on those arrows.
