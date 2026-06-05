# Core

Core is the protocol-neutral runtime substrate. A different protocol should be
able to reuse it unchanged: core stores immutable facts, matches context ranges,
runs projectors, dispatches queued intents, commits effect batches, hosts CLI
and daemon loops, and moves opaque network bytes. It must not know what a
workspace, message, invite, key wrap, sync range, or connection fact means.

## How Core Works

Core is the reusable runtime loop around a protocol declaration. At startup the
app hands core a `ProtocolDescription`; core opens the selected SQLite store,
applies core, network, and protocol schemas, builds the command registry, and
constructs a `Runtime` from the declared projector, handler registry, row
allowlist, schema sources, and daemon hooks. From that point on, core does not
ask what a protocol fact means. It only moves facts, context, rows, intents,
time wakes, and opaque network bytes through the declared pipeline.

A normal command is a serialized runtime turn. Core opens the store, builds a
`CommandContext`, calls the protocol command, and commits the command's
`PipelineEffects`. If the command emitted facts, core stores their immutable
bytes, records local admission metadata, and marks them pending for projection.
The command can return human-readable `CliOutput`, but durable protocol state
must enter through facts, row mutations, or intents.

Projection is core's deterministic reaction step. Core drains
`pending_projection`, loads one fact and its matched context, resolves any
newly declared needs that already match stored offers, calls the protocol
projector until the item settles, and commits the output. That commit replaces
the fact's owned needs, offers, and time wakes; applies allowed row mutations;
admits emitted facts; queues follow-up intents; and wakes other fact owners
whose standing needs now overlap newly added offers. Core performs the overlap
query mechanically, but projectors decide what the matched payload proves.

Intents are core's bounded stateful work step. A projector or command emits an
intent when the next action should not happen inside deterministic projection:
sending bytes, building a response fact, creating a key wrap, seeding sync, or
performing any other retryable action. Core claims one durable or local intent,
loads only the fact inputs declared by that handler, calls the registered
handler, and commits the handler's output atomically with queue consumption.
Retry leaves the row queued; success deletes the row with its effects.

The daemon runs the same mechanics without a user command on the stack. Each
tick stages accepted network bytes as local protocol intents, admits due
time-wake ranges as pending projection, drains projection, dispatches intents,
and drains projection again for handler-emitted facts. The runtime lock ensures
this daemon work cannot race with a CLI command that is admitting new facts into
the same store.

Core's job is therefore coordination, persistence, and mechanical validation.
It owns the serialized turn shape, SQLite transaction boundaries, queue
fairness, idempotent fact and intent admission, protocol-blind context matching,
network byte pumping, and schema/row allowlist checks. It leaves protocol
meaning in the protocol scopes: fact layouts, authority checks, sync policy,
connection-frame opening, read-model rows, commands, and queries.

## Interface To Protocol

Protocol code enters core through declarations and effect values:

- `runtime::RuntimeDescription` declares protocol schema sources, allowed row
  mutation tables, the projector factory, registered intent handlers, and
  command-excluded handler names.
- `app::ProtocolDescription` adds the product name, daemon declarations, CLI
  command table, and command context constructor.
- `pipeline::Projector` receives one `Fact` plus a `ProjectionContext` and
  returns a `ProjectionOutput`; staged families also implement the pipeline
  decode, authenticate, adapt, and semantic project traits.
- `intents::IntentHandler` receives one idempotent `Intent` plus a
  `HandlerContext` containing only declared input facts and returns
  `PipelineEffects`.
- `command_context::CommandContext` gives user-facing commands read-only store
  access, a monotonic timestamp source, and identity-owned local capabilities.
- `effects::PipelineEffects` is the shared language for facts to admit,
  ephemeral facts, purges, row mutations, durable intents, and local intents.
- `store::SchemaSource` lets core, network IO, and protocol registry code
  declare SQL DDL, opaque row-table allowlists, and replay lifecycle for
  protected, resettable, and state-summary tables.

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

### Top-Level Files

- `app.rs`: generic process runner over a `ProtocolDescription`. It owns the
  product-independent CLI shape: `--db`, daemon lifecycle commands, command
  lookup, runtime opening, command dispatch, and the `assert eventually` helper.
  Protocol code supplies declarations and command functions; core supplies the
  stable host behavior.
- `cli.rs`: tiny command registry and text-output boundary. It validates
  duplicate command names, reports unknown commands with usage, carries
  positional arguments, and returns display lines. It does not parse
  protocol-specific options beyond handing arguments to the registered command.
- `clock.rs`: store-local logical clock for deterministic authoring and tests.
  It is local runtime metadata, not synced protocol state. Commands use it as a
  lower bound for new timestamps without changing the timestamp semantics of
  already-authored facts.
- `command_context.rs`: read-only command boundary. Commands get store queries,
  monotonic timestamp allocation, and identity-owned signing/encryption
  capabilities through this type. They do not get a runtime handle, handler
  dispatcher, network socket, or write transaction.
- `context.rs`: public vocabulary for standing context relationships. It
  defines needs, offers, roles, opaque byte keys, canonical key construction,
  complete replacement context sets, and the protocol-blind overlap rule that
  lets core wake facts without understanding their semantics.
- `crypto.rs`: reusable primitive facade for hashes, signatures, key exchange,
  authenticated encryption, and checked byte slices. It centralizes low-level
  library calls. Protocol modules still own signing domains, associated data,
  key lifetimes, authority checks, and semantic validation.
- `daemon.rs`: long-running process lifecycle and tick ordering. It owns the
  store lock, listener setup, readiness/stop/reset handling, inbound frame
  staging, due time-wake admission, and bounded projection/intent/projection
  drain loop. The protocol declaration decides how inbound bytes become local
  intents and which time-wake timelines are active.
- `effects.rs`: shared effect language for commands, projectors, and handlers.
  `PipelineEffects` names facts to admit, ephemeral facts, exact purges, row
  mutations, durable intents, and local intents. The pipeline commits this
  mechanical description atomically; display-only command data stays outside it.
- `fact_store.rs`: immutable fact storage and local admission metadata. It
  inserts content-addressed fact bytes, records local scope/timestamp/admission
  ordering, marks facts pending for projection, reads facts back with their
  local metadata, and purges exact fact ids plus core-owned derived rows.
- `facts.rs`: protocol-neutral fact identity and visibility scope. It defines
  fact ids as BLAKE3 hashes of immutable bytes, the `Fact` container, and the
  `Global`, `Local`, and protocol-defined `Scoped` visibility model. It does
  not interpret fact tags, signatures, messages, keys, or sync payloads.
- `intents.rs`: queued work and handler contract types. It defines durable and
  local intent identity, opaque payloads, row mutation values, handler input
  declarations, retry/fatal handler errors, and the rule that handlers return
  `PipelineEffects` instead of mutating runtime state directly.
- `network.rs`: opaque network IO boundary. It owns memory-local inbound and
  outbound queue rows, deterministic route+bytes row keys, listener setup,
  length-prefixed TCP frame reading/writing, and cleanup. It does not classify
  bootstrap frames, connection frames, auth facts, sync facts, or content facts.
- `pipeline.rs`: public facade for fact lifecycle contracts and SQL-backed
  queue workers. It names the route, decode, authenticate, adapt, project,
  effects, and commit stages, and runtime calls it to submit facts and intents,
  admit due time wakes, drain pending projection, dispatch queued intents, and
  purge exact facts. The concrete stage contracts and worker code live in the
  pipeline submodules below.
- `perf_profile.rs`: env-gated performance instrumentation. It records coarse
  phase timings in thread-local state only when explicitly enabled, preserving
  normal command output by default. It is for runtime profiling, not protocol
  measurement semantics.
- `projectors.rs`: transitional re-export facade for the fact-processing
  pipeline. New code should import from `pipeline`; this file keeps existing
  protocol modules compiling during fact-by-fact cutover.
- `runtime.rs`: executable engine for one selected protocol description. It
  opens stores, applies declared schemas, submits command effects, drains
  projection and intent queues, admits due time wakes, filters command-safe
  handlers, and composes the pipeline pieces into bounded runtime turns.
- `schema.rs`: core-owned SQL table inventory. It declares facts, local
  admissions, context edges, time wakes, pending projection, ephemeral
  projection inputs, intent queues, local network tables, and the local clock
  table. Protocol rows live in protocol schema sources.
- `store.rs`: SQLite substrate below runtime policy. It applies schema batches,
  opens transactions, quotes identifiers, validates opaque row-table allowlists,
  and provides generic keyed row helpers. It does not know what a fact, context
  role, network frame, or protocol row means.
- `wire.rs`: fixed-layout byte primitive layer. It provides exact-length
  readers/writers, big-endian integers, one-byte booleans, bounded padded
  slots, and trailing-byte checks. Owning fact and intent modules layer tags,
  semantic validation, signatures, and test vectors on top.

### Pipeline Submodules

- `pipeline/route.rs`: tag route declarations and staged route metadata that
  reviewers use to see each family's first-class pipeline stages.
- `pipeline/decode.rs`: decode-stage trait. Core owns when decoding happens;
  protocol families own how their bytes become typed payloads.
- `pipeline/authenticate.rs`: authentication-stage contracts and helpers:
  `AuthenticatedFact`, `Authentication`, `Authenticator`,
  `DecodedAuthenticator`, `authenticate_authored`, and `verify_fact_id`.
- `pipeline/adapt.rs`: adapter-stage trait for moving from authenticated source
  shape to the semantic value projected at the active head version.
- `pipeline/project.rs`: project-stage contracts and staged runners. It exposes
  `SemanticProjector` and `project_staged`, which compose
  decode/authenticate/adapt/project for routed facts.
- `pipeline/context.rs`: in-memory `ProjectionContext`, matched payload facts,
  due time ranges, and typed payload helpers visible while one fact is being
  processed.
- `pipeline/effects.rs`: `ProjectionOutput`, time wakes, and due time ranges.
  Projection output is the complete context/time-wake replacement plus shared
  `PipelineEffects` for one fact.
- `pipeline/commit_effects.rs`: shared atomic commit path for
  `PipelineEffects`. It validates duplicate or conflicting effects, purges exact
  facts, admits durable and ephemeral facts, applies allowed row mutations, and
  queues follow-up intents inside the caller's transaction.
- `pipeline/context_store.rs`: SQL implementation of standing context. It stores
  need/offer edges, assembles projection context with matched payload facts,
  computes replacement deltas by owner, and fans out pending projection rows
  when new needs and offers overlap.
- `pipeline/dispatch.rs`: intent queue worker. It claims one durable or local
  intent, loads only the handler-declared fact inputs, calls the registered
  handler, handles retry/fatal outcomes, and commits handler output atomically
  with queue-row deletion.
- `pipeline/insert_select.rs`: checked `INSERT OR IGNORE ... SELECT` helper
  used by queue fanout. It accepts only static comment-free `SELECT` statements
  over declared source tables and bound parameters, keeping dynamic scheduling
  SQL narrow and auditable.
- `pipeline/pipeline_one.rs`: one queued fact pipeline item. It loads matched
  context and due time ranges, runs staged decode/authenticate/adapt/project
  routes, replaces the owner's context/time wakes, and commits emitted effects.
- `pipeline.rs`: runtime state machine and pending projection queue drain. It
  admits facts and due time wakes, selects durable and ephemeral projection
  items, applies the one-item pipeline step, and lets
  context wakes or emitted child facts re-enter the queue explicitly.

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
