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
time wakes, and opaque network bytes through the declared runtime workers.

A normal command is a serialized runtime turn. Core opens the store, passes the
store and command clock to protocol command code, and commits the command's
authored facts. Core stores their immutable bytes, records local admission
metadata, and marks them pending for projection. The command can return
human-readable `CliOutput`, but command-authored durable protocol state must
enter through facts; rows, purges, and intents come from projection or handler
work.

Projection is core's deterministic reaction step. Core drains
`pending_projection`, loads one fact and the matched context attached to that
pending row, resolves any newly declared needs that already match stored offers,
calls the protocol projector until the item settles, and commits the output.
That commit replaces the fact's owned needs and time wakes; appends newly
emitted offers as durable evidence; applies allowed row mutations; admits
emitted facts; queues follow-up intents; and wakes other fact owners whose
standing needs now overlap newly added offers. Core performs the overlap query
mechanically when it queues the work, but projectors decide what the matched
payload proves.

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
- `app::ProtocolDescription` adds the product name, daemon declarations, and
  CLI command table.
- `project_fact::Projector` receives one `Fact` plus a `ProjectionContext` and
  returns a `ProjectionOutput`; fact families keep decode, authenticate, adapt,
  and semantic projection helpers inside their owning `project.rs`.
- `intents::IntentHandler` receives one idempotent `Intent` plus a
  `HandlerContext` containing only declared input facts and returns
  `RuntimeEffects`.
- `command` defines the protocol-neutral command clock, local capability value
  types, and authored command output. User-facing commands receive `Store` and
  `CommandClock` directly, then query protocol-owned state before authoring
  facts.
- `effects::RuntimeEffects` is the shared language for projector and handler
  facts to admit, candidate facts, purges, row mutations, durable intents, and
  local intents.
- `store::SchemaSource` lets core, network IO, and protocol registry code
  declare SQL DDL, opaque row-table allowlists, and replay lifecycle for
  retained fact storage, resettable runtime state, and state-summary tables.

Data leaves core through the same narrow surfaces: commands receive
`CliOutput`, protocol queries read schema-owned rows through `Store`, daemon
handlers receive inbound frames as local intents, and network sends consume
opaque outbound rows from `network`.

## Data Flow

```text
CLI command / daemon / handler
  -> authored facts or RuntimeEffects
  -> fact admission and pending_projection
  -> projector
  -> context needs/offers, time wakes, rows, intents
  -> intent queue
  -> handler
  -> RuntimeEffects
```

Facts can enter through commands, handlers, sync, or incoming daemon input.
Core records durable bytes or candidate bytes with admission scope and
timestamp, then queues them for projection. Projection is the only path from
fact bytes to standing context, read-model rows, time wakes, and follow-up work.
Runtime work can record candidate facts in `candidate_facts`, submit local
(ephemeral, not-replayed) intents to `local_intents`, and mark facts whose
scheduled wake-up time has arrived as pending projection work.

Network bytes enter as `network_in` rows, become local protocol intents via the
daemon declaration, then stage protocol frame facts as candidates. Candidate
frame facts may be retained while they wait on observation, connection, or key
context. Outbound bytes are produced by protocol handlers, staged as
`network_out` rows, and written by core's TCP pump without parsing frame
payloads.

Time enters through daemon-owned `DaemonTimeWake` declarations. Core selects
due `time_wakes`, attaches the due `TimeRange` to projection context, and lets
the owning projector decide whether that time proves anything.

## Invariants

- Fact ids are deterministic BLAKE3 hashes of immutable fact bytes. Scope and
  timestamp are local admission metadata, not part of content identity.
- Context rows are standing state owned by one fact. A projection output
  replaces the previous needs and time wakes for that owner, while newly emitted
  offers append as durable evidence until the owner fact is purged.
- Context matching is protocol-blind range overlap over `(role, scope,
  start_key, end_key)`. Projectors must decode and validate matched payloads.
- Projectors do not query the store, perform IO, call handlers, or mutate
  process-local state.
- Intent queue identity is `(kind, idempotence_key)`. Re-emitting the same
  payload is idempotent; conflicting payloads for the same identity reject.
- Handler output commits atomically with deletion of the handled queue row.
  Retry errors leave the row queued.
- Projection mode is sticky toward replay. If an owner is already queued in
  replay mode, later normal wakes do not downgrade it.
- Needs are replacement subscriptions. The settled `ProjectionOutput` is the
  complete standing need set for that fact; emitting no needs marks the fact no
  longer parked on context.
- Durable offers are append-only evidence. Once a fact offers context, that
  offer remains until the fact is purged.
- Rejected durable projection items do not stall the batch. Context-free
  rejection purges the fact; context-dependent rejection keeps the fact bytes as
  evidence and clears only the pending row.
- Candidate facts start as temp rows. A projector may keep a candidate retained
  while parked on standing context needs, retain it as protocol evidence, or
  drop it.
- Typed-table inserts are idempotent only when the existing row matches every
  supplied column; changing typed projection state is expressed as
  `DeleteWhere` followed by `InsertValues`.
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
- `command.rs`: command authoring primitives. It defines the command clock,
  local signing/encryption capability value types, workspace id alias, and
  authored receipt-plus-facts output. Commands query `Store` directly and do
  not get a runtime handle, handler dispatcher, network socket, or write
  transaction.
- `context.rs`: public vocabulary for standing context relationships. It
  defines needs, offers, roles, opaque byte keys, canonical key construction,
  replacement need subscriptions, append-only offer evidence, and the
  protocol-blind overlap rule that lets core wake facts without understanding
  their semantics.
- `crypto.rs`: reusable primitive facade for hashes, signatures, key exchange,
  authenticated encryption, and checked byte slices. It centralizes low-level
  library calls. Protocol modules still own signing domains, associated data,
  key lifetimes, authority checks, and semantic validation.
- `daemon.rs`: long-running process lifecycle and tick ordering. It owns the
  store lock, listener setup, readiness/stop/reset handling, inbound frame
  staging, due time-wake admission, and bounded projection/intent/projection
  drain loop. The protocol declaration decides how inbound bytes become local
  intents and which time-wake timelines are active.
- `effects.rs`: shared effect language for projectors and handlers.
  `RuntimeEffects` names facts to admit, candidate facts, exact purges, row
  mutations, durable intents, and local intents. The shared commit helper writes
  this mechanical description atomically inside the caller's transaction;
  commands use `AuthoredCommand` facts plus a receipt instead.
- `facts.rs`: protocol-neutral fact identity and visibility scope. It defines
  fact ids as BLAKE3 hashes of immutable bytes, the `Fact` container, and the
  `Global`, `Local`, and protocol-defined `Scoped` visibility model. It does
  not interpret fact tags, signatures, messages, keys, or sync payloads.
- `intents.rs`: queued work and handler contract types. It defines durable and
  local intent identity, opaque payloads, row mutation values, handler input
  declarations, retry/fatal handler errors, and the rule that handlers return
  `RuntimeEffects` instead of mutating runtime state directly.
- `network.rs`: opaque network IO boundary. It owns memory-local inbound and
  outbound queue rows, deterministic route+bytes row keys, listener setup,
  length-prefixed TCP frame reading/writing, and cleanup. It does not classify
  bootstrap frames, connection frames, auth facts, sync facts, or content facts.
- `handle_intent.rs`: one queued intent transaction. It claims one durable or
  local intent, loads only handler-declared fact inputs, calls the registered
  handler, handles retry/fatal outcomes, and commits handler output atomically
  with queue-row deletion. It also owns handler route metadata, handler sets,
  recurring intent schedules, work status, and replay dispatch filtering.
- `perf_profile.rs`: env-gated performance instrumentation. It records coarse
  phase timings in thread-local state only when explicitly enabled, preserving
  normal command output by default. It is for runtime profiling, not protocol
  measurement semantics.
- `project_fact.rs`: one queued fact projection transaction. It loads matched
  context and due time ranges, runs the routed projector, applies
  durable/candidate source rules, replaces the owner's needs/time wakes,
  appends offers, wakes matched owners, and commits emitted effects.
- `runtime.rs`: executable engine for one selected protocol description. It
  opens stores, applies declared schemas, submits command-authored facts, drains
  projection and intent queues, admits due time wakes, filters command-safe
  handlers, and composes `project_fact.rs` and `handle_intent.rs` into bounded
  runtime turns.
- `schema.rs`: core-owned SQL table inventory. It declares facts, local
  admissions, context edges, time wakes, pending projection, candidate facts,
  pending projection matches, intent queues, local network
  tables, and the local clock table. Protocol rows live in protocol schema
  sources.
- `store.rs`: SQLite substrate below runtime policy. It applies schema batches,
  opens transactions, quotes identifiers, validates opaque row-table allowlists,
  provides immutable fact storage primitives, and provides generic keyed row
  helpers. It does not know what a fact tag, context role, network frame, or
  protocol row means.
- `wire.rs`: fixed-layout byte primitive layer. It provides exact-length
  readers/writers, big-endian integers, one-byte booleans, bounded padded
  slots, and trailing-byte checks. Owning fact and intent modules layer tags,
  semantic validation, signatures, and test vectors on top.

### Runtime Work Sections

The runtime contract is split by ownership: `project_fact.rs` keeps the
protocol-neutral projection contract, route metadata, shared commit/context
helpers, and fact queue worker; `handle_intent.rs` keeps handler route metadata,
handler sets, replay dispatch policy, and the intent queue worker. `runtime.rs`
composes those pieces into command, daemon, and replay turns. Protocol
projectors own raw decoding, validation, adaptation, and semantic projection;
core owns queueing, matched context, needs/offers, effect commits, and replay
mode.

- `project_fact.rs::route`: tag route declarations, projector route metadata,
  and the protocol-owned fact admission hook type.
- `project_fact.rs::context`: in-memory `ProjectionContext`, matched payload
  facts, projection mode, and due time ranges visible while one fact is being
  processed.
- `project_fact.rs::effects`: `ProjectionOutput`, time wakes, and due time
  ranges. Projection output is the complete need/time-wake replacement, new
  append-only offers, plus shared `RuntimeEffects` for one fact.
- `project_fact.rs::commit_effects`: shared atomic commit path for
  `RuntimeEffects`. It validates duplicate or conflicting effects, purges exact
  facts, admits durable facts, candidate facts, row mutations, and queues
  follow-up intents inside the caller's transaction.
- `project_fact.rs::context_store`: SQL implementation of standing context. It
  stores need/offer edges, assembles projection context from queued
  `pending_projection_matches`, computes replacement-need and append-only-offer
  deltas by owner, and fans out pending projection rows when new needs and
  offers overlap.
- `handle_intent.rs`: intent queue worker. It claims one durable or local
  intent, loads only the handler-declared fact inputs, calls the registered
  handler, handles retry/fatal outcomes, and commits handler output atomically
  with queue-row deletion.
- `project_fact.rs`: one queued fact projection item. It loads matched context
  and due time ranges, runs the routed projector, replaces the owner's
  needs/time wakes, appends offers, and commits emitted effects.
- `runtime.rs`: bounded work ordering. It admits facts and due time wakes,
  selects durable and candidate projection items through `project_fact.rs`,
  dispatches queued intents through `handle_intent.rs`, and lets context wakes
  or emitted child facts re-enter the queue explicitly.

### Projection Path And Commit Boundary

The write-side authoring path is:

```text
command -> author -> encode -> protocol self-check -> AuthoredCommand facts -> admit -> projection
```

Commands own user intent, argument parsing, local capability lookup, receipts,
and the decision to author facts. They return `AuthoredCommand` facts plus a
receipt, not row mutations, purges, or intents. Family `author.rs` owns
construction crypto: signing, encryption, and typed assembly. Family
`encode.rs` owns canonical byte encoding only. Before storage, the runtime may
call the protocol-owned `FactAdmissionFn`; poc-10 installs one that dispatches
by fact tag to protocol-local decode and validation helpers. After admission
each fact is queued for projection like any other durable fact.

The routed fact path is:

```text
raw fact -> tag route -> projector -> ProjectionOutput -> commit
```

The core projection worker stays protocol-neutral. It loads one durable or
candidate fact, the matched context already attached to that pending row, due
time ranges, and projection mode, then invokes the registered protocol
projector. A typical projector locally decodes the raw body, validates the fact
id and cryptographic/container proof, requests missing context as needs,
validates matched offers when present, adapts any legacy payload shape, and
projects rows, context, time wakes, purges, or intents.

Missing context is normal projection output, not a separate core stage. The
projector emits standing needs; core records those replacement needs and parks
the fact. When a later offer matches a parked need, core records that offer in
`pending_projection_matches` for the parked owner and queues the owner again.
The pending item already carries the context that woke it, so the retried
projector reads the matched payload through `ProjectionContext` instead of
doing a database search.

Detached signature evidence, key material, deletion markers, receipts, and
other cross-fact proof are ordinary facts that may publish context offers after
their own projector accepts them. A consumer projector still validates that the
matched offer applies to the current fact before treating it as authority.

For a durable fact, one projection commit performs this ordered unit:

```text
delete durable pending row
delete queued pending_projection_matches for this owner
clear due time range rows for this owner
delete old needs and time wakes owned by fact
insert new needs, append new offers, and insert new time wakes
wake owners whose needs match newly added offers and record their matched context
apply RuntimeEffects through commit_effects
```

For a retained candidate fact, the commit moves the candidate into `facts` and
`local_fact_admissions`, then applies the same context/time/effect commit as a
durable fact. For a dropped candidate fact, the commit validates that no durable
offers or time wakes remain, deletes any old context for that input id, deletes
the candidate fact row, and applies `RuntimeEffects` through `commit_effects`.

Before that boundary, projector runs are calculation. Durable pending items
start with the matched context already attached to their queue row. Newly
declared needs are matched during commit and wake a later queue item; the
projector does not search the store for more context during the same run.

### Handler Commit Boundary

One handler commit performs this ordered unit:

```text
delete claimed intent row
delete shadowed local duplicate intent when the claimed row was durable
purge exact facts
admit emitted facts and mark them pending
insert emitted candidate facts
apply row mutations
record durable follow-up intents
record local follow-up intents
```

If any step fails, SQLite rolls back the whole unit. This is what makes handler
replay and process restart safe. Retry errors leave the intent row in place;
fatal errors consume the row only when the fatal outcome itself commits.

### Replay And Time Wakes

A projector can schedule its own fact on a protocol timeline. When the daemon
advances that timeline, core marks matching fact owners in
`pending_projection`, stores the due `TimeRange`, and projection context
exposes that range without allowing projectors to read the clock.

Replay uses the same projection and handler paths with a different runtime
mode. It preserves only the retained fact store (`facts` plus
`local_fact_admissions`), clears schema-declared resettable runtime state,
queues retained facts and replayable scheduled wake-ups into
`pending_projection` with mode `replay`, exposes that mode through
`ProjectionContext::is_replay()`, and keeps facts emitted during replay in
replay projection mode. Projectors use replay mode to avoid live-only
projection intents. During replay dispatch, handlers receive
`HandlerContext::is_replay()` and return empty effects at live-only edges.
Recurring work is represented as recurring intents; the live daemon's in-memory
cadence is only the scheduling mechanism that enqueues due work.

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
