# Topo rewrite

I want to rewrite topo with clarity on:

* interfaces
* the invariants they guarantee
* decoupling
* realms of responsibility (and *non* responsibility)
* event-based networking
* what crucial design decisions contributors and agents must take not to break 

See appendix for documentation style rules and references.

# Core

`core/` is protocol-agnostic. It provides the generic substrate needed by any
protocol:

- canonical byte and table-row storage,
- queue tables and idempotent table-row writes,
- opaque network queue row types and generic target/source queue mechanics,
- generic TCP listener/connect/read-frame/write-frame mechanics,
- storage operations used by protocol-owned wait queues,
- generic transactions and storage queries,
- generic Crux app/effect driving, isolated from protocol code.

Core does not decide admission, blocking, dependency meaning, signature/auth
validity, which projector runs, connection, bootstrap, transit, sync ranges,
workspaces, content, endpoint identity, codec format, or CLI command semantics.
A different protocol should be able to reuse `core/` by providing its own
scoped workers, event registry, tables, wire helpers, and CLI command registry.

The current code split follows that boundary:

```
src/core/
  store.rs
  crux_runner.rs
  network_queues.rs
  tcp.rs

src/protocol/
  cli.rs           // current protocol CLI composition
  event_modules/
    worker.rs       // common event-module admission/apply worker
    connection/
      worker.rs     // connection-scope queued work
    sync/
      worker.rs     // sync-scope queued work
  wire.rs
```

# Protocol

`protocol/` is the current Topo protocol built on the reusable core. It owns
all event families, domain workers, protocol byte meaning, and CLI commands. A
completely different protocol should be able to replace `protocol/` while
reusing `core/`.

`protocol/cli.rs` composes the current Topo CLI. Command semantics and output
types should live in the closest relevant scoped `cli.rs`; protocol-level CLI
code only coordinates commands that cross module scopes, such as aggregate
status/count and synchronous calls into the core TCP runner for this POC. There is no
`protocol/app` layer. Crux remains available only as generic core runner
machinery; protocol code must not define Crux app/model/effect types.

**event_modules/** contains every protocol or domain behavior that can be
expressed as events, projectors, commands, module-owned tables, and module
workers. This includes content, identity, auth, connection, sync, and local-only
behavior. A built-out module owns its schema/read model next to its event type:
this is the poc-7 `message` / `reaction` pattern and the poc-6
`message.py` + `message.sql` pattern. Do not split "event type" and "tables"
into separate conceptual homes; tables live with the module that owns the
projection or queue. A domain may also own shared tables and
workers at the domain root when those tables coordinate several leaf event
modules.

`protocol/mod.rs` defines the current protocol composition object. That object
owns the event-module registry.
`protocol/event_modules/worker.rs` is the event-module-scope admission/apply
worker: it hashes canonical bytes, applies this protocol's dependency/scope
rules, calls this protocol's registry, and applies projector rows through core
storage. It also owns the default Topo blocking policy: immediate dependencies
declared by the codec/record are checked before projection, and missing
dependencies are written to the protocol's blocked-event queue.
`protocol/wire.rs` contains shared fixed-field binary helpers used by protocol
codecs; it is shared by modules, but it is still protocol infrastructure.
`protocol/event_modules/mod.rs` imports concrete protocol families and exposes
the narrow registry surface used by the protocol shell and tests. `core/` does
not call event parse/project traits and does not import concrete event
families. The protocol shell calls through the protocol composition object and
does not import `connection`, `sync`, `content`, or `identity` directly. Module
workers interpret inbound byte rows, canonical events, queues, and route state.

Suggested organization:

```
src/protocol/event_modules/
  content/
    message/
      types.rs
      codec.rs
      commands.rs
      projector.rs
      schema.rs
      queries.rs
      mod.rs
    reaction/
      ...
    file/
    cli.rs          // optional content-level command registry/help
  identity/
    workspace/
    user/
    peer/
    cli.rs
  auth/
    invite/
    key/
    removal/
    cli.rs
  connection/
    worker.rs
    schema.rs
    queries.rs
    types.rs
    cli.rs
    connection/
    connection_secret/
    observed_address/
  sync/
    worker.rs
    schema.rs
    queries.rs
    types.rs
    cli.rs
    compare/
    have/
    need/
    frame/
    dep_cache/
  local/
    local_secret/
    clock_wake/
```

**Per-file pattern, always.** Every leaf event module is a directory with one
file per concern (`types.rs`, `codec.rs`, `projector.rs`, `commands.rs`,
`schema.rs`, `queries.rs`, `cli.rs`, `registry_meta.rs`, `mod.rs`, etc.) — even when a
module is small enough that a single `.rs` file would suffice. `schema.rs` is
where the module declares its projection tables, indexes, queues, cursors, and
storage class. A domain root may also contain `schema.rs`, `queries.rs`,
`types.rs`, `worker.rs`, and `cli.rs` when it owns shared tables, a worker, or a
domain-level CLI command registry coordinating several leaf event modules.
There is no generic `jobs/` or `cli_commands/` dumping ground and no fake event
module for an algorithm: `sync/worker.rs` may run negentropy over `sync/schema.rs`;
`negentropy/` is only a child module if it defines an actual event type. `worker`
is the component noun; `run` is the method verb.
The cost is some empty-ish files in tiny modules; the win is that this is
intentional friction. In a codebase where most code is assistant-generated,
uniform shape across the surface makes accumulating logic easy to spot — files
that grow disproportionately, or directories that sprout extra concerns, are
the audit signal that something needs simplification or splitting. No collapsed
single-file event modules.

This rule is in conscious tension with "let complexity earn length" in the documentation quality bar (see appendix): that rule applies to *prose* in docs, this rule applies to *code structure* in event modules. Both stand.

**networking** All complex networking behavior including bootstrap,
connection, transit, and sync is implemented in event modules: commands propose
events, projectors write rows, module workers decide what to run next, and
connection/transit modules wrap and unwrap transit blobs. Core network queues
carry only `target/source + opaque bytes`, and core TCP only frames and moves
those bytes to concrete transport targets. Connections are
between two endpoints (daemons) and sync all data in all workspaces those two
endpoints share. Every workspace-scoped event carries its own `workspace_id`;
endpoint-scoped events (connection, intro, observed_address, self_address,
prekey events) carry endpoint identity instead. A daemon hosts at most one
instance of any given workspace, so for workspace-scoped events `workspace_id`
alone identifies the local processing scope and there is no separate
"recorded_by". See **Event Scopes** below for the full taxonomy.

**worker.rs** is the only active-component filename. A worker lives at the
scope whose queues/cursors it owns. `protocol/event_modules/worker.rs` covers
common canonical event admission/apply for all event modules. A domain worker
such as `sync/worker.rs` covers active sync queues and cursors. There is no
`protocol/worker.rs`: protocol root is too broad to own a worker.
Every `worker.rs` exposes one public free function, `run`, as the obvious
entrypoint. Public work/output types describe the worker boundary; helper
functions stay private.

Default dependency blocking is centralized in the event-modules worker after
record decoding and before projection. Projectors remain expressive by writing
module-owned wait/blocked rows for semantic blockers that are not just
immediate missing dependencies, but they do not each reimplement the common
dependency wait queue.

**control loop** means the protocol's worker scheduling policy. It claims
bounded batches of queue rows, dispatches to the owning worker, applies returned
state writes atomically through core storage, and admits returned events
through the event-modules worker. Workers queue network IO by writing
`OutboundNetworkRow`s with target metadata; core TCP drains those rows as
opaque frames. Core
provides queue and transaction mechanics; protocol owns which workers exist
and what their work means.

**state** is the explicit table-shaped substrate that projectors and workers observe. It is materialized from event-module table declarations and can be a database in production or an in-memory store in testing and simulation.

**core network queues** contain one outbound table and one inbound table. The
outbound queue is not split into per-target tables; `target` is metadata encoded
into the row key so core can claim a bounded batch for one target with a generic
key-prefix scan. `Store` only exposes generic table-row and prefix-scan
mechanics; `core/network_queues.rs` owns the typed row wrappers and queue
encoding.

**core TCP** drains and fills opaque network queue rows. It owns listener,
connect, length-prefixed frame read/write, socket shutdown, and transport
backpressure mechanics. It does not create or interpret transit blobs,
canonical event bytes, sync frames, invites, or connection ids.

**workers** are module-owned active components woken by queue rows, timers, IO
readiness, or explicit CLI requests. A worker declares its wake sources, read
set, and write set. Core uses those declarations to load bounded context
and commit output; the worker owns the semantic decision. Use `wake` for
scheduling and `run` for execution.

**cli.rs** is the module-local CLI adapter. It owns help text, parameter names,
domain command invocation, follow-up queries, and output formatting for the
commands that belong to that module or domain. The generic CLI runner stays
boring: parse global flags, find the module CLI command, run proposed events,
then hand control back to the module CLI command for queries and formatting.

For a write command, the module CLI calls a pure module command to produce
`ProposedEvent`s with deterministic ids, asks the runner to process exactly
those proposed events, then runs whatever module query is needed for output:

```
let proposed = message::commands::create(params, context)?;
let applied = runner.run_proposed(proposed.events)?;
let row = message::queries::by_event_id(store, applied.primary_id)?;
CliOutput::text(message::cli::format_created(row))
```

`run_proposed` means "admit and apply this proposed chain enough that its own
projection rows are visible." It does not drain unrelated ready events. Query-only
commands simply run module queries and format output. Commands that need
external progress, such as `sync` or `assert-eventually`, say that explicitly by
waking the owning worker or polling a module query.

CLI scenario/check/expect definitions live in the closest event module or
domain root, not in the app shell. A generic scenario runner can still execute
the real `topo` binary and real TCP; the scenario's setup, command sequence,
and expected output stay local to the behavior being specified.

`cli_test.rs` follows the same scope rule as `cli.rs`. A leaf event module test
owns scenarios for that event type; a domain-root test owns workflows spanning
its child event modules; protocol-level tests are only for cross-domain
end-to-end behavior. The shared CLI harness is deliberately uninteresting:
build/run the binary, allocate temp dbs and ports, capture output, and nothing
else. Command names, argv construction, invite editing, retries, polling, output
keys, and expected results belong to the scoped test file. If we add a generic
scenario type, it should be a small data contract like:

```
CliScenario {
  name,
  setup,
  steps: [argv + optional timeout + expect(stdout, stderr, status)]
}
```

The scenario type must not know Topo command semantics; it only standardizes how
scoped tests submit params and checks to the black-box runner.

The substrate pieces outside `event_modules` are deliberately narrow:

```
core/crux_runner.rs      // generic Crux app/effect driving
core/store.rs            // typed table rows, memory/disk storage, transactions
core/network_queues.rs   // opaque inbound/outbound byte queue rows
core/tcp.rs              // generic length-prefixed TCP byte transport
protocol/cli.rs          // current Topo CLI composition
protocol/event_modules/worker.rs     // event-module admission/apply and blocking worker
protocol/wire.rs         // shared fixed-field protocol codec helpers
protocol/event_modules/  // protocol facts, projectors, tables, workers
```

If behavior is protocol semantics expressible as
events/projectors/commands/tables/workers, it belongs under `event_modules`. If
it owns Topo admission/apply semantics, it belongs in `protocol/event_modules/worker.rs`.
If it owns shared protocol encoding helpers, it belongs in `protocol/wire.rs`.
If it owns process execution, IO, storage mechanics, or queue mechanics, it
belongs outside event modules.

## Core State and Registry Interface

State is the set of declared tables the control loop can read and update atomically:

```
State_t =
  events
  + module-owned projection tables
  + boundary/work tables
  + declared caches
```

Processing has the shape:

```
Event + Context(State_t) -> StateUpdates
State_{t+1} = apply(State_t, StateUpdates)
```

`state` does not centrally know the domain schema. Each event module declares its schema and behavior:

```
module id
event types
tables it owns
indexes
storage class: durable | memory | temp
migrations / schema version
projectors
commands / workers
```

Those declarations form the runtime catalog:

```
event_modules/*/registry_meta.rs
  -> ModuleRegistry
  -> WorkerRegistry
  -> StateCatalog
  -> database / memory store schema
```

The event domain owns semantic meaning: what a row means, which projection
writes it, which indexes are required, which workers consume it, and whether it
may be rebuilt. A leaf event module owns one event type's codec, dependencies,
commands, projector, and leaf projection tables. A domain root owns shared
tables and workers that coordinate several leaves. `state` owns mechanics:
creating tables, applying migrations, opening transactions, inserting NewRows,
deleting Purges, querying declared indexes, resetting transient rows on
startup, and choosing durable vs memory storage.

Boundary tables should follow the same rule where possible. `outbox` is a
connection-domain queue declared by the connection domain root, `blocked_by_event`
by the ready-event loop, schedule rows by the owning module or `protocol/timers`,
and sync caches by the sync modules. The fewer central special tables, the
better.

## Protocol Admission And Codec Interface

**codec** is canonical event encoding and parsing. It is not necessarily network wire. A module's `codec.rs` defines `Event <-> CanonicalEventBytes`, the event type tag, field layout, dependency field declarations, signature and signer-family rules, and deterministic id rules. Canonical event layout is fixed-width per event type: once the type tag is known, the field layout and canonical byte length are known, though different event types may have different fixed lengths. `protocol/wire.rs` provides shared primitive reads/writes, fixed-size ids, truncation checks, and trailing-byte checks so codecs read as format descriptions.

**encode** encodes an Event to `CanonicalEventBytes`, returning a BLAKE3 event id, usually used by `create` or other domain-specific functions.

**parse** consumes `CanonicalEventBytes` and returns an Event, which includes all event values, its BLAKE3 hash id, its canonical bytes, and the `workspace_id` it belongs to, or throws an error if the bytes are invalid.

**canonical-event processing** is owned by `protocol/event_modules/worker.rs`. It hashes
the canonical bytes, checks protocol admission before loading context, parses
only newly admitted events, and then runs context/project/apply as one chained
step unless the event blocks.

Typed Rust event values are the in-process semantic representation. They should not carry canonical bytes as ordinary fields. Canonical bytes and ids are boundary artifacts:

```
Event type     = semantic fields
EncodedEvent   = event_id + event_type + CanonicalEventBytes
ParsedEvent<E> = E + EncodedEvent
```

For locally created events:

```
E
  -> encode(E)
  -> EncodedEvent
  -> insert/project
```

Local creation does not enqueue durable data for peers. Durable data transfer is driven by negentropy: compare events discover differences, have/need events identify missing ids, and only a `NeedId` response queues the requested durable event id to `outbox`.

For inbound events:

```
CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> ParsedEvent<E>
  -> project
```

Traits are the module API; canonical bytes are event identity. Projectors that need the id or original bytes receive them through `ParsedEvent<E>`, not because every event struct embeds them. This prevents typed values and encoded bytes from silently diverging.

**admit_event_id** consumes an event id and returns known or newly claimed. Known includes applied, blocked, rejected, and in-flight events. Duplicates record observations, call `suppress_received(id)` (see: Sync), and stop before context loading. Newly claimed ids become canonical event ids only after parse succeeds.

**get_context** consumes a newly admitted Event and returns an EventWithContext.
The protocol-owned default context for `project` is:

1. the parsed Event,
2. the other Events that the consumed Event names as immediate dependencies,
3. every `label` for that event,
4. generic origin metadata such as source socket address or received transport id.

This default should be sufficient for most projectors. If a projector needs more
state, first try to make that state an explicit dependency or a bounded label.
We can always add more dependency fields, and labels are the right substrate for
small derived facts such as authorization, trust-anchor, route, expiry,
supersession, or "this event blocks others." Do not introduce bespoke
per-event-type SQL queries against arbitrary state just because a dependency or
label is missing.

Custom typed context is allowed only for module-owned read models that are too
large or index-shaped to fit the default context. The module owns the context
request type, the context result type, and the semantics of the read model; the
protocol runner only routes the request/result and never inspects
module-specific fields.
The known required case is negentropy response projection: compare/have/need
responders need indexed summaries, bucket ids, presence checks, and event bytes
from module-owned sync/negentropy tables. That is context for the sync module,
not sync vocabulary in the core.

Connection and bootstrap projectors should not need custom context in the first
cut. Model their checks as first-level dependencies and labels:

- a connection request depends on the invite, peer-shared signer, or other
  signer/prekey facts needed to verify it;
- a connection ack depends on the request it acknowledges;
- invite acceptance creates or labels local trust anchors and route hints rather
  than reaching through custom context;
- observed/self address and route facts are labels or module rows consumed by
  sender/outbox workers, not projector-only hidden queries.

If a future connection or bootstrap behavior appears to need custom context,
the burden is to prove that extra dependencies or labels cannot express it
boundedly.

**labels** is a table whose rows are tuples of (event_id, label_type); adding a label can be a result of projection. Labels become part of context so there should be a bounded number of labels for a given event_id. "This event blocks others" can be a label. 

**blocking** is protocol-worker-owned policy over core-maintained queues. A blocked event remains an `events` row with `status = blocked`; each missing dependency is a `blocked_by_event(blocked_by_event_id, event_id)` row.

**project** consumes an EventWithContext and returns either RejectedEvent (if known invalid), BlockedEvent, or StateUpdates.

**apply** consumes StateUpdates, applies them to State, and returns an AppliedEvent. There must be no writes (or at least no *context-relevant* writes) between the `get_context` and `apply` steps.

**StateUpdates** is [Purges, NewRows] i.e. what to delete and what rows to write to State.

**Purges** is a list of event id's for `apply` to purge.

**NewRows** is a list of tuples (table, row) for adding new rows to sorted tables in State, e.g. in SQLite with INSERT OR IGNORE. All NewRows are indexed by (event_id, workspace_id) and adding a NewRow with the same index must be idempotent.

Semantic removal is expressed by durable facts or labels, not by the absence of old rows. Examples include `deleted:message_id`, `expired:event_id`, `removed:user_id`, `revoked:key_id`, and `superseded:invite_id`. A projector may remove visible projection rows immediately, but future correctness must come from the surviving fact, label, summary, or high-water mark.

`Purges` are physical compaction. In trace, simulation, and audit modes, time-based purge should be disabled so facts remain monotonic and replayable. In app/production mode, events and projection rows may be purged for deletion or TTL once no future projector needs their bytes or rows as the only evidence of what happened.

Invariant: purging may remove physical evidence, but it must not be the only representation of a semantic change. If future behavior depends on knowing that something was deleted, expired, revoked, removed, or superseded, some surviving row must say so after purge.

Queue-like work is represented as ordinary NewRows into module-owned tables. Boundary tables are used only at wait, dedupe, retry, schedule, and IO boundaries.

## Event Scopes

All events inserted into `events` have canonical bytes from a module `codec.rs`, even if they are never sent over the network. Canonical bytes provide the event id, dedupe key, replay form, dependency reference, and projector input.

```
durable event:
  workspace_id: yes
  codec: yes
  signed: yes
  may be sent to peers: yes

endpoint-scoped event:
  workspace_id: NO  (carries endpoint identity instead)
  codec: yes
  signed: yes
  may be sent to peers: yes
  examples: connection, connection_prekey, connection_prekey_shared, intro,
            observed_address, self_address

endpoint-local event:
  workspace_id: optional (e.g. negentropy/sync events name (connection_id, workspace_id))
  codec: yes
  signed: usually no
  may be sent to one endpoint/connection: yes

connection-scoped event:
  connection_id: yes
  workspace_id: optional, when the event concerns a workspace over the connection
  codec: yes
  signed: usually no
  core scope: Transient
  may be sent only on that connection
  id: BLAKE3(canonical bytes), with connection_id inside the bytes
  examples: sync_compare, sync_have_id, sync_need_id

local-only event:
  workspace_id: usually yes
  codec: yes, if stored/projected/deduped
  signed: usually no
  may be sent to peers: no

work item:
  codec: no, unless promoted into events
```

Examples of work items that do not need codecs are timer-fired, socket-writable, CLI-command-entered, and internal-wakeup notifications. Once something is inserted into `events`, referenced by id, deduped, blocked, replayed, or projected like an event, it needs canonical bytes.

## Protocol Worker Scheduler

The control loop is the protocol worker scheduler. It owns:

- the module registry,
- generic table-row storage,
- transaction boundaries,
- resource limits,
- queue commit ordering.

All domain behavior lives in event modules and their colocated workers. The
control loop should stay domain-agnostic within this protocol: it sees ready
events, opaque worker wakes, and worker output, not sync ranges,
connection handshakes, content semantics, or connection routes. Core maintains
the queues, transactions, opaque network queues, and TCP byte mechanics the
scheduler uses.

Queued work is typed:

```
WorkItem =
  ReadyEvent
  WorkerWake(worker_id, wake_key)
```

Each queue item has exactly one owning worker. The control loop calls one
function:

```
worker.run(wake, context) -> WorkerOutput
worker.run(wake, context) -> WorkerOutput
```

Mathematically:

```
Worker_i : Wake_i x Read_i(State) -> Delta_i(State) x Events x Complete
```

The module registry gives core an worker catalog:

```
WorkerSpec:
  worker_id
  wake_sources
  read_set       // declared tables/indexes this worker can read
  write_set      // declared tables this worker can update
  run
```

The protocol scheduler owns the mechanical sequence:

```
select wake
lookup WorkerSpec
load declared context from read_set
worker.run(wake, context)
commit returned rows/events/completions against write_set
```

Core does not know this worker catalog exists. The protocol supplies worker
catalogs and wake sources. At network boundaries, protocol workers write
`OutboundNetworkRow`s with target metadata; core TCP drains those rows without
learning protocol meaning.

`WorkerOutput` contains:

```
StateUpdates   // includes NewRows into ordinary tables and boundary tables
Events         // proposed canonical events to admit through the event-modules worker
Complete       // queue rows to complete/delete after the state commit
```

The event-modules worker is a pure chain over canonical event bytes:

```
CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> get_context(Event)
  -> project(EventWithContext)
  -> apply(ProjectorRows)
```

Admission happens before parse context. Known event ids stop at
`admit_event_id`. Parse failures reject the proposed event and let the
protocol caller record whatever IO-level failure row it owns. Blocked events
write `blocked_by_event` rows and stop.

Projectors only write rows. They cannot emit follow-on events. If projection
discovers work, it writes a module-owned queue row; a worker reads bounded queue
rows, queries its declared context, calls module commands, and sends the
proposed canonical events back to the control loop for admission. If the work
reaches a network boundary, the worker writes `OutboundNetworkRow`s to the core
network queue.

Workers are the active boundary. Projectors can only change rows, especially
queue rows. Commands are pure construction/query helpers. Workers are the only
event-module surface that can advance queued work. They do not return ad hoc
effects; they write queue rows.

Protocol inbound processing receives `InboundNetworkRow`s from core TCP. The
connection worker unwraps or rejects the opaque bytes and sends surviving
canonical bytes through the event-modules worker.

Boundary tables that need claim/retry ownership are ordinary module-owned tables with status metadata:

```
id primary key
status
not_before_ms
attempts
last_error
created_at_ms
updated_at_ms
```

Core tables:

```
events              // canonical event bytes plus status; ready rows are claimable
blocked_by_event    // dependency wait edges, not a job queue
```

`events` stores every canonical event byte string that can be projected, replayed, referenced by id, or sent:

```
events:
  event_id primary key
  canonical_event_bytes
  scope        // durable | local | endpoint_local
  status       // processing | ready | blocked | applied | rejected
  created_at_ms
  expires_at_ms
```

`blocked_by_event` stores dependency wait edges:

```
blocked_by_event:
  blocked_by_event_id  // missing dep
  event_id             // blocked event
  primary key(blocked_by_event_id, event_id)
  index(event_id, blocked_by_event_id)
```

When event `D` becomes applied, the same transaction deletes `blocked_by_event_id = D` rows and marks affected blocked events `ready` when `NOT EXISTS` any remaining blocker.

Unblocking never recursively processes dependents in the same call. `events.status = ready` is the unblocked-events queue; the control loop later claims a bounded batch of ready events.

The control loop commits `StateUpdates`, proposed events, and queue completions
in one transaction. Network IO happens later by draining committed core network
queues.

The first implementation has one process-wide control-loop writer. Failed
claim/retry work remains in its table with status, attempts, and last_error
until its owning module marks it pending, rejected, blocked, expired, or dead.
On startup, `events.processing -> ready`; protocol-owned processing rows return
to pending according to their module rules. Memory protocol queues start empty;
recurring protocol workers recreate recoverable work.

Modules may run pure helper transforms inline until they reach a queue, state,
or effect boundary. Modules do not recursively drain queues and do not perform
transport IO inline.

The control loop has no sync, bootstrap, auth, connection, or event-type policy
beyond calling protocol workers. It only knows dispatch, bounded batches,
transactions, time, limits, retries, and queue commits. Blocking policy belongs to
the event-modules worker. Leases are a
later extension for multiple workers or long-running claim ownership.

## Network Boundary

There is no `protocol/network.rs`. Network mechanics are split:

- `core/network_queues.rs` defines one outbound byte queue and one inbound byte
  queue. The outbound queue is not split into per-target tables. Target metadata
  is encoded into each row key so core can claim bounded batches for a concrete
  target with a generic key-prefix scan.
- `core/tcp.rs` owns listener, connect, `[u32 length][bytes]` framing, socket
  shutdown, and transport backpressure. It sends and receives only opaque bytes.
- protocol event modules own route facts, connection ids, transit wrapping,
  bootstrap, auth, sync frame meaning, and canonical event admission.

The only transport target visible to core is a concrete network target such as
`(ip, port)` or a future socket id. If a protocol worker starts with a
`connection_id`, it must resolve that id to a concrete `NetworkTarget` before
writing `OutboundNetworkRow`s. Core must not see the connection id.

Protocol-owned boundary tables include:

```
outbox              // connection_id + event_id, dedupe by unique pair
wake_schedules      // timer IO enters the protocol
```

Normal inbound processing is a core/protocol worker chain:

```
InboundNetworkRow { source, bytes }
  -> connection.unwrap / raw frame parse
  -> CanonicalEventBytes
  -> event-modules worker
```

Normal outbound processing is:

```
protocol outbox row
  -> connection/transit worker resolves NetworkTarget and creates opaque bytes
  -> OutboundNetworkRow { target, bytes }
  -> core/tcp.rs writes length-prefixed TCP frames
```

`Store` supports this without network semantics by exposing generic table-row
operations, including a bounded `table_rows_with_key_prefix` scan. Network queue
encoding lives in `core/network_queues.rs`, not `core/store.rs`.

## Possible Further Work

The current target-indexed core network queue is the right boundary for a POC,
but the sender loop can become more mature without changing that model. A
future long-lived sender should keep each open `NetworkTarget` fed with bounded
low/high watermarks, claim queued bytes by target and byte budget, and wake
protocol workers when that target has capacity for more wrapped bytes. That
demand signal should stay generic: core TCP reports target capacity and drains
opaque rows; protocol workers decide which connection-scoped outbox rows to
wrap. This does not imply per-connection core network queues. Per-connection
dedupe and fairness remain protocol concerns, while physical backpressure
remains target-scoped in core.

**connection** is an event module. A connection event references two endpoints and carries `shared_workspaces`. Each workspace entry's authority is established by the connection event's own dependencies and signature: deps point at endpoint/bootstrap authorization plus workspace capability events (workspace-membership grant, invite, etc.) that authorize the signer to bind that workspace to that connection, and the ready-event loop's standard signature/dep validation is what makes the entry trustworthy. Rotation, revocation, and expiry are further connection-related events with their own deps/sigs. The same module owns `connection_secrets`: globally-unique `connection_secret_id` → `(key, direction, connection_id, ttl)`, with separate inbound and outbound secrets per connection, each known only to the two endpoints.

The connection module also owns the transit envelope as plain functions, not as a protocol runtime concern (mirroring poc-6's `crypto.wrap` / `crypto.unwrap_transit`):

- `connection.wrap_bootstrap(remote_endpoint_id, inner_events) -> TransitBlob`: encrypts to the endpoint public key. Used for connection establishment and connection-secret repair.
- `connection.wrap(connection_id, inner_events) -> TransitBlob`: looks up the outbound secret for the connection, asserts every inner event's `workspace_id ∈ shared_workspaces(connection_id)`, pads to a size bucket, encrypts. Used for ordinary sync/control/event traffic.
- `connection.unwrap(bytes) -> Vec<CanonicalEventBytes>`: a parse-stage transform run by the inbound-byte loop on every inbound frame. Unwraps either endpoint-pubkey bootstrap frames or connection-secret frames. Connection-secret frames recover `connection_id`, drop any inner event whose `workspace_id ∉ shared_workspaces(connection_id)`, and pass the surviving canonical event bytes into canonical-event processing.

Wrapped bytes are never canonical events. They have no event id, no dependencies, and no labels — they are an opaque transit form. Only inner canonical event bytes are ids in the event store.

*Invariants: `shared_workspaces` is authoritative because the connection event's deps + signature have already been validated by the standard ready-event loop — the connection does not authorize itself, its dependencies do; a valid unwrap under one of our inbound secrets is by construction proof that the sender is the remote endpoint of that connection; every wrap is bound to exactly one connection; wrap and unwrap both enforce workspace ↔ connection alignment.*

**Outbox.** No projector calls `transport.send` or emits a `SendEvent`.
Projectors write rows to module-owned queues. A sync worker that wants to send a
durable event — e.g. after reading a queued need from connection C for event E —
calls a command that creates deterministic `SendEvent(connection_id=C,
inner_event_id=E)` and admits it through the control loop. The `SendEvent`
projector only writes `outbox(connection_id, send_event_id)`.
`connection/worker.rs` claims outbox rows, checks that E's `workspace_id` is in
`shared_workspaces(C)`, resolves C to a current transport target, calls the
transit wrap command, and writes a core TCP send queue row. The
TCP IO worker packs those bytes into TCP frames and writes sockets. A
slow route backs off its own target; other transport targets continue.
*Invariant: every ordinary byte on the wire is the product of two independent
workspace-membership checks (SendEvent projection + `connection.wrap`) plus a
third symmetric check on the receiving side (`connection.unwrap`).*

`outbox` stores only deterministic event ids to process for a connection:

```
outbox:
  connection_id
  event_id
  queued_at_ms
  primary key(connection_id, event_id)
```

`outbox` is memory by default and has no per-row claim, lease, or retry status.
Each active connection has exactly one `connection/worker.rs` owner for outbox
drain work:

```
connection::worker.run:
  connection_id
  hot_queue: bounded deque<event_id>
  present: set<event_id>
```

`hot_queue` is bounded by estimated bytes, not only event count. When it drops
below a low-water mark, `connection::worker.run` refills from pending `outbox`
rows for that connection, skipping ids already in `present`. After the socket
accepts a complete frame, the protocol runner deletes the corresponding
`outbox` rows and removes those ids from `present`. On send failure it removes
ids from `present`, leaves `outbox` rows pending, and backs off the target. No
database transaction is held while writing to the socket.

# Protocol source references

Use poc-6 for the event-based networking shape. Its `events/network/` tree is
the local reference for expressing connection establishment, bootstrap,
observed/self addresses, sync-window facts, and transit-related facts as
ordinary canonical events projected into tables. The translation target is not
to copy poc-6 directly; it is to keep connection, bootstrap, transit, and route
state in protocol event modules rather than in core runtime code.

Use poc-7 for sync behavior and user-facing scope. Its negentropy and
dep-aware sync code are the local references for range comparison, have/need
id exchange, dependency closure accounting, incremental dep caches, and the CLI
commands/perf surfaces worth preserving. The translation target is to move that
logic behind `protocol/event_modules/sync` workers and tables rather than keep a
parallel sync engine.

The protocol should preserve useful poc-7 CLI functionality as black-box
surfaces: account/workspace creation, invite/join, messaging, file transfer,
large message sync, and cascade/dependency stress commands. Those commands are
not core APIs; they are this protocol's public behavior and tests.

Every migration of a poc-6 or poc-7 surface must land directly on this design:
one core substrate, one protocol module family for each domain, projectors that
write rows only, commands that propose events only, and workers that own active
queue/cursor work. No compatibility adapters or duplicate engines.

# Appendix: Negentropy, dependencies, and dedupe

## Plain negentropy

Negentropy is a recursive equality query over a sorted set of event ids.

For a range-tree node `v`, define:

```
R_v = locally present root events whose sync key is inside range(v)
F_v = Hset("root", R_v)
```

A sync compare event from connection `C` carries `(workspace_id, node,
count, fingerprint)`. Starting sync is not a separate protocol concept; it is
just the top-level compare over the root node.

```
compare(v, remote_count, remote_fingerprint):
  if remote_fingerprint == F_v:
    return []
  else if v is splittable:
    return child compare events
  else:
    return have-id events for ids in R_v
```

There is no protocol session id required for correctness. Duplicate compares
are harmless because the compare answer is a pure function of projected state.
The top-level compare starts a round of work for a connection. The sync worker
should avoid creating a new root compare while that connection has recent
sync or bulk-transfer activity.

## Dep-aware negentropy

Dep-aware negentropy uses the same equality query, but the fingerprint for a root range also includes the present external dependencies required by those roots.

For every root event `r`, maintain a cached transitive dependency set:

```
D(r) = transitive event ids required by r
```

For each range-tree node `v`:

```
R_v = local root events inside range(v)
Q_v = union D(r) for r in R_v
X_v = Q_v \ R_v
P   = locally present event ids

F_v = Hset("root", R_v) + Hset("dep", X_v intersection P)
```

`X_v` is the invariant: it contains deps required by roots in `v` that are not already satisfied as roots inside `v`.

Projection maintains this incrementally. On inserting root `r` at leaf `L`:

```
add r to root membership on path L -> root

for each d in D(r):
  for v in path L -> root:
    if d is a root inside v:
      stop
    add requirement d to external deps for v
    if d is present locally:
      add d to present external dep hash for v
```

Use refcounts for `(node, dep_id)` and separate hash domains for roots and deps. A dep contributes to a node hash only when its refcount transitions `0 -> 1`, and is removed only when it transitions `1 -> 0`. This prevents duplicate dependency edges from double-counting or XOR-canceling.

When an event `d` becomes present, update the present-external-dep contribution for nodes that already require `d`. When `d` also becomes a root inside some node, it satisfies that dep for the node and all ancestors, so the external-dep contribution stops at the first satisfying node.

This is the same dep-aware comparison computed by poc-7's session code, but materialized as projected state instead of rebuilt as an on-demand session snapshot.

## Connection-scoped sync events and outbox

Sync protocol messages are connection-scoped events. They are not durable shared events and do not need signatures. The connection already authenticates the endpoint pair; the messages are only hints:

```
compare this node
I have these ids
I need these ids
```

They still use the normal event model: a module `codec.rs` defines canonical bytes, and `event_id = BLAKE3(canonical_event_bytes)`. `connection_id` is part of the canonical sync event, so ids for otherwise identical sync messages do not overlap across connections.

Plain sync events are fixed-shape:

```
SyncCompare(connection_id, workspace_id, node, count, fingerprint)
SyncHaveId(connection_id, workspace_id, node, event_id)
SyncNeedId(connection_id, workspace_id, event_id)
```

The current POC keeps `sync/frame` as the transient connection-scoped packet
event for real TCP throughput: it batches compare/have/need/data items, its
codec owns that packet format, and its projector only writes the connection
outbox row. Core network queues and core TCP still see only opaque transit bytes
and TCP length frames.

Projectors do not write to sockets and do not emit events. They only maintain
sync/outbox queue rows. Commands and module workers create deterministic
connection-scoped events, and the API running those commands admits the proposed
events through the control loop so it gets back their event ids.

There is no distinct `SyncStartRequested` event in the base design. Manual sync
starts by creating a root `SyncCompare`. If the negentropy index is maintained
synchronously by projection, the CLI command can create the root compare
directly from command context. If index catch-up is batched through
`sync.new_events`, `sync/worker.rs` first drains that queue and then calls the
same root-compare command. Either way, the first protocol event is still
`SyncCompare(root)`.

```
topo sync connection_id
  -> compare::commands::create_root(params, context(params))
  -> proposed SyncCompare(connection_id, workspace_id, root, count, fingerprint)
  -> admit event

Local SyncCompare / SyncHaveId / SyncNeedId projected
  -> outbox(connection_id, event_id)

Durable event projected
  -> sync.new_events(event_id, applied_seq)

Inbound SyncCompare / SyncHaveId / SyncNeedId projected
  -> sync.work(Inbound { connection_id, required_frontier, payload })

sync::worker.run
  -> first drains sync.new_events into sync.negentropy.index
  -> advances sync.negentropy.cursor
  -> then reads ready sync.work rows
  -> only answers work with required_frontier <= sync.negentropy.cursor
  -> command(ctx, params) -> proposed SyncCompare / SyncHaveId / SyncNeedId / SendEvent
  -> admit(proposed events) -> event_ids

connection::worker.run
  -> reads outbox(connection_id, event_id)
  -> transit_wrap command returns transit bytes
  -> writes core TCP send queue rows for those bytes
```

The sync worker's invariant is: never answer sync work against a stale negentropy
index. It must cover `sync.new_events` before responding to `sync.work`.
Use `apply_seq`, not event timestamps, as the sync-index cursor order. Index
updates and cursor advancement are one transaction; index writes are idempotent
with unique `(scope_key, event_id)` rows. Prefer per-workspace indexes and
aggregate the allowed workspace scopes for a connection at response time rather
than maintaining per-connection negentropy indexes.

Duplicate worker output collapses because connection-scoped sync event bytes are
deterministic and `outbox` is unique on `(connection_id, event_id)`.

For the first implementation, this can be two storage classes rather than one clever table:

```
durable_events(event_id, canonical_event_bytes, ...)
connection_events(connection_id, event_id, canonical_event_bytes, expires_at)
outbox(connection_id, event_id)
```

`connection/worker.rs` resolves an outbox `event_id` from transient
connection-event storage. For sync control events, it wraps their canonical
bytes. For `SendEvent`, it loads the referenced durable event, checks authority,
creates a transit blob, resolves the connection to a concrete `NetworkTarget`,
and writes an `OutboundNetworkRow`. Sync modules do not batch ids into transport
frames and do not create transit blobs.

Outgoing dedupe belongs at the `outbox` boundary and the per-connection hot queue, not in every projector's context. Projectors should not need `recently_sent` sets. If suppression beyond pending-buffer dedupe is needed later, keep sent rows in `outbox` with a TTL.

## Incoming buffer dedupe

Core TCP and core network queues remain byte-only. On receive, a durable inbound
buffer can hash bytes before parsing:

For the minimal reactive POC this buffer can be memory-only or skipped: the socket reader wakes the inbound-byte loop immediately, and recurring sync can recreate transient control traffic after a crash. When durable ingress is enabled, use the shape below.

```
wire_id = BLAKE3(bytes)

inbound_bytes:
  wire_id primary key
  bytes
  status

inbound_observations:
  wire_id
  connection_id
  remote_endpoint_id
  ip
  port
  first_seen_at
  last_seen_at
  seen_count
```

The incoming buffer is idempotent by `wire_id`. Source observations are tracked separately so address changes are diagnostics and dialing hints, not event semantics. Inner canonical event bytes unwrapped by `connection.unwrap` re-enter the same inbound processing path and dedupe again by their own canonical bytes.

Canonical-event processing only calls sync suppression after parse succeeds and the canonical event id is known. Invalid bytes may be deduped as bytes, but they are not event ids.

## Transit wrapping

Dedupe deterministic send intent before transit wrapping.

```
NeedId
  -> SendEvent(connection_id, inner_event_id)
  -> outbox(connection_id, send_event_id)
  -> connection::worker.run
  -> connection.wrap(connection_id, inner_event)
  -> core tcp_send_queue(target: ip/port or socket_id, bytes: transit_blob)
  -> protocol TCP frame/write
  -> delete sent outbox rows
```

Bootstrap and repair traffic uses `connection.wrap_bootstrap(remote_endpoint_id, inner_events)`. Ordinary sync/control/event traffic uses `connection.wrap(connection_id, inner_events)`.

If send fails, leave the `outbox` rows for retry and back off the connection sender. Dedupe remains `(connection_id, event_id)` based, not ciphertext based.

The receiver still validates inner events normally after decrypting. Network sync messages can cause work to be attempted, but they cannot make invalid durable events valid.

# Appendix: Documentation quality bar

Write this plan, implementation docs, and significant inline comments in the style of high-quality systems documentation: concrete, narrow, and audit-friendly. The model to emulate is Stellar Core's documentation:

- Overview and component map: https://github.com/stellar/stellar-core/blob/master/docs/readme.md
- Process and network architecture: https://github.com/stellar/stellar-core/blob/master/docs/architecture.md
- History system design and failure behavior: https://github.com/stellar/stellar-core/blob/master/docs/history.md
- BucketList mental model, formal model, examples, and cost analysis: https://github.com/stellar/stellar-core/blob/master/src/bucket/BucketListBase.h
- LedgerManager thread/data-flow diagram and invariant `LCL <= A <= Q <= H`: https://github.com/stellar/stellar-core/blob/master/src/ledger/LedgerManager.h
- OverlayManager responsibility and message taxonomy: https://github.com/stellar/stellar-core/blob/master/src/overlay/OverlayManager.h
- SCP/Herder separation between abstract protocol and application-specific driver: https://github.com/stellar/stellar-core/blob/master/src/scp/readme.md and https://github.com/stellar/stellar-core/blob/master/src/herder/readme.md

For every important component, document the same surface:

```
Purpose
Ownership / non-ownership
Interfaces
State
Invariants
Flow
Failure / restart behavior
Performance notes
Testing hooks
```

Style rules:

- Start with the component's responsibility, not implementation trivia.
- Say what the component does not own.
- Define vocabulary before relying on it.
- Prefer data flow and lifecycle descriptions over architecture slogans.
- State invariants explicitly, as small facts, formulas, or ordering rules.
- Explain a mechanism first with the simplest mental model, then with the precise rule.
- Use examples when a mechanism is subtle enough that the rule alone is easy to misread.
- Include operational consequences: crash, restart, retry, slow peer, invalid input, and overload behavior.
- Treat performance constraints as part of the design.
- Link prose to concrete files, functions, tables, events, or interfaces.
- Use inline comments only for non-obvious ownership, ordering, threading, safety, or performance rules.
- Keep small components brief; let complexity earn length.

Code-structure lessons from Stellar Core:

- Source directories should mark semantic subsystem boundaries, as in Stellar's `scp`, `herder`, `overlay`, `ledger`, `bucket`, `history`, `work`, and `transactions` directories. Avoid generic dumping grounds.
- Large runtime components should have a small public interface and a concrete implementation, following Stellar's `OverlayManager` / `OverlayManagerImpl`, `HistoryManager` / `HistoryManagerImpl`, and `Application` / `ApplicationImpl` pattern.
- Abstract protocol machinery should be separated from application meaning. Stellar's `scp` is protocol-generic; `herder` maps slots and values onto ledgers and transaction sets. Here, negentropy is the generic comparison mechanism; sync event modules map it onto workspace roots, deps, have/need/send events, and outbox writes.
- Managers own lifecycle, scheduling, and resource wiring. Helpers own algorithms. Do not let managers accumulate domain policy.
- Long-running work should be represented explicitly, as Stellar does with `work/`, `catchup/*Work`, and `historywork/*Work`. Hidden background behavior should become an worker, table row, or effect owner.
- Data structures should encode workload assumptions. Stellar's BucketList is shaped around temporal churn, incremental hashing, and catchup. Here, dep-aware negentropy should be a projected incremental tree/cache, not a session-time rebuild.
- Canonical encoding is a hard boundary. Stellar uses XDR for hashed, historical, and peer-message forms. Here, `codec.rs` produces canonical event bytes for ids, storage, projection, replay, and dedupe; connection wrapping is a separate transit layer. The codec should name the fixed-per-event-type format; shared utilities should do the repetitive binary lifting.
- Prefer immutable snapshots and stable ids at concurrency boundaries.
- Keep the first concurrency model legible: one control-loop writer, one sender owner per connection, bounded work at explicit boundaries.
- Failure behavior should be local: a failed send backs off one connection; a duplicate event is admitted once; a memory outbox can be regenerated; invalid bytes stop before event semantics.
