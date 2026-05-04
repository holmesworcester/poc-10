# Topo rewrite

I want to rewrite topo with clarity on:

* interfaces
* the invariants they guarantee
* decoupling
* realms of responsibility
* event-based networking

UPDATED:

- Inbound processing is a pure function chain; admission by event id happens before context loading.
- Queue-like work is just module-owned table rows at wait/dedupe/retry/schedule/IO boundaries.
- Canonical events have scopes: shared, local-only, endpoint-scoped, or connection-scoped. The normal event id is always `BLAKE3(canonical_event_bytes)`; connection-scoped events include `connection_id` in their canonical bytes so their ids are naturally connection-local.
- Durable shared data events live in durable event storage. Connection-scoped protocol events may live in transient storage, but still use normal canonical bytes and event ids. `outbox` stores only `(connection_id, event_id)`.
- Blocking uses `blocked_by_event(blocked_by_event_id, event_id)` pair rows and same-transaction unblocking.
- Projectors receive a core default context of immediate dependency events, labels, and origin metadata. Modules may define custom typed context only for module-owned read models that cannot be represented as bounded deps or labels; negentropy responders are the known case because compare/have/need answers depend on indexed summaries, bucket ids, and event-byte lookups.
- Connection/transit modules create transit blobs. The kernel never creates transit blobs; it only packs module-produced bytes into TCP frames and writes them to transport targets.
- Outgoing flow dedupes deterministic connection-scoped events before transit wrapping. TCP writability and socket backpressure are transport mechanics, not sync or connection semantics.
- Event modules own their canonical `codec.rs`; "wire" means transit bytes, not canonical event bytes.
- `state` materializes table definitions from event-module declarations; it owns storage mechanics, not domain schema meaning.
- Sync is an event-module family, not a separate sync engine.
- The kernel is only a run-loop scheduler plus IO adapters. It does not own a protocol flow; ready-event processing is just the default run loop over module-owned event/projector contracts.
- Timely Dataflow and Differential Dataflow are a proposal and source of ideas for Rust architecture and performance: deltas, arrangements, consolidation, frontiers, compaction, and bounded work should inform experiments without committing the kernel to those runtimes.
- Production may physically purge deleted or TTL-expired events and rows, but only after surviving facts, labels, summaries, or high-water marks preserve any semantic truth future projections need.

See appendix for documentation style rules and references.

# Timely / Differential Proposal

Timely Dataflow and Differential Dataflow are a proposal and source of ideas, not a settled dependency choice or required kernel architecture. They are useful local references for Rust performance work because they make deltas, indexed arrangements, logical progress, compaction, and bounded work explicit.

The design should borrow ideas that simplify this kernel. It should not import their full model unless doing so clearly reduces code and operational complexity. A good outcome is that selected projector families could later be lowered into Differential-style dataflows, while the default kernel remains small and auditable.

Ideas to test:

- Facts/events are base collections.
- Projectors are incremental transformations from input deltas and indexed context to output deltas.
- Module table declarations include the keys and indexes needed to maintain reusable arrangements.
- Dedupe is consolidation by deterministic key: event id, wire id, `(connection_id, event_id)`, or module-owned fact key.
- Joins, semijoins, antijoins, distincts, counts, and reductions should be expressed structurally in module declarations when possible, not hidden behind opaque context scans.
- Large cascades become bounded obligations with fuel/batch limits; the control loop reactivates them rather than recursively draining them.
- Logical truth and physical storage are separate: deletion, expiry, revocation, and supersession are facts; purge and merge are physical compaction of data whose semantic replacement is already represented.
- Pure deterministic work such as parse, signature verify, decrypt, hash, and canonical encode may run inline or as module run loops, but its results are facts. External IO remains an effect boundary.

Performance rules from these systems:

- Do work proportional to input deltas and affected arrangements, not total stored facts.
- Maintain hot indexes incrementally; do not rebuild negentropy trees, dependency caches, or unblock state at session time.
- Batch where throughput matters, especially inbound admission, projection apply, outbox refill, and socket writes.
- Bound every unit of runtime work by records, bytes, or time.
- Keep compaction explicit and tunable so simulation can disable purge while production can merge or discard physical detail that is no longer semantically required.

# Components / Responsibility

**event_modules/** contains every protocol or domain behavior that can be
expressed as events, projectors, commands, module-owned tables, and module run
loops. This includes content, identity, auth, connection, sync, and local-only
behavior. A built-out module owns its schema/read model next to its event type:
this is the poc-7 `message` / `reaction` pattern and the poc-6
`message.py` + `message.sql` pattern. Do not split "event type" and "tables"
into separate conceptual homes; tables live with the module that owns the
projection or queue.

Core imports `event_modules::Modules` only. `event_modules/mod.rs` is the single composition point that imports concrete module families and exposes the narrow registry surface used by the control loop, CLI, and tests. Kernel files call methods on `Modules`; they do not import `connection`, `sync`, `content`, or `identity` directly. The kernel does not own protocol flows. It wakes and runs loops, commits returned rows, admits returned events, and executes returned effects. Module loops interpret framed bytes, canonical events, queues, and route state.

Suggested organization:

```
src/event_modules/
  content/
    message/
      types.rs
      codec.rs
      commands.rs
      projector.rs
      tables.rs
      queries.rs
      mod.rs
    reaction/
      ...
    file/
  identity/
    workspace/
    user/
    peer/
  auth/
    invite/
    key/
    removal/
  connection/
    connection/
    connection_secret/
    observed_address/
  sync/
    compare/
    have/
    need/
    negentropy_index/
      tables.rs
      queries.rs
      run.rs
    dep_cache/
  local/
    local_secret/
    clock_wake/
```

**Per-file pattern, always.** Every event module is a directory with one file
per concern (`types.rs`, `codec.rs`, `projector.rs`, `commands.rs`,
`tables.rs`, `queries.rs`, `registry_meta.rs`, `mod.rs`, etc.) — even when a
module is small enough that a single `.rs` file would suffice. `tables.rs` is
where the module declares its projection tables, indexes, queues, cursors, and
storage class. `run.rs` is optional and exists only when the module owns queued
or cursor state that needs active work. There is no generic `jobs/` dumping
ground; run code is colocated with the table or cursor whose invariant it owns.
The cost is some empty-ish files in tiny modules; the win is that this is
intentional friction. In a codebase where most code is assistant-generated,
uniform shape across the surface makes accumulating logic easy to spot — files
that grow disproportionately, or directories that sprout extra concerns, are
the audit signal that something needs simplification or splitting. No collapsed
single-file event modules.

This rule is in conscious tension with "let complexity earn length" in the documentation quality bar (see appendix): that rule applies to *prose* in docs, this rule applies to *code structure* in event modules. Both stand.

**networking** All complex networking behavior including bootstrap,
connection, transit, and sync is implemented in event modules: commands propose
events, projectors write rows, module run loops decide what to run next, and
connection/transit modules wrap and unwrap transit blobs. Kernel IO modules
only frame and move bytes to concrete transport targets. Connections are
between two endpoints (daemons) and sync all data in all workspaces those two
endpoints share. Every workspace-scoped event carries its own `workspace_id`;
endpoint-scoped events (connection, intro, observed_address, self_address,
prekey events) carry endpoint identity instead. A daemon hosts at most one
instance of any given workspace, so for workspace-scoped events `workspace_id`
alone identifies the local processing scope and there is no separate
"recorded_by". See **Event Scopes** below for the full taxonomy.

**ready_event_loop** is not a kernel subsystem. It is the default run loop: admit facts, load context, call the owning module's projector, and apply rows. Most event modules use only this generic loop. Modules with richer state, such as sync, add their own module-owned run loops over module-owned queues.

**control_loop** is the single-writer run-loop scheduler. It claims bounded batches of table rows, dispatches to the owning module loop, applies returned state writes atomically, admits returned events through the generic ready-event loop, and runs external effects.

**state** is the explicit table-shaped substrate that projectors and module run loops observe. It is materialized from event-module table declarations and can be a database in production or an in-memory store in testing and simulation.

**kernel_io/** contains protocol-agnostic IO modules such as TCP listener,
reader, writer, and timer modules. IO modules create and drain IO queues; they
do not interpret transit blobs or canonical event bytes. They can return effects
against operating-system resources and rows/events against kernel-owned IO
tables such as inbound bytes, outbound bytes, listener state, socket state, and
backoff state.

**network** is a TCP-only kernel IO module family. It accepts module-produced
`TransportSend { target, bytes }` effects, packs `bytes` into length-prefixed
TCP frames, writes sockets, and records inbound bytes with origin metadata. It
does not create or interpret transit blobs.

**module run loops** are event-module actors woken by queue rows, timers, IO
readiness, or explicit CLI requests. A run loop can query state, decide whether
it is ready to run, call commands, admit proposed events, update/delete queue
rows, and return effects. Use `wake` for scheduling and `run` for execution.

The substrate pieces outside `event_modules` are deliberately narrow:

```
control_loop/   // dispatch, transactions, bounded batches, effect execution
state/          // catalog materialization, storage, migrations, snapshots
kernel_io/      // protocol-agnostic IO loop modules and IO queues
network/        // TCP bytes and socket ownership, under kernel_io
sender/         // TransportSend effects -> TCP frame/write, under kernel_io
```

If behavior is protocol semantics expressible as events/projectors/commands/tables, it belongs under `event_modules`. If it owns process execution, IO, storage mechanics, or scheduling, it belongs outside.

## State and Registry

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
commands / run loops
```

Those declarations form the runtime catalog:

```
event_modules/*/registry_meta.rs
  -> ModuleRegistry
  -> StateCatalog
  -> database / memory store schema
```

The event module owns semantic meaning: what a row means, which projection writes it, which indexes are required, and whether it may be rebuilt. `state` owns mechanics: creating tables, applying migrations, opening transactions, inserting NewRows, deleting Purges, querying declared indexes, resetting transient rows on startup, and choosing durable vs memory storage.

Boundary tables should follow the same rule where possible. `outbox` can be declared by the sender-facing module, `blocked_by_event` by the ready-event loop, schedule rows by the owning module or `kernel_io/timers`, and sync caches by the sync modules. The fewer central special tables, the better.

## Ready Event Loop

**codec** is canonical event encoding and parsing. It is not necessarily network wire. A module's `codec.rs` defines `Event <-> CanonicalEventBytes`, the event type tag, field layout, dependency field declarations, signature and signer-family rules, and deterministic id rules. Canonical event layout is fixed-width per event type: once the type tag is known, the field layout and canonical byte length are known, though different event types may have different fixed lengths. Shared binary utilities handle primitive reads/writes, fixed-size ids, truncation checks, and trailing-byte checks so codecs read as format descriptions.

**encode** encodes an Event to `CanonicalEventBytes`, returning a BLAKE3 event id, usually used by `create` or other domain-specific functions.

**parse** consumes `CanonicalEventBytes` and returns an Event, which includes all event values, its BLAKE3 hash id, its canonical bytes, and the `workspace_id` it belongs to, or throws an error if the bytes are invalid.

**canonical-event processing** hashes the canonical bytes, checks admission before loading context, parses only newly admitted events, and then runs context/project/apply as one chained step unless the event blocks.

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
The core-owned default context for `project` is:

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
core only routes the request/result and never inspects module-specific fields.
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
  sender/outbox run loops, not projector-only hidden queries.

If a future connection or bootstrap behavior appears to need custom context,
the burden is to prove that extra dependencies or labels cannot express it
boundedly.

**labels** is a table whose rows are tuples of (event_id, label_type); adding a label can be a result of projection. Labels become part of context so there should be a bounded number of labels for a given event_id. "This event blocks others" can be a label. 

**blocking** is ready-event-loop-owned. A blocked event remains an `events` row with `status = blocked`; each missing dependency is a `blocked_by_event(blocked_by_event_id, event_id)` row.

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
  storage: transient by default
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

## Control Loop

The control loop is the only always-running runtime. It owns:

- the module registry,
- boundary-table storage,
- transaction boundaries,
- clock wakes,
- resource limits,
- effect runners for TCP and local IO.

All domain behavior lives above the control loop in event modules and their
colocated run loops. The control loop is protocol-agnostic for a given IO
surface: it sees queue rows, ready events, run results, and effects, not sync
ranges, connection handshakes, or content semantics.

Queued work is typed:

```
WorkItem =
  InboundBytes
  ReadyEvent
  OutboxWake(connection_id)
  RunWake(module, runner)
```

Each queue item has exactly one owning module. The control loop calls one function:

```
run(work_item, context) -> RunResult
```

`RunResult` contains:

```
StateUpdates   // includes NewRows into ordinary tables and boundary tables
Events         // proposed canonical events to admit through the ready-event loop
Effects
```

Normal inbound processing is a pure chain inside the `InboundBytes` step:

```
InboundBytes
  -> connection.unwrap / raw frame parse
  -> CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> get_context(Event)
  -> project(EventWithContext)
  -> apply(ProjectorRows)
```

Admission happens before parse context. Known event ids stop at `admit_event_id`. Parse failures mark the inbound bytes invalid and release the event claim. Blocked events write `blocked_by_event` rows and stop.

Projectors only write rows. They cannot emit follow-on events. If projection
discovers work, it writes a module-owned queue row; a run loop reads bounded
queue rows, queries its context, calls module commands, and sends the proposed
canonical events back to the control loop for admission. Commands may also return wire bytes
for transport-only boundaries such as transit wrapping; the caller owns whether
those bytes are admitted as events or sent to transport.

Module run loops are the actors. Projectors can only change rows, especially
queue rows. Commands are pure construction/query helpers. Run loops are the
only event-module surface that can return IO effects; the kernel runner
executes those effects without knowing protocol meaning.

The first POC kernel may run this inbound chain directly from the socket reader without first durably queuing `InboundBytes`. That is still a loop boundary: the socket reader only passes `(origin, bytes)` into the inbound run loop, and event modules decide meaning and queue follow-on work. A durable `inbound_bytes` table is added when we need crash replay, fairness across many sockets, leases, or independent retry.

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

Core boundary tables:

```
inbound_bytes       // transport ingress, dedupe by wire_id
events              // canonical event bytes plus status; ready rows are claimable
blocked_by_event    // dependency wait edges, not a job queue
outbox              // connection_id + event_id, dedupe by unique pair
wake_schedules      // time enters the system
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

`outbox` stores only deterministic event ids to process for a connection:

```
outbox:
  connection_id
  event_id
  queued_at_ms
  primary key(connection_id, event_id)
```

`outbox` is memory by default and has no per-row claim, lease, or retry status. Each active connection has exactly one `connection/outbox::run` owner:

```
connection/outbox::run:
  connection_id
  hot_queue: bounded deque<event_id>
  present: set<event_id>
```

`hot_queue` is bounded by estimated bytes, not only event count. When it drops below a low-water mark, `connection/outbox::run` refills from pending `outbox` rows for that connection, skipping ids already in `present`. For each deterministic send event, the module loads the referenced canonical bytes, checks connection/workspace authority, resolves C to a current transport target, calls the transit wrap command, and returns `TransportSend { target, bytes }`. The kernel IO sender module packs those bytes into TCP frames and writes the socket. After the socket accepts a complete frame, the control loop deletes the corresponding `outbox` rows and removes those ids from `present`. On send failure it removes ids from `present`, leaves `outbox` rows pending, and backs off. No database transaction is held while writing to the socket.

The control loop commits `StateUpdates` in one transaction, then runs `Effects`. Effects may write new rows but do not directly project events.

The first implementation has one process-wide control-loop writer. Failed claim/retry work remains in its table with status, attempts, and last_error until its owning module marks it pending, rejected, blocked, expired, or dead. Send failure is connection-level backoff: `outbox` rows stay present. On startup, transient statuses are reset: `events.processing -> ready` and `inbound_bytes.processing -> pending`. Memory `outbox` starts empty; recurring sync run loops recreate root compare work, and any durable data sends are recreated only by later `NeedId` responses.

Modules may run pure helper transforms inline until they reach a queue, state, or effect boundary. Modules do not recursively drain queues and do not perform transport IO inline.

The control loop has no sync, bootstrap, auth, connection, dependency, or event-type policy. It only knows dispatch, bounded batches, transactions, time, limits, retries, and effects. Leases are a later extension for multiple workers or long-running claim ownership.

## Network

**transport** is a kernel IO module family for TCP byte I/O between network routes (listeners, socket cache, `[u32 length][bytes]` framing, addresses learned from invite/`observed_address`/incoming connections). `TransportSend { target, bytes }` is the only egress, where `target` is a concrete route such as `(ip, port)` or an existing socket id, not a `connection_id`. Inbound bytes enter an IO-owned inbound-bytes queue with origin `(ip, port, socket_id, observed endpoint if known)`; a durable inbound-bytes buffer is optional until replay/fairness requirements justify it. *Invariant: transport produces and interprets no transit bytes; if it sends bytes, those bytes were produced by an event module.*

**connection** is an event module. A connection event references two endpoints and carries `shared_workspaces`. Each workspace entry's authority is established by the connection event's own dependencies and signature: deps point at endpoint/bootstrap authorization plus workspace capability events (workspace-membership grant, invite, etc.) that authorize the signer to bind that workspace to that connection, and the ready-event loop's standard signature/dep validation is what makes the entry trustworthy. Rotation, revocation, and expiry are further connection-related events with their own deps/sigs. The same module owns `connection_secrets`: globally-unique `connection_secret_id` → `(key, direction, connection_id, ttl)`, with separate inbound and outbound secrets per connection, each known only to the two endpoints.

The connection module also owns the transit envelope as plain functions, not as a kernel concern (mirroring poc-6's `crypto.wrap` / `crypto.unwrap_transit`):

- `connection.wrap_bootstrap(remote_endpoint_id, inner_events) -> TransitBlob`: encrypts to the endpoint public key. Used for connection establishment and connection-secret repair.
- `connection.wrap(connection_id, inner_events) -> TransitBlob`: looks up the outbound secret for the connection, asserts every inner event's `workspace_id ∈ shared_workspaces(connection_id)`, pads to a size bucket, encrypts. Used for ordinary sync/control/event traffic.
- `connection.unwrap(bytes) -> Vec<CanonicalEventBytes>`: a parse-stage transform run by the inbound-byte loop on every inbound frame. Unwraps either endpoint-pubkey bootstrap frames or connection-secret frames. Connection-secret frames recover `connection_id`, drop any inner event whose `workspace_id ∉ shared_workspaces(connection_id)`, and pass the surviving canonical event bytes into canonical-event processing.

Wrapped bytes are never canonical events. They have no event id, no dependencies, and no labels — they are an opaque transit form. Only inner canonical event bytes are ids in the event store.

*Invariants: `shared_workspaces` is authoritative because the connection event's deps + signature have already been validated by the standard ready-event loop — the connection does not authorize itself, its dependencies do; a valid unwrap under one of our inbound secrets is by construction proof that the sender is the remote endpoint of that connection; every wrap is bound to exactly one connection; wrap and unwrap both enforce workspace ↔ connection alignment.*

**Outbox.** No projector calls `transport.send` or emits a `SendEvent`.
Projectors write rows to module-owned queues. A sync run loop that wants to send a
durable event — e.g. after reading a queued need from connection C for event E —
calls a command that creates deterministic `SendEvent(connection_id=C,
inner_event_id=E)` and admits it through the control loop. The `SendEvent`
projector only writes `outbox(connection_id, send_event_id)`. A
`connection/outbox::run` claims outbox rows, checks that E's `workspace_id` is in
`shared_workspaces(C)`, resolves C to a current transport target, calls the
transit wrap command, and returns `TransportSend { target, bytes }`. The kernel
IO sender module packs those bytes into TCP frames and writes sockets. A
slow route backs off its own target; other transport targets continue.
*Invariant: every ordinary byte on the wire is the product of two independent
workspace-membership checks (SendEvent projection + `connection.wrap`) plus a
third symmetric check on the receiving side (`connection.unwrap`).*

# Forking plan

poc-9 forks poc-7 at commit `c6f142e9` ("Simplify projection context loading", 2026-03-28) — the commit immediately before `56a9bc21` adopts iroh.

What poc-9 keeps from poc-7 (era E4–E5 substrate):

- pure-functional projectors + two-stage deletion (`b8669d31`)
- event-module locality under `event_modules/` (`bd14af95`, `7ace636d`, `26ec8c6f`)
- FieldSpec wire layout (`04bce8fc`)
- `shared_event_index`, atomic hard purge, projection context query adapters
- `runtime/state/shared` Option-D layout (`d90d083b`)

What poc-9 throws out and replaces:

- iroh (not yet in tree at fork point — bespoke QUIC + holepunch/intro/nat/upnp code physically present as deletion target / reference)
- `runtime/sync_engine/` range-owned session machinery, multi-source partition scheduler, receive/suppression plumbing
- `runtime/peering/` shared-daemon-connection orchestration
- the heavy `verus-proofs/` real-proof tree (not landed at fork point)
- ad-hoc per-event-type context-query adapters (see below)

Connection model follows poc-6's `events/network/` (`connection`, `connection_ack`, `intro`, `negentropy`, `self_address`, `sync_window`, etc. as canonical events). This is a **deliberate reversal** of poc-7's stance — poc-6's `SIMPLIFICATION_FOR_RUST_POC.md` §2 explicitly said "Connection/sync state is protocol/runtime state, not canonical events." poc-9 rejects that rule in favor of putting sync/connection facts through the same ready-event loop as everything else.

**Each step must align 100% to plan.md. No duplication of logic.** Every migration of a poc-7 surface — a projector, a state table, a runtime path, an RPC, a test — has to land at the principles described in this document, not somewhere halfway. Specifically:

- **No two implementations of the same concern.** Connection / transit / sync are event-based via `event_modules/connection/` and `event_modules/sync/` — there is no parallel session/round/open machinery, no second transport, no parallel sync engine. If a poc-7 module is brought over, the legacy machinery it depended on must be retired in the same commit, not left to coexist as a "transitional path."
- **No ad-hoc per-event-type loaders.** `get_context` returns the core default context: `{event, deps, labels, origin}`. There is one generic context-loading path. If a projector needs additional state, first declare it as a dependency or write it as a label upstream. Custom module context is allowed only through a declared module-owned context request/result for indexed read models such as negentropy response state; the core routes that opaque request/result and does not learn sync-specific fields.
- **No legacy compatibility scaffolding.** This is a POC. Canonical event ids and wire layouts are not load-bearing across deployments — change them whenever the new model needs a field. Do not preserve old hashes via shadow columns, sentinel strings, thread-local bridges, or "still-needed" parallel tables. If the legacy reader is still around, retire the reader.
- **No duplication via vocabulary drift.** "Session", "round", "open", "tenant" (as a per-row scope key), "recorded_by" (as anything other than a transient diagnostic) are forbidden in active code. Substrate-level work is queue-driven and event-driven; reads scope by `workspace_id` (or `endpoint_id` for endpoint-scoped events). One word per concept.
- **Each step ends green.** A migration that compiles by leaving partial scaffolding in place is not done. The build, the substrate test bar, and the relevant CLI tests must all pass at the end of each step. Half-done work is rolled back, not left to a future agent.

The bar is alignment, not progress. A commit that lands more code while leaving plan.md violated by an extra abstraction layer or a duplicate path is a regression.

**Ready-event loop simplicity is non-negotiable.** Preserve the ready-event shape of this document — see `get_context` in the Ready Event Loop section for the strict contract. poc-7's projection-context-query adapters (one custom `context_loader` per event module) are the surface this fork is rejecting. The exception is a declared module context request/result for large module-owned indexes such as negentropy; that request is part of the module API, not a second core loader. To restate concretely, in poc-9:

- dependencies come from schema metadata on flat fields (one mechanism for all event types),
- labels are a small generic table `(event_id, label_type)` populated by projectors as the only cross-event signal,
- `get_context(event)` always starts with `{event, deps, labels, origin}`,
- if a projector "needs more state," that state should arrive as a declared dependency or a label unless it is a module-owned index that requires a declared custom context request,
- custom context is justified for negentropy responders because the answer depends on summaries, bucket ids, presence checks, and event-byte lookup; it is not justified for ordinary connection/bootstrap validation.

Note: in poc-9, labels replace custom gates for deletes, user/peer removal, and bootstrap-anchor events. poc-7 handles these with bespoke projector logic that queries side tables (deletion tombstones, removal sets, `invite_bootstrap_trust` / `pending_invite_bootstrap_trust`). poc-9 uses one uniform pattern instead:

1. on the gating event (delete X, remove user U, supersede invite I, etc.), act on all *existing* matching events in one pass — purge their rows, drop their derived state, etc.,
2. write a single label of the appropriate type (e.g. `deleted:X`, `removed_by:U`, `superseded:I`) so the gate is reified as one durable label row,
3. for any *future* incoming event that would otherwise match, the projector reads the same `labels` set already in its context and rejects / blocks / no-ops.

No per-event-type gate query, no "two-stage deletion" projector branch, no bootstrap-trust side tables consulted out-of-band — one mechanism (labels) carries every "this thing has been retired / superseded / revoked" signal, and projectors see it through the same default context.

This keeps one control loop, one projector contract, one dependency mechanism, and one set of correctness invariants for everything in the system. Sync may add module-owned context for negentropy indexes, but connection and bootstrap should stay on first-level deps, labels, and origin metadata unless a future design proves those are insufficient.

## Event types brought over

We can in principle bring over every event module from poc-7 at `c6f142e9` (`src/event_modules/`), but starting minimal is better — each event type carried forward must be re-justified under the new context-and-labels rules and the new connection-as-event model. The plan is two waves.

**Wave 1 (minimal — auth + messages, brought over from poc-7):**

- `workspace` — workspace identity / metadata root
- `user` — user identity bound to a workspace
- `peer_secret` / `peer_shared` — legacy workspace-scoped device principal if retained from poc-7; endpoint identity lives in connection events and is what gates bootstrap/transport acceptance
- `user_invite_shared` / `peer_invite_shared` — invite events for joining a workspace and linking a device
- `invite_secret` — invite local secret (issuer side)
- `invite_accepted` — accepted-workspace binding
- `key_secret` / `key_shared` — group-key material
- `encrypted` — encrypted-event wrapper
- `message` — chat message
- `reaction` — message reaction
- `message_deletion` — message delete (ported under the new label-based gate pattern; drop the two-stage-deletion branch and the deletion-tombstone side table)
- `removal` — user/peer removal (same: act on existing rows + write a `removed_by:U` label; future events check the label)

This is the smallest set that exercises all the hard cases: signed identity chains, dependency blocking, encrypted events, invites/joins, deletions, and removals — i.e. everything we need to validate the context-and-labels rules end-to-end.

**Wave 1 deferred from poc-7** (port later when the wave-1 surface is solid): `admin`, `key_request`, `key_rotation`, `tenant`, `bench_dep`, `file`, `file_slice`. `file` / `file_slice` are big enough to be their own milestone and aren't on the auth/messages critical path.

**Translation rules for any poc-7 module brought over:**

1. drop the per-module `context_loader` — declare deps as schema metadata on flat fields,
2. replace any side-table gate read (deletion tombstones, removal sets, `invite_bootstrap_trust`) with a label read on the in-context `labels` set,
3. drop any "two-stage" projector branch (e.g. message_deletion, removal) in favor of the act-on-existing + write-label + check-label pattern,
4. drop `recorded_by` in favor of the event's own `workspace_id`.

**Connection-related event types translated from poc-6:**

poc-6's `events/network/` originals: `connection_request`, `connection_prekey`, `connection_prekey_shared`, `connection_ack`, `intro`, `negentropy`, `observed_address`, `self_address`, `server_connection`, `sync_window`.

Translation note: in poc-6 these were workspace-scoped; in poc-9 connections are between two **endpoints** (daemons) and a single connection carries every workspace the two endpoints share. So:

- `connection` (new, replaces `connection_request` + `connection_ack`): two `endpoint_id`s, agreed `shared_workspaces` set signed at establishment, rotated by further `connection` events. No `workspace_id`.
- `connection_prekey` / `connection_prekey_shared`: keep the secret/shared split, but key material is per-endpoint-pair, not per-workspace.
- `intro`: keep as endpoint-pair introduction; carries no workspace identity.
- `observed_address` / `self_address`: keep as-is; both are endpoint-scoped already.
- `negentropy`: keep as the sync-compare event, but it must name `(connection_id, workspace_id)` because reconciliation is per-workspace within a shared connection.
- `sync_window`: keep as the per-workspace range/window selector; same `(connection_id, workspace_id)` scoping.
- `server_connection`: defer until we add cloud-relay / always-on server endpoints.

The transit envelope is *not* an event type in poc-9. It is `connection.wrap` / `connection.unwrap` — plain functions on the connection module, mirroring poc-6's `crypto.wrap` / `crypto.unwrap_transit`. The encrypted bytes are opaque transit form with no id, no deps, no labels; only the inner canonical event bytes are events. See the Network section above. Every connection-related event listed here travels *inside* a wrapped frame.

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
The top-level compare starts a round of work for a connection. The sync run
loop should avoid creating a new root compare while that connection has recent
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

Projectors do not write to sockets and do not emit events. They only maintain
sync/outbox queue rows. Commands and module run loops create deterministic
connection-scoped events, and the API running those commands admits the proposed
events through the control loop so it gets back their event ids.

There is no distinct `SyncStartRequested` event in the base design. Manual sync
starts by creating a root `SyncCompare`. If the negentropy index is maintained
synchronously by projection, the CLI command can create the root compare
directly from command context. If index catch-up is batched through
`sync.new_events`, the `sync/negentropy_index` run loop first drains that queue
and then calls the same root-compare command. Either way, the first protocol
event is still `SyncCompare(root)`.

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

sync/negentropy_index::run
  -> first drains sync.new_events into sync.negentropy.index
  -> advances sync.negentropy.cursor
  -> then reads ready sync.work rows
  -> only answers work with required_frontier <= sync.negentropy.cursor
  -> command(ctx, params) -> proposed SyncCompare / SyncHaveId / SyncNeedId / SendEvent
  -> admit(proposed events) -> event_ids

connection/outbox::run
  -> reads outbox(connection_id, event_id)
  -> transit_wrap command returns transit bytes
  -> returns TransportSend effects for those bytes
```

The sync run loop's invariant is: never answer sync work against a stale
negentropy index. It must cover `sync.new_events` before responding to
`sync.work`.

Duplicate run output collapses because connection-scoped sync event bytes are
deterministic and `outbox` is unique on `(connection_id, event_id)`.

For the first implementation, this can be two storage classes rather than one clever table:

```
durable_events(event_id, canonical_event_bytes, ...)
connection_events(connection_id, event_id, canonical_event_bytes, expires_at)
outbox(connection_id, event_id)
```

`connection/outbox::run` resolves an outbox `event_id` from transient connection-event storage. For sync control events, it wraps their canonical bytes. For `SendEvent`, it loads the referenced durable event, checks authority, creates a transit blob, and emits `TransportSend { target, bytes }`. Sync modules do not batch ids into transport frames and do not create transit blobs.

Outgoing dedupe belongs at the `outbox` boundary and the per-connection hot queue, not in every projector's context. Projectors should not need `recently_sent` sets. If suppression beyond pending-buffer dedupe is needed later, keep sent rows in `outbox` with a TTL.

## Incoming buffer dedupe

Transport remains byte-only. On receive, the buffer hashes bytes before parsing:

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
  -> connection/outbox::run
  -> connection.wrap(connection_id, inner_event)
  -> TransportSend { target: ip/port or socket_id, bytes: transit_blob }
  -> kernel_io TCP frame/write
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
- Long-running work should be represented explicitly, as Stellar does with `work/`, `catchup/*Work`, and `historywork/*Work`. Hidden background behavior should become a run loop, table row, or effect owner.
- Data structures should encode workload assumptions. Stellar's BucketList is shaped around temporal churn, incremental hashing, and catchup. Here, dep-aware negentropy should be a projected incremental tree/cache, not a session-time rebuild.
- Canonical encoding is a hard boundary. Stellar uses XDR for hashed, historical, and peer-message forms. Here, `codec.rs` produces canonical event bytes for ids, storage, projection, replay, and dedupe; connection wrapping is a separate transit layer. The codec should name the fixed-per-event-type format; shared utilities should do the repetitive binary lifting.
- Prefer immutable snapshots and stable ids at concurrency boundaries.
- Keep the first concurrency model legible: one control-loop writer, one sender owner per connection, bounded work at explicit boundaries.
- Failure behavior should be local: a failed send backs off one connection; a duplicate event is admitted once; a memory outbox can be regenerated; invalid bytes stop before event semantics.
