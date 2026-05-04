# Rules

## Rules Intended To Be Covered By Types And Static Checks

Prefer enforcement in this order:

1. Rust types, traits, visibility, and crate/module boundaries.
2. Static boundary tests over file paths, imports, exported names, and forbidden
   vocabulary.
3. Short prose rules for intent, review judgment, and behavior that cannot be
   proven mechanically.

The following rules should stay mechanically enforced where practical:

- Commands return `CommandOutput<T>` with `Vec<ProposedEvent>`, not rows,
  effects, or storage writes. `ProposedEvent` is constructed from an
  `EventRecord` and carries both the deterministic `event_id` and that
  canonical record.
- Projectors return `ProjectionOutput` with `Vec<TableRow>`, not events.
- `commands.rs` is reserved for event modules. App shells and adapters use
  shell-specific names such as `flows.rs`, and module CLI adapters live in
  module-local or domain-local `cli.rs`.
- `event.rs` is forbidden. Semantic event types live in `types.rs`; canonical
  wire parsing and formatting live in `codec.rs`.
- Codec files do not define public semantic types, and every codec module has a
  sibling `types.rs`.
- Domain roots contain only child event modules plus shared domain files:
  `mod.rs`, `actor.rs`, `tables.rs`, `queries.rs`, `types.rs`, and `cli.rs`.
- Child directories under `event_modules/<domain>/` are canonical event modules
  and must carry the standard shape: `mod.rs`, `types.rs`, `codec.rs`, and
  `tables.rs` at minimum. Shared domain tables, queues, and helper types live at
  the domain root instead of masquerading as event modules.
- Event-module files use standard concern names only. New concern files require
  an explicit boundary decision and a static-test update.
- Dumping-ground directories such as `jobs`, `cli_commands`, `runtime`,
  `state`, and algorithm-only `negentropy` are forbidden under
  `event_modules`.
- Core never imports protocol modules and does not contain protocol vocabulary
  such as connection, transit, sync, outbox, TCP, sockets, or bootstrap schema.
- Core has a small allowlisted file set and must not contain domain vocabulary
  such as workspace, content, endpoint, identity, invite, or message.
- The core pipeline is generic admission/apply plumbing; protocol branching
  belongs behind the protocol module registry.
- Sync modules do not own TCP/frame IO, and core/network code does not contain
  sync protocol logic.
- Event-module commands do not mutate storage directly. Event-module
  projectors do not query storage directly.
- Event modules do not import runtime/control-loop/pipeline/transport effect
  machinery. The top-level protocol registry is the only event-module file that
  implements the core registry trait.
- Projectors are row-only boundaries: no `CommandOutput`, `ProposedEvent`,
  `EventRecord`, IO effects, transport work, or transit creation.
- Table names are declared in `tables.rs`; projectors and queries use those
  declarations.
- `EventRecord` literals are constructed by codecs. Other code asks codecs to
  produce records or proposed events.
- `codec.rs` uses shared binary helpers and finishes reads so trailing bytes are
  rejected.
- `types.rs` does not store encoded/canonical event artifacts as semantic
  fields.
- `protocol/network.rs` remains TCP framing only, and `protocol/app`/`inbound`
  do not import concrete event families directly.
- Source tests reject fake-crypto terminology that would let placeholder crypto
  be named as real protection.

When a prose rule becomes mechanically enforceable, add the type boundary or
static check and shorten the prose. Keep prose for realness, black-box proof,
crypto quality, performance expectations, and design rationale.

## Commands Live In Event Modules

Commands belong under `event_modules`, alongside the event types, codecs,
projectors, queries, and module-owned tables they operate on.

CLI, RPC, actors, and other adapters should dispatch into module commands
instead of constructing canonical event bytes directly. Adapters own
input/output shape; event modules own protocol and domain semantics.

Commands receive explicit input values plus narrow read context values. They do
not mutate SQLite, open transactions, drain queues, or call broad apply loops.
They return `CommandOutput` with proposed canonical events only. Commands must
not return rows or effects. The API that runs a command is responsible for
admitting those proposed events through the pipeline; admission returns the
event ids for chaining.

Projectors return `ProjectionOutput` with table rows only. They cannot emit
events. If projection discovers follow-on work, it writes a module-owned queue
row; a module actor reads that queue, queries context, runs a command, and sends
the command's proposed events back through the pipeline.

Module actors are the active boundary. Projectors do not perform IO or emit
effects. Event-module commands do not perform IO either; they construct
canonical events or transport bytes from explicit input and context. Actors own
dequeueing, fairness, bounded work, retries, calling commands, admitting
proposed events, and returning IO effects for the core runner.

The intended shape is:

```text
event_modules/<domain>/<module>/commands.rs
  command(ctx, input) -> CommandOutput { value, events: Vec<ProposedEvent> }

event_modules/<domain>/<module>/codec.rs
  Event <-> CanonicalEventBytes

event_modules/<domain>/<module>/types.rs
  Event type and semantic constants

event_modules/<domain>/<module>/projector.rs
  EventWithContext -> ProjectionOutput { rows }

event_modules/<domain>/<module>/tables.rs
  module-owned projection tables, indexes, queues, cursors, and storage class

event_modules/<domain>/<module>/cli.rs
  optional module-local CLI help, parameters, queries, and output formatting

event_modules/<domain>/actor.rs
  optional actor over domain-owned queues/cursors shared by child event modules

event_modules/<domain>/cli.rs
  optional domain-level CLI registry/help for commands spanning child modules
```

Leaf event modules own event types. Domain roots may own shared `tables.rs`,
`queries.rs`, `types.rs`, `actor.rs`, and `cli.rs`. Do not create an
event-module directory for an algorithm unless it defines an actual canonical
event type.

Do not create `event.rs` files in event modules. The typed event struct belongs
in `types.rs`. `codec.rs` is only for canonical format tags, field order,
encode/decode, and event-specific parse validation. Commands belong in
`commands.rs`.

CLI commands belong in the closest relevant event module or domain root
`cli.rs`. A generic CLI runner may parse global flags, dispatch to module CLI
commands, admit/apply proposed events, and print returned output. It must not
own domain command semantics, help text, post-write queries, or formatting.

A module CLI command may run module queries and format text or JSON output. If
it creates events, it first calls a pure module command, then asks the generic
runner to process exactly those proposed events, then runs any query that
depends on their projection rows. It must not rely on a broad global drain
unless the command is explicitly a wait/poll command such as sync status or
assert-eventually.

## Core Is Protocol-Agnostic

Core code under `src/core` must not import `src/protocol` or concrete event
families. `protocol/event_modules/mod.rs` is the protocol composition point
that knows the concrete module list.

Allowed in core:

```text
use crate::core::pipeline::EventRegistry;
use crate::core::store::Store;
```

Not allowed in core:

```text
use crate::protocol::event_modules::Modules;
use crate::protocol::event_modules::{connection, sync};
crate::protocol::event_modules::connection::...
```

The protocol shell talks to the current protocol composition object, `Protocol`.
`Protocol` owns the event-module registry (`Modules`) and any protocol IO
namespaces. The shell may pass `Protocol` into core pipeline/control-loop
functions through core traits such as `EventRegistry` and move returned
bytes/effects. Core must not import concrete protocol namespaces to get work
done.

`pipeline.rs` is the core's generic ready-event actor: admit canonical bytes,
check dependencies, parse new events, call projectors, and apply rows. It must
not branch on connection, transit, sync, response, or transport-target details.
The module registry parses and projects canonical event bytes. Framed byte
handling lives under `src/protocol`.

`store.rs` is generic storage mechanics. It should expose table rows, event
status, dependency waits, and generic event-id partitions. It must not expose
sync buckets, connection/bootstrap schema, or content payload semantics as
storage concepts. Module `tables.rs` files declare whether each table is
durable, memory, or temp; core provides the requested storage class without
learning the table's protocol meaning.

## Proposed Events Have Deterministic IDs

Event ids come from canonical event bytes, not from projected state. The codec
or shared codec utility that constructs canonical bytes should also expose the
event id, usually as `BLAKE3(canonical_event_bytes)`, so commands can chain
proposed events without writing, re-querying, or inferring ids from projection
tables.

The write path still returns event ids as a receipt for the exact bytes it
admitted. That receipt is for status and verification: callers can confirm the
stored id matches the proposed id, learn whether the event was applied,
blocked, or duplicate, and surface pending ids when needed.

Prefer this command shape:

```text
create(input, ctx) -> CommandOutput {
  value,
  events: Vec<ProposedEvent { event_id, record }>
}
```

Use two levels of write API:

```text
append_event(proposed_event) -> Admission {
  event_id,
  status: Ready | Blocked { blocked_by } | Duplicate { status },
}

append_apply(proposed_event) -> WriteResult {
  event_id,
  status: Applied | AlreadyApplied | Blocked { blocked_by },
  admitted: Vec<EventId>,
}
```

Commands that only need a prior proposed event's id can use the proposed id
directly:

```text
let workspace = workspace::create(...)?;
let account = account::create(workspace.event_id, username)?;

CommandOutput {
  value: account.value,
  events: vec![workspace.event, account.event],
}
```

If a later event requires the prior event to be semantically applied, the actor
or API running the command admits and applies the proposed chain in order and
checks the write result. Event-module commands do not call the writer directly.

Commands that intentionally create pending work, such as accepting an invite
before the invite event has synced, may return proposed events whose admission
can block; the caller surfaces the proposed id as pending.

## Apply Only The Command's Own Chain

Commands must not call a broad `drain_until_idle` loop to make chaining work.
That applies unrelated ready events and makes command behavior depend on ambient
queue state.

For command chaining, apply exactly the event the command just wrote, in order,
inside the command transaction. The global control loop remains responsible for
draining unrelated ready work.

## Ownership Boundary

The event writer owns storage mechanics:

- transactions
- canonical event admission
- dependency checks
- projection apply
- labels
- outbox rows
- returned event ids

Module commands own semantic construction:

- what command input means
- which state queries are required
- which canonical events to create
- how to interpret `Applied`, `AlreadyApplied`, or `Blocked`

All state mutation still goes through canonical events and projectors.

## Event Modules Use The Clean Contract

Event modules must target the new core/protocol contract directly. Do not introduce
compatibility adapters for old `state`, `runtime`, queue, or transport APIs.
If an existing module depends on old core machinery, refactor the module until
the dependency is gone.

The module shape is:

```text
event module =
  codec
  deps
  projector
  tables
  commands/queries where needed
```

```text
event family =
  child event modules
  shared domain tables/queries/types where needed
  domain actor where active queued/cursor work spans child modules
```

The universal contract is:

```text
CanonicalBytes -> Event
Event -> Vec<EventId>
(Event, Context) -> Projection

Projection =
  rows
```

Rows may target module-owned projection tables, indexes, labels, queues,
outbox, or purge/compaction tables. They are still rows. Projectors do not
return events or effects.

Event modules must not:

- import `crate::runtime`
- import old `crate::state` internals
- know queue table names or pipeline phase names
- start actors or drive the control loop
- perform transactions
- call global drain/apply functions
- write SQLite directly, except for data-only table declarations if that
  remains the chosen schema representation
- know transport implementation details

Event modules may:

- decode and encode canonical event bytes
- declare dependencies
- declare owned tables, indexes, and storage class (`durable`, `memory`, or
  `temp`)
- query through a narrow read context
- return canonical events from commands
- return declarative projector output: rows, labels, queue rows, outbox rows,
  and purges
- implement `actor.rs` actors that claim module-owned queue rows, call
  commands, and return bounded IO effects

`codec.rs` describes the module's canonical/wire format: tags, field order,
and event-specific validation. Shared binary mechanics such as integer
encoding, length prefixes, fixed-size ids, truncation checks, and trailing-byte
checks belong in a format-agnostic utility, not reimplemented in every codec.

Canonical event fields should be fixed-width per event type: once the event
type tag is known, the field layout and canonical byte length are known.
Different event types may have different fixed lengths. Use fixed-size ids,
fixed-size hashes, fixed-size integers, fixed-size enum tags, and fixed-size
domain fields. Do not introduce varints, maps, self-describing encodings,
nullable ad hoc fields, or variable-width strings into canonical event codecs.
If variable application data must cross a boundary, express it as fixed-size
chunk event types or padded size-bucket event types. Counted transport batches
may carry repeated fixed-format items or opaque canonical event bytes, but that
batch framing is not itself an open-ended canonical event schema.

Strict checks should stay true:

```text
rg "crate::runtime" src/protocol/event_modules
rg "crate::state" src/protocol/event_modules
rg "rusqlite|Transaction" src/protocol/event_modules
```

These should return no matches unless a match is explicitly documented as a
data-only schema declaration.

## Sync And Connection Are Event Modules

Sync and connection protocol logic must not be custom code hidden in the CLI,
network transport, runtime loop, or core. It must be expressed as properly
decoupled event modules along the same lines as the structured modules in
`poc-8/src/protocol/event_modules`.

This includes:

- connection setup and supporting connection events
- connection metadata and observed/self addresses
- key, invite, and bootstrap protocol events
- sync compare/have/need events
- deterministic connection-scoped send-intent events
- dep-aware negentropy events and tree/cache maintenance
- request/response behavior that can be represented as event emission

Core may:

- admit canonical events
- compute event ids
- check dependencies
- apply pure projector output
- schedule bounded work
- commit actor state updates
- return opaque actor effects to the protocol runner after commit

The first POC may process inbound frames reactively without a durable inbound
queue. The protocol socket reader hands `(origin, bytes)` to a protocol
inbound actor, which unwraps/parses protocol bytes and admits surviving
canonical event bytes through the core ready-event path. This shortcut is
allowed only while the socket reader remains semantic-free and recurring sync
can recreate lost transient control traffic.

Core must not:

- contain a bespoke sync coordinator
- contain connection protocol state machines
- create transit blobs, choose transit encryption/padding/key rules, or decide
  which events are authorized on a connection
- inspect sync ranges or negentropy trees except through module-declared tables
- contain negentropy, compare/have/need, or sync-range vocabulary in
  `core/pipeline.rs`, `core/control_loop.rs`, or `protocol/network.rs`
- contain `TransportSend`, TCP frame, socket, inbound-byte, outbox, or
  connection-target vocabulary in `src/core`
- special-case have/need/compare behavior outside event modules
- bypass event admission for protocol messages
- use side-channel protocol messages when an event can express the fact

The network layer owns only transport mechanics: TCP framing, sending,
receiving, buffering, and backpressure to concrete targets such as `(ip, port)`
or socket ids. It does not own sync, connection, transit wrapping, or
authorization semantics.

Protocol IO modules own IO effect names such as `TransportSend { target,
bytes }`, inbound-byte queues, socket state, listener state, and send
backpressure. Protocol event modules own outbox rows and transit bytes. Core
does not name any of these concepts.

Events declare scope explicitly:

- `Shared`: durable data that participates in sync summaries and dependency
  checks.
- `Local`: durable private facts such as endpoint keys, invites, and route
  observations.
- `Transient`: non-durable canonical protocol events. The current Topo
  protocol uses transient events for exactly one established connection.

Connection-scoped protocol events are real canonical events. Their route or
connection id must be inside their canonical bytes, and their id is the normal
`BLAKE3(canonical_event_bytes)`. They are not durable event-set truth: the
pipeline applies their projector output immediately, and their outbox row may
carry the canonical bytes until transport confirms send. After send, the outbox
row can be deleted; a future identical connection-scoped event may be projected
again.

Durable data events are not pushed to peers on creation. Durable data transfer
is queued only through deterministic connection-scoped protocol events, usually
created by a sync actor after projectors write compare/need/range queue rows. The
outbox dedupes these events by `(connection_id, event_id)`. The
connection/transit module drains the outbox and creates transit blobs; the
protocol network code only frames and writes those bytes.

`TransportSend.target` is a transport route, not a semantic connection id. Use
an address or socket target such as `(ip, port)` or `socket_id`. If a module
starts from `connection_id`, it must resolve that connection to a transport
target before emitting the effect.

## No Fake Or Placeholder Encryption

Never implement fake, placeholder, pass-through, XOR, reversible toy, or
"encrypted in name only" encryption.

If a path requires confidentiality, integrity, authentication, forward secrecy,
or key erasure, use a real reviewed cryptographic construction through a
well-maintained library and document the exact primitive, nonce/key rules,
associated data, and failure behavior. If the real construction is not ready,
leave the feature unimplemented and make the boundary explicit.

Code, tests, CLI output, table names, event names, and docs must not call bytes
encrypted, sealed, secret, private, wrapped, or protected unless the production
path actually enforces the claimed property. A framing function may be called a
frame. It must not be called encryption.

Tests must not prove crypto behavior with fake keys, fake ciphers, identity
transforms, or deterministic toy encryption. They may use deterministic test
vectors for real cryptographic primitives. They may use fakes only below the
cryptographic boundary, such as a fake transport that carries already-encrypted
bytes without inspecting or transforming them.

When real encryption is added, required tests include:

- round-trip tests against real test vectors
- tamper rejection for ciphertext, nonce, associated data, and key id
- wrong-key rejection
- nonce uniqueness or misuse-resistance checks, depending on the primitive
- boundary tests proving plaintext does not cross storage, wire, or log surfaces
  that claim encryption
- restart/retry tests for key lookup, rotation, revocation, and expiry behavior

## Realness Bar

Functional tests and demos must exercise the production boundary they claim to
prove. Do not call a shortcut and name it sync, network, auth, storage, or CLI
if the real path would cross a different boundary.

Do not stop working at a partial, fake, or merely scaffolded result. A task is
not complete until the claimed behavior is real through the production boundary,
proven with an appropriate black-box test, and any remaining fake or missing
piece is either removed or explicitly marked out of scope. If the real result
cannot be completed in the current branch, stop claiming the feature works and
leave a concrete blocker instead of passing placeholder coverage.

Use these rules:

- Functional tests are black-box by default. They should drive the public
  `topo` binary and assert observable behavior.
- CLI tests run the actual `topo` binary.
- Networking tests use real networking through the CLI. If a test claims sync,
  transport, or multi-node behavior, it must move bytes across real sockets with
  production framing and the same outbox/inbox adapters used by the CLI.
- Sync tests move canonical event bytes through outbox, wire frames, receive,
  ingest, and project. They must not copy rows from another database.
- The only normal exceptions are pure functional projector tests and module
  command tests. Projector tests may assert declarative projection output.
  Command tests may use a fake writer/read context to prove event construction,
  status interpretation, and command chaining. These tests are useful local
  checks, but they do not prove product functionality; feature completion must
  be proven by black-box tests through the public boundary with real networking
  when networking is involved.
- Static boundary tests are allowed. They may scan source text or public module
  structure to enforce architectural rules, but they are not functional proof.
- Harnesses may create temp directories, spawn processes, choose ports, and
  assert output. They must not create core tables or apply domain semantics.
- Toy adapters are allowed only for small unit tests that name the fake
  explicitly, such as projector math or scheduler ordering. They are not
  acceptable evidence for end-to-end behavior.
- If a feature is not real yet, say so in the command name, test name, or
  documentation. Prefer deleting fake coverage over keeping a test that certifies
  the wrong boundary.
- A passing test should fail if the production codec, queue, network frame,
  database adapter, or projector path is broken.

## CLI Contract Decoupling

CLI behavior and CLI tests should express product contracts, not core
implementation contracts. The CLI surface should be stable enough that the old
core and new core/protocol split can both satisfy the same user-visible tests while internal
queues, projection phases, and storage layout change underneath.

CLI tests should cover:

- workspace creation and joining
- messages, reactions, and deletions
- file send and save
- invite flows
- multi-node sync and transport behavior
- observable output, exit codes, and durable user-visible state

CLI tests must not depend on:

- internal queue names
- internal table names
- projection phase names
- exact sync round internals
- whether an event became ready through one queue or another
- whether storage is backed by the old state modules or the new core store

The CLI test harness may spawn processes, allocate temp directories, choose
ports, and assert command output. It must not create core tables, insert rows,
copy databases, simulate sync, or decode private storage layout.

Prefer stable machine-readable CLI outputs for tests where ambiguity matters:

```text
topo status --json
topo events list --json
topo workspace list --json
topo message list --json
topo file list --json
topo daemon status --json
```

The success criterion is that realistic CLI tests can run unchanged against the
old core and the replacement core/protocol implementation.

## Fresh Minimal Rewrite Guardrails

The fresh rewrite starts from `plan.md` and `RULES.md` only. Add code back only
when it serves the minimal black-box path:

```text
topo --db PATH invite --public-addr ADDR
topo --db PATH connect INVITE_LINK
topo --db PATH generate NUM_EVENTS EVENT_SIZE_BYTES
topo --db PATH sync
```

A read-only `count`/`status` command is allowed solely so black-box tests can
assert eventual convergence and measure sync-start to all-counted time.

Keep core boring:

- `protocol/network.rs` owns TCP, frame boundaries, connection attempts, and byte IO only.
- `core/store.rs` owns durable bytes, generic module-owned rows, and generic event-set
  reads/writes only.
- `protocol/event_modules/content` owns content event construction, codec, and projection.
- `protocol/event_modules/sync` owns all negentropy, compare/have/need/range decisions,
  connection-scoped sync events, and sync actors.
- `protocol/event_modules/connection` owns endpoint identity, bootstrap/connection
  events, established-connection rows, and the route facts needed to reach an
  endpoint.

Core should be a pleasure to read: small files, direct control flow,
plain names, and no hidden protocol cleverness. A reader should understand the
core as an executor and durable byte store without learning the content or sync
protocols. Protocol IO belongs under `src/protocol`; all real domain and
protocol logic belongs in protocol event modules.

Core files must not own connection, peer, or bootstrap schema. If a
protocol needs a durable or transient table, the owning event module declares
the table and writes it through generic storage/projector output.

Do not put sync protocol vocabulary or decisions in core files. In particular,
`core/store.rs`, `core/pipeline.rs`, and `core/control_loop.rs` may not decide
what a negentropy range means, when to split a range, which ids are needed, or
which events satisfy a sync request. Protocol shell code may only call
event-module functions and move returned bytes.

Do not put transit wrapping in `protocol/network.rs`, `core/store.rs`, CLI
glue, or sync modules. Connection/transit modules create transit blobs;
protocol network code creates only generic TCP frames around module-produced
bytes.

Event modules stay directory-shaped:

```text
protocol/event_modules/<name>/commands.rs
protocol/event_modules/<name>/codec.rs
protocol/event_modules/<name>/types.rs
protocol/event_modules/<name>/projector.rs
protocol/event_modules/<name>/tables.rs
protocol/event_modules/<name>/queries.rs   # only when needed
protocol/event_modules/<name>/mod.rs
```

Domain roots may additionally contain:

```text
protocol/event_modules/<domain>/actor.rs
protocol/event_modules/<domain>/tables.rs
protocol/event_modules/<domain>/queries.rs
protocol/event_modules/<domain>/types.rs
```

Never create `event.rs`.

Functional proof for this rewrite means black-box CLI tests that spawn the real
`topo` binary, use real TCP sockets, start `sync`, wait through the CLI-observed
event count, and report both events/s and MiB/s for perf cases.
