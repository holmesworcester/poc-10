# Context Architecture

Context is a lightweight p2p engine for building local-first, end-to-end
encrypted collaboration apps. Its storage and wire protocol are made of facts
in the Datalog/database sense: asserted ground records that can be stored,
matched, and projected. Context facts are immutable, fixed-layout records
admitted locally and exchanged between peers. A fact can be a message, invite,
membership change, sync request, receipt, key wrap, or connection handshake;
deterministic projectors validate facts against context and turn them into
SQLite rows or bounded retryable work.

The result is a fact-based protocol runtime meant to be small enough to reason
about and complete enough to be the backend for a p2p Slack: team chat, invites,
membership, reactions, files, message history, sync, and frontend-friendly
queries without a custom middle layer.

The runtime keeps the p2p stack behind a boring local API. A client should be
able to ask for paginated message views with users, reactions, attachments, and
download progress while Context handles networking, auth, sync, projection, and
durable retry in one model.

## Approach

In Context, a central idea is that facts offer context to other facts. Context
is a more general relationship than blocking: a context need can name an exact
fact, but it can also name a range of facts, and context
offers can be projected before the facts they refer to exist. That gives the
runtime a standing relationship surface. Later facts can wake when relevant
context appears, and earlier offers can satisfy later needs without hidden
callbacks or broad scans.

### Needs And Offers

Every context row is either a need or an offer. A need says "wake and
reproject this owner fact when matching context appears." An offer says "this
owner fact can be loaded as payload context for matching needs." Both have
the same matching shape: owner fact id, role, fact scope, and an inclusive byte
range. Core only matches role/scope/range overlap and loads the offer owner as
payload; the woken projector decides whether that payload actually proves what
it needs.

Readable examples look like this; real keys are canonical protocol bytes:

```text
need
  owner: fact:content_message:7f2a
  role: content_signer
  scope: workspace:acme
  range: endpoint:alice_phone..endpoint:alice_phone
offer
  owner: fact:endpoint_shared:51de
  role: content_signer
  scope: workspace:acme
  range: endpoint:alice_phone..endpoint:alice_phone

need
  owner: fact:connection:c810
  role: connection_fact_receipt
  scope: local
  range: fact:connection:c810..fact:connection:c810
offer
  owner: fact:connection_fact_receipt:03db
  role: connection_fact_receipt
  scope: local
  range: fact:connection:c810..fact:connection:c810

need
  owner: fact:content_message:9af3
  role: secret_coverage
  scope: workspace:acme
  range: (frontier:room_key_v4, minute:28583333, leaf:9af3)..same
offer
  owner: fact:local_history_node_secret:6e15
  role: secret_coverage
  scope: workspace:acme
  range: (frontier:room_key_v4, minute:28583280, leaf:9a00)
      ..(frontier:room_key_v4, minute:28584600, leaf:9aff)
```

Because context is projector-described evidence, it is more powerful than a
Boolean dependency block. A projector decides which context proves the fact,
whether missing context parks or rejects it, whether derived state is durable or
ephemeral, what context it offers to later facts, what future context should
wake it, and which bounded intents should run. Core stores facts, matches
context, schedules wakes, and commits declared effects; the narrative for what
happens when a fact exists stays in the owning projector.

Protocol aspects such as connection, sync, and auth are all described as
facts. Connection handshakes, sealed frame receipts, sync compares, key wraps,
workspace authority, messages, deletions, and retention policy are admitted and
projected through the same fact model. This gives the project a consistent way
to reason about concurrency and network interaction: bytes from another node
enter as facts, core matches context, the owning projector validates meaning,
and handlers perform bounded retryable work.

The current architecture has a small vocabulary:

```text
facts
context needs
context offers
projectors
intents
intent handlers
runtime work queues
protocol scopes
```

The system has one fact store, one context matching surface, one projection
scheduler, one intent scheduling surface, and one product-facing binary:
`con`.

## Architecture Principles

The current architecture is described by these boundaries:

- **Core mechanics.** Core owns protocol-neutral mechanics: facts, context,
  command authoring primitives (`src/core/command.rs`), byte-range context
  matching, generic runtime/app mechanics, pending fact processing, context wake
  fanout, intent dispatch, storage mechanics, wire field primitives, network
  queues, TCP, clock, and crypto helpers.
- **Scope semantics.** Protocol scopes own fact semantics: layouts,
  projectors, context
  roles/ranges, command constructors, read-model rows, queries, CLI adapters,
  and protocol validation rules.
- **Scope manifests.** `src/protocol.rs` and `src/protocol/<scope>.rs` are
  manifests. A scope manifest declares its fact families and intent handlers in
  one place.
- **Handler work.** Intent handlers own bounded stateful work and handler
  checkpoint state.
- **Projector output.** Projectors return needs, offers, time wakes, row
  mutations, and intents.
- **Handler output.** Intent handlers return facts, purged facts, row
  mutations, and intents. Purge output remains a bounded core-owned escape
  hatch for exact fact removal, not a broad storage API.
- **Runtime isolation.** No fact module, intent handler, command, schema, or
  wire layout reaches around core to call another stage directly.
- **Durable queues.** Runtime coordination is explicit and durable where it
  needs to survive restart: pending facts, time wakes, durable intents, and
  ephemeral intents are named queue surfaces rather than hidden callbacks.
- **Explicit schemas.** Schema declarations are explicit SQL DDL in the owning
  Rust modules:
  `src/core/schema.rs`, `src/core/network.rs`, and
  `src/protocol/registry.rs`.
- **Fixed layouts.** Wire layouts are declarative and fixed length. There are
  no variable payload slots except bounded, canonical slots explicitly modeled
  by a fact layout.

## Runtime Shape

`src/main.rs` delegates to the product app boundary. Protocol manifests declare
their commands, fact families, intent handlers, schemas, and daemon hooks; the
app assembles those declarations into a `ProtocolDescription` and passes it to
core. Core uses that description to build the `con` CLI, open the declared
runtime, run the declared daemon tick, and dispatch registered protocol commands
without hard-coding their names or behavior.

Runtime turns are serialized per database to avoid races between
command-created facts and ongoing projection or intent activity. A daemon tick
and a normal protocol CLI command both acquire `<db>.runtime.lock` before
entering the runtime, so a command cannot admit facts while another turn is
draining pending facts, matching context, committing projector output, or
running handlers. The daemon releases the turn after each bounded tick; CLI
commands wait for the next turn, and `reset` removes the runtime lock file
along with the database and daemon lock files.

Runtime work moves through these core-owned queues:

```text
command output
  -> authored facts
  -> pending_projection
  -> projector
  -> replacement needs + append-only offers + row mutations + follow-up intents
  -> durable or ephemeral intent queue
worker/daemon
  -> registered handler
  -> committed RuntimeEffects
```

Command-authored facts and intent-created facts skip the incoming intake table:
core retains them in `facts` and `local_fact_admissions`, then marks them in
`pending_projection` in the same transaction. Outside-origin facts from the
network handler enter through `incoming_facts`; projection either drops them or
retains them as normal facts when they must park on context or become protocol
evidence.

Commands do not dispatch handlers. Before any protocol query reads projected
state, runtime pre-settles retained `pending_projection` work so the query sees
local command-authored facts. That pre-query settle does not consume
`incoming_facts`, dispatch intents, or admit time wakes; the daemon and worker
turns own incoming facts, due time wakes, and handler-derived state. Tests that
observe handler output should run a daemon/worker and assert eventually.

Network input is staged as core-owned opaque bytes, converted by the daemon
declaration into an ephemeral protocol intent, and then handled through the
same intent dispatch path. Network output is produced by protocol handlers as
opaque byte rows and written by the core TCP pump.

## Scope Layout

Fact families are organized by protocol scope. The grouping is mostly arbitrary
to core: core receives the manifests, type tags, projectors, handlers, schemas,
and commands that the app declares. For protocol code, scopes act like
module-like families. They keep related facts, rows, context roles, commands,
queries, and handlers near each other and give each group a clear realm of
responsibility.

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
needs, validate matched context, and return replacement needs, append-only
offers, and materialization effects. They are separate from handlers because
missing context parks projection, while IO and retryable stateful work belongs
in queued intents.

Deletion is target-owned: a target fact keeps the need or time wake that can
remove it, and when that context appears it deletes only its own rows and may
purge only itself.

### Intent Handlers

Intent handlers are the bounded stateful work path. They decode one queued
intent, name exact fact inputs for core to load, perform one effect, and return
`RuntimeEffects`. They are separate from projectors so network sends,
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

This keeps core's network interface minimal. Core owns TCP accept/write
mechanics and stores inbound or outbound network payloads as opaque bytes. It
does not know whether a byte string is a bootstrap request, bootstrap response,
established connection frame, auth fact, sync fact, or content fact. On ingress,
the daemon hands accepted bytes to the protocol-declared inbound network intent;
the connection scope classifies the frame, emits the right local wrapper fact,
and lets connection projectors open it with auth and connection context. Opened
payloads re-enter the normal fact admission path as child facts, and receipt
facts record which connection delivered them.

Egress is the same boundary in reverse. Sync may decide that a fact id should
be sent to an authorized connection, but the connection scope decides how to
load, filter, batch, seal, and address those facts as connection frames. The
final `send_network_frame` intent gives core only a route and opaque frame
bytes. Core writes bytes to the socket; connection facts preserve the durable
relationship between those bytes, the session, recovered child facts, and
receipts.

### Simplicity Guardrails

Production work is represented with immutable facts, standing context,
time-wake schedules, pending projection, durable intents, and ephemeral intents.
Protocol progress is visible through those mechanisms and through schema-owned
rows. The declared runtime work surface is complete: production state enters as
facts, context, time wakes, intents, or schema-owned rows.

## Documentation

Active design and maintenance docs are:

- `README.md`: architecture overview and protocol function boundaries.
- `ARCHITECTURE_DIAGRAMS.md`: GitHub-renderable architecture flowcharts.
- `docs/RULES.md`: architecture rules, projector rules, and guardrails.
- `docs/todo-add-verus-proofs.md`: TODO plan for adding Verus proofs.
- `src/core/README.md`: core/runtime responsibility boundaries, including
  projection and handler commit boundaries.
- `src/protocol/*/README.md`: fact-scope responsibilities, facts, handlers,
  row state, and cross-scope interfaces.

Planning notes live under `docs/archived/`.
