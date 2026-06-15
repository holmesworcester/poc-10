# Sync Fact Scope

Sync is the replication planning scope. We use it to make shared facts
converge between endpoints so other scopes can rely on eventual consistency for
admitted shared facts. Sync starts once per live connection with an
initial seed compare, continues with live-tail sends for newly indexed facts on
established authorized connections, and, where catch-up work remains, uses
periodic daemon tick catch-up (`--sync-ms`/`--tick-ms`) to drain queued
compare/have/need/fact-send work and due time wakes. A secondary goal is fast
wall-clock display of fact state in a requested range, such as latest messages;
that requires syncing the range's dependency closure, not only the owner facts
in the range. The scope owns shareability rows, projector-owned range
summaries, compare/have/need facts, local sync-setting facts, and sync handler
work.

## Interface To Core

Data enters sync as ordinary sync facts from connection receive paths, as
sync-owned intents dispatched by core, and from CLI/test commands that author
local sync-setting facts. The `sync` command does not queue handler work. It
writes local state; daemon runtime work reads that state and performs ongoing
sync. Other scopes may enqueue sync-owned intents as follow-up work, but core
treats those payloads as opaque queued work.

Data leaves sync as:

- context offers such as `sync_exact_fact`;
- control facts such as `compare`, `have_id`, and `need_id`;
- intents to send compare responses, request missing ids, answer requested ids,
  seed a connection, and batch facts onto a connection.

Core owns queueing, fact identity, handler retry, context range matching, and
transaction boundaries. Sync owns shareability, connection-specific visibility,
range summary planning, and exact-id request/response mechanics. Sync never
parses content, auth, or connection payload semantics beyond checking fact
scope and tag sendability through the owning helpers.

## Managed Row State

Sync owns shareable-fact rows, negentropy leaf rows, negentropy context-have
rows, negentropy node rows, compare rows, have-id rows, need-id rows, and local
sync-setting rows. The share/negentropy rows are the durable visibility index:
shareable and leaf rows record which owner facts are eligible to send in a sync
scope, context-have rows record direct validated dependency facts supplied by
the owner projector, node rows store deterministic range counts and
fingerprints, and compare/have/need rows record received control facts. Local
sync-setting rows record one local-only setting fact per command; the active
setting is the row with the greatest `(effective_at_ms, setting_fact_id)`.

Sync rows are internal planning state. Other scopes enqueue sync work or
consume sync context; they should not treat sync rows as their admission
interface.

## Interfaces To Other Scopes

### Context Interface

Sync-owned facts publish context for replication planning. `shared_fact`
publishes `sync_exact_fact`. The matched projector still validates the payload
fact after core supplies the context match.

### Other Interfaces

Fact projectors in other scopes enqueue the sync-owned `share_fact_with_sync`
intent after they can identify the sync scope and the validated context that
should travel with the owner fact. Sync records that projector-supplied graph;
it does not rediscover dependencies by scanning protocol rows or parsing
payload bytes. Connection supplies live connection rows and frame send
handlers. Sync asks connection to send fact ids; connection decides frame size,
sealing, and socket IO. Auth endpoint rows are used when building
connection-specific visibility: shareable-fact queries check workspace
membership and connection peer identity before returning facts to send.

## Cross-Scope Row Reads

No other protocol scope should read sync-owned rows directly. Sync handlers and
queries own those rows. Other scopes interact with sync by emitting facts,
publishing context, or queuing sync-owned intents such as `share_fact_with_sync`.

## Connection Boundary

Sync is scoped by live connections. A connection identifies the
local endpoint, the remote endpoint, the workspace routes learned during the
handshake, and the connection secret used to seal frames. Sync uses that
connection id as the security and transport domain for every compare,
have/need, and fact-byte send.

The split is deliberate. Sync chooses ids; connection carries bytes. Sync asks
"which admitted facts and dependency facts are visible on this connection?"
Connection answers the transport questions: how to batch the chosen ids, which
facts are sendable, how to seal the frame, where to write it, and how to record
the receipt. Once a frame is opened, the recovered bytes enter core as ordinary
facts and the owning auth, content, connection, or sync projector validates
their meaning.

Connection-specific visibility combines three pieces of state:

- sync shareable rows, which say a fact may participate in workspace sync;
- connection request/connection rows, which name the live peer session
  and workspace routes for that connection;
- auth endpoint membership rows, which say whether the remote endpoint is a
  member of a workspace.

A fact is considered for sending only when the connection authorizes the
workspace directly or the remote endpoint is a workspace member. Dependency
closure uses the same connection filter, so recursive `context_have` expansion
cannot cross into local/private facts, unauthorized workspaces, or purged facts
that no longer have sendable rows. Live-tail sends also use connection receipts
to skip the origin connection that supplied a fact while still advertising the
fact to other authorized connections.

## Live Tail

Live tail is the latency path after initial connection seeding. When
`share_fact_with_sync` records a changed upsert, sync asks the connection
visibility index which live connections may see that owner fact. It
removes any origin connection recorded by `connection_fact_receipt`,
recursively expands the owner through stored `context_have` edges for each
remaining connection, and queues `send_facts_on_connection`.

Live tail does not create authority and does not bypass projection. Connection
still rejects unsendable local/private facts and carries sealed frames; the
receiver admits the opened bytes as ordinary facts and runs the owning
projectors. Its purpose is wall-clock latency: peers that are already
connected see new shareable facts without waiting for another compare round.
Compare/have/need rounds and periodic daemon tick catch-up still repair peers
that were disconnected, missed a send, or learned a dependency after the first
live-tail send.

## Visibility And Dependency Closure

Range sync exists so a peer can make a bounded user-visible slice useful
without downloading every shared fact in the workspace. A view such as latest
messages starts from a requested time range, but facts inside that range often
depend on facts outside it: signer authority, recipient keys, key wraps,
retained key-node wraps, deletion facts, or retention policy context. If sync
sent only the owner facts in the requested range, the receiver could store the
bytes but many projectors would park, leaving the user-visible data incomplete.

Dependency closure is the solution: the response for a range carries the owner
facts in that range plus the out-of-range context facts needed to project them
quickly. This keeps catch-up bounded by the requested view and its validated
dependency graph rather than by the whole workspace history. The server remains
untrusted: it may relay range summaries and bytes, but authority, key access,
and key healing are still ordinary facts, context, projectors, and bounded
handlers.

## Convergence Process

Sync converges by turning projector output into a durable range index, then
exchanging summaries, exact ids, and the requested fact bytes over live
connections:

1. The owner projector admits or partially understands a shared fact. In the
   same projection pass it emits `share_fact_with_sync` with the fact id,
   timestamp, workspace, and any validated context facts that should travel
   with it. Projectors own this step because only the owning fact family knows
   which context has actually been validated.
2. The `share_fact_with_sync` handler records that contribution in sync rows.
   It rejects local/private bytes, stores the owner as shareable, stores the
   direct `context_have` edges, and refreshes the affected range-summary path.
   If this is a changed upsert, the same handler starts the live-tail path for
   already-established authorized connections. Sync does not infer dependencies
   by parsing fact bytes or scanning protocol rows.
3. When a connection is seeded or a range is compared, sync sends a `compare`
   fact that summarizes the visible range for that connection. The peer
   projects the `compare` and runs `send_sync_compare_response`.
4. The response handler compares the peer summary with the local durable index.
   If a range is too broad to answer exactly, it creates child `compare` facts.
   If exact ids are useful, it sends `have_id` facts or asks connection to send
   selected fact bytes. Before selected bytes are handed to connection, sync
   recursively expands the selected owner ids through stored `context_have`
   edges, so the send set includes authorized dependencies of dependencies as
   well as the in-range owners.
5. A peer that receives `have_id` checks whether it already has the named fact.
   If not, it creates and sends a `need_id` fact on the same connection.
6. A peer that receives `need_id` checks the shareable index for that
   connection, rejects unsendable payloads, and asks connection to send the
   requested fact bytes.
7. Received bytes enter core as ordinary facts. Their owning projectors decide
   whether the bytes are valid, materialize local rows, publish context, and
   emit more sync contributions. Convergence is the repeated application of
   this loop until summaries match.

The recursive walk includes each in-range owner, then that owner's
projector-supplied `context_have` facts, then each dependency's own
`context_have` facts until the authorized shareable graph is exhausted. The
walk stops at missing, purged, unauthorized, or local-only facts because those
facts have no sendable shareable row for the connection.

## Share Contributions

A `share_fact_with_sync` payload is not a command to send bytes immediately.
It is the owner projector's durable visibility statement for one fact in one
workspace:

```text
workspace_id
owner_fact_id
owner_timestamp_ms
state: upsert | retract
context_have: [fact:direct_validated_dependency, ...]
```

`workspace_id` is the sync namespace and authorization boundary.
`owner_fact_id` is the fact whose bytes may be sent. `owner_timestamp_ms` is
copied from the owner fact and places that owner in the range-summary tree; the
handler rejects a later contribution that tries to move the same owner to a
different timestamp. `state` either inserts/refreshes the contribution or
removes it. `context_have` is the direct dependency list that the projector has
validated or consumed in this pass.

`context_have` should name exact input parents, matched subject facts,
authority facts, key wraps, retained key nodes, and other out-of-range
witnesses that help a receiver project the owner fact. It should not name
local-only secrets. Raw `ContextNeed` selectors are not stored in negentropy
state, hashed into summaries, or sent as dependency closure; needs are local
wake hints until they are satisfied by validated offers.

The handler stores direct dependency edges as a union for that owner. Replaying
the same contribution is a no-op, and an older queued contribution cannot
erase richer context learned by a later projection. If a dependency must stop
travelling with an owner, the owner projector must emit an explicit prune or
retraction path.

Removal uses the same ownership boundary. When the owner projector observes
deletion, expiry, supersession, or retirement context for its own fact, it
emits a `share_fact_with_sync` retraction along with ordinary row deletion or
self-purge effects. Sync removes that owner's contribution and refreshes
ancestor summaries; it does not rediscover purged ids from broad fact scans.

## Invariants And Responsibility

A shareable fact contribution names an existing non-local owner fact whose
scope is global or the same workspace scope. Listed context facts are non-local
sendable facts if they still exist when the handler runs. The share index stores
ids, timestamps, direct dependency edges, and deterministic summary rows; it
does not store payload copies.

Range summaries are deterministic over connection-visible shareable rows plus
their stored dependency closure. Compare facts are hints. If summaries differ,
handlers split ranges, send exact have-id facts, or send exact requested facts.
The receiver still admits each payload through its owning projector, so
semantic admission remains in the fact family that owns the payload.

## Intent Handlers

`share_fact_with_sync` implements the contribution path described above. It
upserts or retracts one owner fact's durable sync visibility, refreshes the
affected range-summary rows, and triggers live-tail advertisement while
skipping the origin connection that supplied the fact.

`seed_connection_sync` is emitted by `connection` projection after
`connection` context proves the live connection row exists. It
computes the active configured range summary for facts visible on that
connection, creates a `compare` fact, and asks connection to send it.

`maintain_sync` is a live-only recurring daemon intent. It scans existing
connection rows, reads the active local sync setting, and reseeds compare work
for each connection. This is the ongoing-sync path; user commands influence it
only by changing projected local state.

`send_sync_compare_response` handles one `compare` fact. It loads connection
visible shareable facts, computes local summaries for the requested range,
creates child compare facts or exact fact-id sends, expands requested ids with
validated dependency context, and queues `send_facts_on_connection`.

`send_needed_fact_id` handles one `have_id` fact. If this store already has the
advertised fact id, it does nothing. Otherwise it creates a `need_id` fact and
queues it for the same connection.

`send_requested_fact` handles one `need_id` fact. It loads the requested fact,
checks that the fact is shareable on the requesting connection, rejects
unsendable local/private payloads, and queues `send_facts_on_connection`.

## Facts

Sync facts are the durable messages in the convergence loop. They are created,
sent, projected, and handled as ordinary facts; each one moves the loop one
step closer to equal range summaries.

### `range_request` (tag 160)

Optional process step for a bounded range request. A command can create this
workspace-scoped fact to name a connection and timestamp interval that should
become useful locally. Current projection validates that the outer scope
matches the workspace and records no rows; compare/send handlers perform the
transfer using the same range index and dependency closure used by ordinary
connection sync.

```text
range_request {
  workspace_id: fact:workspace_acme
  connection_id: fact:connection_ab
  start: 1715000000000
  end: 1715000999999
}
```

### `shared_fact` (tag 162)

Manual or test process step for naming one exact shared id. Projection requires
workspace scope and offers `sync_exact_fact` for the named fact id, allowing a
waiting projector to receive a concrete payload for that id. Normal live
sharing is recorded by the `share_fact_with_sync` handler; this fact is the
fact-level form of the same "this exact id is available" signal.

```text
shared_fact {
  workspace_id: fact:workspace_acme
  fact_id: fact:message_hello
}
```

### `compare` (tag 165)

Process step for comparing one range on one connection. Seeding a connection or
answering a broad mismatch creates `compare` facts. Projection writes
`sync_compare_rows` and emits `send_sync_compare_response`. The handler compares
the peer summary with the local connection-visible summary and decides whether
to answer with narrower compares, exact `have_id` facts, or selected fact ids
expanded with dependency closure.

```text
compare {
  connection_id: fact:connection_ab
  range: { start: 0, end: u64::MAX }
  summary: { count: 318, fingerprint: blake3:range_fingerprint }
  response_requested: true
}
```

### `have_id` (tag 166)

Process step for exact-id advertisement. A peer sends `have_id` when summary
comparison has narrowed a difference to specific ids. Projection writes
`sync_have_id_rows` and emits `send_needed_fact_id`; the handler checks whether
this store already has the id and creates a `need_id` only when the id is
missing.

```text
have_id {
  connection_id: fact:connection_ab
  timestamp: 1715000060000
  fact_id: fact:message_hello
}
```

### `need_id` (tag 167)

Process step for exact-id request. A peer sends `need_id` after receiving a
`have_id` for a fact it lacks. Projection writes `sync_need_id_rows` and emits
`send_requested_fact`; the handler verifies that the requested id is shareable
on that connection and asks connection to send the bytes.

```text
need_id {
  connection_id: fact:connection_ab
  fact_id: fact:message_hello
}
```

### `local_setting` (tag 174, local only)

Local-only setting for recurring sync. Projection writes
`sync_local_setting_rows`, and current-state queries choose the most recent row.
`mode = all` uses the root timestamp range. `mode = range` limits seed compares
and live-tail owner selection to the inclusive timestamp interval while still
expanding selected owners through dependency closure before bytes are sent.

```text
local_setting {
  mode: range
  effective_at_ms: 1715001000000
  start_ms: 1715000000000
  end_ms: 1715000999999
}
```

## Example Fact Graph

```text
auth/content projector admits message_hello
  -> share_fact_with_sync(upsert message_hello, context_have=[endpoint, user, key])
  -> sync_shareable_fact_rows + negentropy rows

connection_ab
  -> seed_connection_sync
  -> compare(active sync-setting range summary)
  -> send_facts_on_connection(compare)

peer compare differs
  -> compare child ranges or have_id(message_hello)
  -> need_id(message_hello)
  -> send_requested_fact
  -> send_facts_on_connection(message_hello + context dependencies)
```

This graph keeps responsibilities separate: sync decides which ids to transfer,
connection carries bytes, and the receiving auth/content/sync projector decides
whether each opened fact is valid.
