# Sync Fact Scope

Sync is the replication planning scope. We use it to make shared facts
converge between endpoints so other scopes can rely on eventual consistency for
admitted shared facts. A secondary goal is fast wall-clock display of fact
state in a requested range, such as latest messages; that requires syncing the
range's dependency closure, not only the owner facts in the range. The scope
owns shareability rows, projector-owned range summaries, compare/have/need
facts, and sync handler work.

## Interface To Core

Data enters sync as ordinary sync facts from connection receive paths, as
sync-owned intents dispatched by core, and from CLI/test commands that create
range or cascade facts. Other scopes may enqueue sync-owned intents as
follow-up work, but core treats those payloads as opaque queued work.

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
rows, negentropy node rows, compare rows, have-id rows, need-id rows, and
cascade-test staging rows. These rows are the durable visibility index:
shareable and leaf rows record which owner facts are eligible to send in a sync
scope, context-have rows record direct validated dependency facts supplied by
the owner projector, node rows store deterministic range counts and
fingerprints, and compare/have/need rows record received control facts.

Sync rows are internal planning state. Other scopes enqueue sync work or
consume sync context; they should not treat sync rows as their admission
interface.

## Interfaces To Other Scopes

### Context Interface

Sync-owned facts publish context for replication planning. `shared_fact` and
`cascade_test_fact` publish `sync_exact_fact`. The matched projector still
validates the payload fact after core supplies the context match.

### Other Interfaces

Fact projectors in other scopes enqueue the sync-owned `share_fact_with_sync`
intent after they can identify the sync scope and the validated context that
should travel with the owner fact. Sync records that projector-supplied graph;
it does not rediscover dependencies by scanning protocol rows or parsing
payload bytes. Connection supplies established connection rows and frame send
handlers. Sync asks connection to send fact ids; connection decides frame size,
sealing, and socket IO. Auth endpoint rows are used when building
connection-specific visibility: shareable-fact queries check workspace
membership and connection peer identity before returning facts to send.

## Cross-Scope Row Reads

No other protocol scope should read sync-owned rows directly. Sync handlers and
queries own those rows. Other scopes interact with sync by emitting facts,
publishing context, or queuing sync-owned intents such as `share_fact_with_sync`.

## Visibility And Dependency Closure

Bounded catch-up follows from the same convergence model. When a peer compares
or requests a time range, the response includes the owner facts in that range
plus the out-of-range context facts needed to project them quickly. For
encrypted content that can include authority facts, recipient keys, key wraps,
retained key-node wraps, and deletion or retention context. The server remains
untrusted: it may relay range summaries and bytes, but authority, key access,
and key healing are still ordinary facts, context, projectors, and bounded
handlers.

Projectors own sync membership. A projector that can decode a fact and
determine its sync scope emits `share_fact_with_sync` in the same projection
pass that emits its rows, offers, needs, wakes, or purge effects. This applies
even when the fact is parked for missing context. Parking means the read model
is not materialized yet; it does not hide the owner fact from sync if the
projector already knows the sync scope and any validated context facts that
should travel with it.

A `share_fact_with_sync` payload is the complete projector view for one owner
fact in one sync scope:

```text
sync_scope
owner_fact_id
owner_timestamp_ms
leaf_range
state: upsert | retract
context_have: [fact:direct_validated_dependency, ...]
```

`context_have` contains direct sync-eligible context facts that the projector
validated or consumed in this pass. It should name exact input parents, matched
update/about facts, authority facts, key wraps, retained key nodes, and other
out-of-range witnesses that help a receiver project the owner fact. It should
not name local-only secrets. Raw `ContextNeed` selectors are not stored in
negentropy state, hashed into summaries, or sent as dependency closure; needs
are local wake hints until they are satisfied by validated offers.

The `share_fact_with_sync` handler is the only durable visibility path. It
loads the owner fact, rejects local/private payloads, validates that listed
context facts are sendable if they still exist, stores the contribution, and
refreshes the shareable rows, leaf rows, context-have rows, and range summaries.
The update is incremental: changing one leaf touches that stored contribution
and its ancestor path, not the whole namespace. Replaying the same contribution
is a no-op, and older queued snapshots cannot remove richer context learned by
a later projection; context rows are inserted idempotently and kept as a union
unless the owner projector emits an explicit prune or retraction.

Compare and response handlers read only the durable sync index for the
connection-authorized scope. For dependency-aware sends, they include each
in-range owner, then walk that owner's projector-supplied `context_have` facts,
then each dependency's own `context_have` facts until the authorized shareable
graph is exhausted. The walk stops at missing, purged, unauthorized, or
local-only facts because those facts have no sendable shareable row for the
connection. A range send without dependencies sends only the owner leaves; that
mode is useful for proving tests are not passing because a full-range sync
happened accidentally.

Live-tail egress is the same contribution path. When a new or changed
contribution is stored, sync can advertise it to established authorized
connections. If the fact arrived from a connection and has a projected receipt
for that connection, live-tail advertisement skips that origin connection while
still advertising the fact to other authorized connections.

Removal uses the same ownership boundary. When a target projector observes
deletion, expiry, supersession, or retirement context for its own fact, it emits
ordinary row deletions or self-purge plus a `share_fact_with_sync` retraction
for that owner id. The handler removes the stored contribution and refreshes
ancestor summaries before or with physical fact-byte purge. Sync does not
rediscover purged ids from broad fact scans.

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

`seed_connection_sync` runs after a connection response becomes durable. It
loads the connection fact, computes the root range summary for facts visible on
that connection, creates a root `compare` fact, and asks connection to send it.

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

### `cascade_test_fact` (tag 2)

Synthetic fixed-width test fact used to exercise dependency replay. Projection
requires the outer timestamp to match the payload timestamp and waits for each
dependency as `sync_exact_fact` in the same scope. When all dependencies are
present it offers `sync_exact_fact`.

```text
cascade_test_fact {
  timestamp: 1715000000000
  dependencies: [fact:dep_a, fact:dep_b]
  payload: bytes:16_byte_test_payload
}
```

### `range_request` (tag 160)

Workspace-scoped control fact requesting a timestamp interval on one
connection. Current projection validates that the outer scope matches the
workspace and records no rows; transfer is driven by compare and send handlers.

```text
range_request {
  workspace_id: fact:workspace_acme
  connection_id: fact:connection_response_ab
  start: 1715000000000
  end: 1715000999999
}
```

### `shared_fact` (tag 162)

Declares that one fact id is shared in a workspace. Projection requires
workspace scope and offers `sync_exact_fact` for the named fact id. Most live
sharing is recorded by the `share_fact_with_sync` handler rather than by
creating this fact manually.

```text
shared_fact {
  workspace_id: fact:workspace_acme
  fact_id: fact:message_hello
}
```

### `compare` (tag 165)

Negentropy range summary for one connection. Projection writes
`sync_compare_rows` and emits `send_sync_compare_response`. The handler decides
whether to answer, split, or send exact ids.

```text
compare {
  connection_id: fact:connection_response_ab
  range: { start: 0, end: u64::MAX }
  summary: { count: 318, fingerprint: blake3:range_fingerprint }
  response_requested: true
}
```

### `have_id` (tag 166)

Advertises that a peer has one fact id at the timestamp used by compare
planning. Projection writes `sync_have_id_rows` and emits
`send_needed_fact_id`.

```text
have_id {
  connection_id: fact:connection_response_ab
  timestamp: 1715000060000
  fact_id: fact:message_hello
}
```

### `need_id` (tag 167)

Requests bytes for exactly one fact id on one connection. Projection writes
`sync_need_id_rows` and emits `send_requested_fact`.

```text
need_id {
  connection_id: fact:connection_response_ab
  fact_id: fact:message_hello
}
```

## Example Fact Graph

```text
auth/content projector admits message_hello
  -> share_fact_with_sync(upsert message_hello, context_have=[endpoint, user, key])
  -> sync_shareable_fact_rows + negentropy rows

connection_response_ab
  -> seed_connection_sync
  -> compare(root summary)
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
