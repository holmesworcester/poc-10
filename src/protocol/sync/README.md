# Sync Fact Scope

Sync facts describe convergence, not domain validity. The scope records which
facts are shareable in a workspace, summarizes shareable fact ranges, advertises
exact ids, requests missing ids, and asks connection to move selected facts.

## Interface To Core

Data enters sync as ordinary sync facts from connection receive paths, as
sync-owned intents dispatched by core, and from CLI/test commands that create
range or cascade facts. Other scopes may enqueue sync-owned intents as
follow-up work, but core treats those payloads as opaque queued work.

Data leaves sync as:

- row mutations in `sync_shareable_fact_rows`, negentropy leaf/context/node
  rows, compare rows, have-id rows, and need-id rows;
- context offers such as `sync_exact_fact` and `sync_key_wrap`;
- control facts such as `compare`, `have_id`, and `need_id`;
- intents to send compare responses, request missing ids, answer requested ids,
  seed a connection, and batch facts onto a connection.

Core owns queueing, fact identity, row commit, handler retry, and context range
matching. Sync owns shareability, connection-specific visibility, range summary
planning, and exact-id request/response mechanics. Sync never parses content,
auth, or connection payload semantics beyond checking fact scope and tag
sendability through the owning helpers.

## Interfaces To Other Scopes

Auth and content projectors enqueue the sync-owned `share_fact_with_sync`
intent only after their own authority checks pass. Sync records those
contributions and their validated context dependencies.

Connection supplies established connection rows and frame send handlers. Sync
asks connection to send fact ids; connection decides frame size, sealing, and
socket IO.

Auth endpoint rows are used when building connection-specific visibility:
shareable-fact queries check workspace membership and connection peer identity
before returning facts to send.

## Invariants And Responsibility

A shareable fact contribution must name an existing non-local owner fact whose
scope is either global or the same workspace scope. Context dependencies
recorded with that contribution must also be non-local if they still exist when
the handler runs.

The share index stores ids and timestamps, not payload copies. If a fact is
purged later, connection-specific queries skip it.

Negentropy summaries are deterministic over connection-visible shareable rows.
Compare facts are hints. If summaries differ, handlers either split ranges,
send exact have-id facts, or send exact requested facts; the receiver still
admits each payload through its owning projector.

Range matching and dependency closure belong in sync rows and handlers.
Semantic admission remains in the fact family that owns the payload.

## Intent Handlers

`share_fact_with_sync` records or retracts one fact's sync contribution. On
upsert it loads the owner fact, rejects local/private owner bytes, validates
context dependencies if present, refreshes shareable and negentropy rows, and
live-tail advertises the fact to established connections except the origin
connection that supplied it.

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

### `encrypted_root` (tag 161)

Advertises that opening one encrypted root fact requires a dependency and key
wrap. Projection requires workspace scope and offers `sync_exact_fact` for the
named root id.

```text
encrypted_root {
  workspace_id: fact:workspace_acme
  fact_id: fact:encrypted_message_root
  dependency_id: fact:retention_workspace
  key_wrap_id: fact:key_wrap_for_phone
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

### `key_wrap_available` (tag 163)

Compact advertisement that a key-wrap fact can be requested in a workspace.
Projection requires workspace scope and offers both `sync_exact_fact` and
`sync_key_wrap` for the key-wrap id.

```text
key_wrap_available {
  workspace_id: fact:workspace_acme
  key_wrap_id: fact:key_wrap_for_phone
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
