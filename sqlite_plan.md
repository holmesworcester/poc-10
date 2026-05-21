# SQLite-First Runtime Pipelines

This note records the current SQLite runtime direction. Older migration notes
for separate context need and offer tables have been retired; the active model
is the queue/edge shape tracked in `simplification_todo.md`.

## Core Model

Core runtime state is a small set of SQLite-backed queues and declared tables:

```text
fact admission -> pending_projection
projection -> context_edges, time_wakes, row mutations, intents
context matching -> pending_projection
time wakes -> pending_projection
intent dispatch -> facts, purges, row mutations, follow-up intents
commands / incoming frames -> facts and intents
```

The scheduler remains single threaded. The code is shaped as independent queue
workers so explicit claim/lease columns can be added later without changing the
projector or handler contracts.

## Durable Tables

Core-owned runtime tables are declared in `src/core/schema.p8sql`.

```text
facts(
  id primary key,
  scope,
  scope_kind,
  scope_id,
  timestamp,
  bytes
)

context_edges(
  owner,
  direction, -- "need" or "offer"
  role,
  scope_key,
  selector,
  primary key(owner, direction, role, scope_key, selector)
)

pending_projection(owner primary key)

pending_time_ranges(
  owner,
  timeline,
  has_start,
  start_exclusive,
  end_inclusive
)

pending_context_changes(
  owner,
  change_kind,
  role,
  scope_key,
  selector
)

time_wakes(timeline, at, owner)
intents(kind, idempotence_key, payload)
local_intents -- SQLite TEMP row table
```

`context_edges` is the standing context relation. Needs and offers are not
separate storage concepts; they are opposite directions in one indexed table.
Projection replay deletes and replaces exactly the edges owned by the projected
fact id.

## Context Matching

Exact selector roles are core-native SQL over `context_edges`.

For a new need, projection commit inserts the need owner into
`pending_projection` if a matching offer edge exists:

```sql
SELECT :need_owner AS owner
WHERE EXISTS (
  SELECT 1
  FROM context_edges
  WHERE direction = 'offer'
    AND role = :role
    AND scope_key = :scope_key
    AND selector = :selector
);
```

For a new offer, projection commit wakes matching need owners:

```sql
SELECT n.owner
FROM context_edges n
JOIN facts f ON f.id = n.owner
WHERE n.direction = 'need'
  AND n.role = :role
  AND n.scope_key = :scope_key
  AND n.selector = :selector
ORDER BY f.timestamp, n.owner;
```

Custom matcher roles keep SELECT-only protocol-owned candidate queries. Those
queries also read `context_edges` with an explicit `direction` predicate.
`pending_context_changes` is only the queue for custom matcher fanout.

## Ownership Rules

- Projectors are pure over one fact plus supplied context.
- Projectors emit needs, offers, time wakes, row mutations, durable intents, and
  restart-local intents.
- Projection commit replaces only the current fact's context edges and time
  wakes.
- Row writes flow through `PipelineEffects`; projectors do not write SQLite.
- Handlers emit facts, purges, row mutations, and follow-up intents through the
  same effect shape.

## Current Status

- Durable and restart-local intent queues are both SQLite-backed.
- Exact context wake fanout uses typed `INSERT OR IGNORE ... SELECT` during
  projection commit.
- Custom matcher candidate lookup for range, coverage, and wrap-source roles is
  SELECT-only SQL over `context_edges`.
- The runtime no longer rebuilds a whole scheduler graph in memory.
- `pipeline_storage.rs` is narrowed to fact storage and fact purge helpers.
