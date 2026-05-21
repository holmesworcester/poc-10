# SQLite-First Runtime Pipelines

This note records the current SQLite runtime direction. Older migration notes
for separate context need and offer tables have been retired; the active model
is the queue/edge shape tracked in `simplification_todo.md`.

## Core Model

Core runtime state is a small set of SQLite-backed queues and declared tables:

```text
fact admission -> pending_projection
projection -> context_edges, time_wakes, row mutations, intents
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
  bytes
)

local_fact_admissions(
  id primary key,
  fact_id unique,
  scope,
  scope_kind,
  scope_id,
  received_at,
  bytes -- encoded local-only admission fact
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

intents(kind, idempotence_key, payload)
local_intents(kind, idempotence_key, payload) -- SQLite TEMP table
time_wakes(timeline, at, owner)
clock(key, timestamp)
```

`local_fact_admissions` is deliberately modeled as a local-only fact about the
actual content-addressed fact. `received_at` is the node's admission time in the
target model; the current Rust `Fact.timestamp` field remains compatibility
debt until sync/range ordering reads protocol-derived event-time indexes. Event
timestamps themselves remain inside the protocol fact bytes that need them.

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
JOIN local_fact_admissions a ON a.fact_id = n.owner
WHERE n.direction = 'need'
  AND n.role = :role
  AND n.scope_key = :scope_key
  AND n.selector = :selector
ORDER BY a.received_at, n.owner;
```

Custom matcher roles also supply wake selects. Core executes those selects
during projection commit and inserts affected owners directly into
`pending_projection`.

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
- Core, network, fact, and intent tables are all declared through p8sql schema
  sources. The old Rust `Schema` registration path has been removed.
- Context wake fanout uses typed `INSERT OR IGNORE ... SELECT` during
  projection commit.
- Time wake admission uses the same checked insert-select pattern from
  `time_wakes` into `pending_projection` and `pending_time_ranges`.
- `core::select::Select` is the shared read-only SELECT shape for this fanout;
  pipeline workers still choose the target queue table and columns.
- Custom matcher candidate lookup for range, coverage, and wrap-source roles is
  SELECT-only SQL over `context_edges`.
- The runtime no longer rebuilds a whole scheduler graph in memory.
- Fact storage and fact purge helpers now live in `core::fact_store`;
  `pipeline_storage.rs` is gone.
- Core pipeline modules and protocol matchers now prepare direct SQL against
  their owned tables instead of using a generic Store selected-row adapter.
