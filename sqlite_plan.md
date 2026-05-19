# SQLite-First Wake Loop And Matchers

This plan keeps the current projector model intact while moving scheduler state,
context lookup, and matcher candidate search into SQLite.

The goal is not to move protocol decisions into storage. Projectors still decide
what rows, needs, offers, time wakes, and intents to emit. SQLite becomes the
durable indexed substrate that lets core find matching context and retry work
without loading the whole graph into memory.

## Core Model

Current conceptual model stays:

```text
fact + matched context -> projector -> needs, offers, time wakes, intents
```

The important storage change is:

```text
SQLite is the scheduler source of truth.
WakeLoop memory is only the current working set.
```

Core owns:

- fact admission
- pending projection queue
- context replacement for one owner
- matcher candidate lookup
- pending wake insertion
- atomic row intent application
- deferred intent persistence
- retry behavior
- transactions

Protocol owns:

- fact layouts and projector semantics
- context role names
- selector field declarations
- matcher relation declarations
- semantic validation of matched payloads inside projectors

Core must not special-case protocol role names.

## Durable Tables

The scalable v1 should use typed durable tables for scheduler state:

```text
facts(
  id primary key,
  scope_tag,
  scope_kind,
  scope_id,
  timestamp,
  bytes
)

context_needs(
  owner,
  role,
  scope_key,
  selector,
  primary key(owner, role, scope_key, selector)
)

context_offers(
  owner,
  role,
  scope_key,
  selector,
  payload_ref,
  primary key(owner, role, scope_key, selector, payload_ref)
)

pending_projection(
  owner primary key
)

time_wakes(
  timeline,
  at,
  owner,
  primary key(timeline, at, owner)
)

intents(
  idempotence_key primary key,
  kind,
  execution,
  payload
)
```

Useful generic indexes:

```text
context_needs(role, scope_key, selector)
context_offers(role, scope_key, selector)
context_needs(owner)
context_offers(owner)
time_wakes(timeline, at)
```

Exact context roles can use these generic indexes directly.

Custom matcher roles may declare role-specific typed index tables. Those tables
are still owned by core execution, but their shape comes from protocol schema.

## Wake Loop V1

`WakeLoop` should become a small retryable job runner.

Fact admission:

```text
submit_fact(fact):
  INSERT OR IGNORE INTO facts ...
  if inserted:
    INSERT OR IGNORE INTO pending_projection(owner = fact.id)
```

Projection drain:

```text
drain_one:
  read one pending owner
  load owner fact
  load previous context for owner
  load matched context for owner's current needs
  run projector outside the SQLite write transaction

  BEGIN IMMEDIATE
    optionally recheck owner context version
    replace owner context with projector output
    update exact/custom matcher indexes
    match added needs against existing offers
    match added offers against existing needs
    INSERT OR IGNORE pending_projection rows for matched need owners
    apply atomic row intents
    persist deferred intents
    replace time wakes for owner
    DELETE FROM pending_projection WHERE owner = current owner
  COMMIT
```

Failure rule:

```text
If projection or commit fails, the owner remains pending and retries later.
```

This preserves the current full-state replay model. A projector does not need to
know whether it is running for the first time, after a duplicate wake, after a
crash, or after a transaction conflict.

## WakeLoop Internal Shape

Do not split `wake_loop.rs` as part of the SQLite-first migration. The SQLite
work should remove enough long-lived in-memory state that the file can become a
straight orchestration layer. Keep implementation-local structs in the file when
they make one transaction step explicit, but avoid creating parallel modules
until there is a clear post-migration reason.

The public surface should stay small:

```text
submit_fact
drain_projection / drain_projection_until_idle
dispatch_intents
wake_time_range
save or flush only if a compatibility bridge still needs it
```

The private flow should read as a pipeline:

```text
claim pending owner
load owner snapshot
run projector outside transaction
validate projection output
commit owner effects in one transaction
dispatch handler output through one shared path
```

Useful internal structs:

- `OwnerSnapshot`: owner fact, previous owner context, matched projection
  context, and any context version/recheck token.
- `ContextReplacement`: normalized new context plus the owner-local delta
  against previous needs/offers.
- `WakeCandidates`: matched need owners and payload refs discovered by exact or
  custom matcher lookup.
- `IntentEffects`: atomic row mutations and deferred intents derived from one
  projection or handler output.
- `HandlerEffects`: emitted facts, purged facts, emitted intents, and report
  increments after one handler invocation.

These structs are transaction-local data carriers. They should not rebuild the
current `WakeLoop` memory model under new names.

As SQLite takes over, delete these current responsibilities from `WakeLoop`
instead of wrapping them:

- whole-graph fact map
- owner-to-context map
- in-memory exact need/offer indexes
- in-memory time-wake map
- pending projection deque and owner set
- intent vector plus in-memory idempotence index
- dirty/deleted tracking sets
- whole-graph `load` / dirty `save` as the primary persistence mechanism

Simplification rules for the implementer:

- Prefer one named helper per pipeline step over nested control flow in
  `drain_inner`.
- Centralize handler-output application so atomic, deferred, fact-context, and
  store-context dispatch paths do not duplicate purge/submit/record logic.
- Replace stringly control flow for retry and missing input with explicit
  internal result variants where possible.
- Keep byte encoding and row decoding out of the wake-loop hot path; use shared
  `wire` helpers and typed SQLite rows.
- Keep matcher lookup behind helper functions that return candidate rows.
  `WakeLoop` should decide when to wake, not how each matcher query is built.

## Context Replacement

Projectors return the complete current context set for the single fact owner
being projected.

Core compares:

```text
previous needs/offers for this owner
current needs/offers returned by this projection
```

The resulting owner-local delta is used as follows:

```text
unchanged need/offer
  keep it; do not wake anyone

added need
  insert it; match existing offers; wake this need owner if matched

added offer
  insert it; match existing needs; wake matched need owners

removed need/offer
  delete it and delete its matcher index rows
```

The diff is not exposed to projectors. It is only the adapter from declarative
full-state projector output to incremental scheduler effects.

## Projection Context Loading

Before projection, core builds `ProjectionContext` from durable state:

```text
1. Load current needs for owner.
2. For each need, find matching offers using indexed matcher lookup.
3. Load payload facts by offer.payload_ref.
4. Pass MatchedContext { need, offer, payload } to the projector.
```

Facts should be loaded on demand by `fact_id` / `payload_ref`, not loaded into a
global in-memory map at runtime open.

## Matcher Model

Matchers find candidates. They do not decide protocol authority and do not
mutate state.

Core converts matcher results into the normal wake behavior:

```text
added need -> matching offer refs -> wake added need.owner
added offer -> matching need owners -> wake those owners
```

Projectors still decode and validate payload facts before emitting rows, offers,
or intents.

## Exact Matching

Exact matching should be core-native.

For a new need:

```sql
SELECT owner AS offer_owner, payload_ref
FROM context_offers
WHERE role = :role
  AND scope_key = :scope_key
  AND selector = :selector;
```

For a new offer:

```sql
SELECT owner AS need_owner
FROM context_needs
WHERE role = :role
  AND scope_key = :scope_key
  AND selector = :selector;
```

This keeps all existing exact roles compatible with the current
`ContextNeed` / `ContextOffer` shape.

## Protocol Metadata

Protocol-specific matcher behavior should move into schema declarations, not
hand-written core code.

That metadata may include:

- context role name
- scope kind
- need selector fields
- offer selector fields
- selector encoding version
- relation type
- matcher indexes
- optional SELECT-only matcher SQL

This is not a boundary violation as long as core treats it as data and never
special-cases protocol role names.

Example declaration:

```text
context_role sync_range_fact {
  scope workspace;

  need {
    start u64;
    end u64;
  }

  offer {
    timestamp u64;
    fact_id bytes(32);
    dependency_id bytes(32);
    key_wrap_id bytes(32);
  }

  match point_in_interval(offer.timestamp, need.start, need.end);
}
```

Core can compile that into typed index tables, selector encoders/decoders, and
query plans.

## SELECT-Only Custom Matcher SQL

Custom matchers can use SQL as a constrained escape hatch.

Allowed:

- `SELECT` only
- named bound parameters only
- reads from declared context/index tables only
- fixed result shapes

Forbidden:

- `INSERT`, `UPDATE`, `DELETE`, DDL, pragmas, or side effects
- string interpolation of values
- role-name special cases in core
- arbitrary access to unrelated tables

For an added need, custom SQL returns matching offers:

```sql
SELECT offer_owner, payload_ref
FROM sync_range_fact_offers
WHERE scope_key = :scope_key
  AND timestamp BETWEEN :need_start AND :need_end;
```

For an added offer, custom SQL returns matching needs:

```sql
SELECT need_owner
FROM sync_range_fact_needs
WHERE scope_key = :scope_key
  AND start <= :offer_timestamp
  AND end >= :offer_timestamp;
```

Core performs all writes after reading these candidates.

## Custom Matcher Migration

Existing custom matcher modules can shrink or disappear as hand-written matcher
logic once their selectors and relations are declared.

`range` is directly expressible:

```text
need.start <= offer.timestamp <= need.end
```

`coverage` is expressible with a SQL prefilter plus a generic prefix primitive:

```text
workspace equal
frontier equal
need.minute within offer.start_minute..offer.end_minute
need.leaf_id matches offer.leaf_prefix / offer.prefix_bytes
```

`wrap_source` needs either tagged need variants or multiple relations under one
role:

```text
requested need:
  workspace equal and frontier equal

proactive need:
  workspace equal and offer.frontier_created_at_ms >= need.minimum_created_at
```

The generated encoding must match existing selector bytes if persisted context
rows need to remain valid without migration.

## What Changes Only Core

These changes should not alter protocol behavior:

- SQLite-first pending projection queue
- SQLite-first intent queue
- SQLite indexed time wakes
- on-demand fact loading
- exact matcher lookup through SQLite indexes
- owner-scoped context replacement in one transaction
- building `ProjectionContext` from SQLite instead of memory maps
- removing whole-graph `WakeLoop::load` / dirty `save` as the primary mechanism

Projectors can keep emitting the existing `ContextNeed` and `ContextOffer`
values.

## What Requires Protocol Metadata

These require protocol declarations, but not protocol logic changes:

- selector schemas for each context role
- relation declarations for non-exact roles
- index declarations for custom matcher lookup
- generated or schema-backed replacement for `CONTEXT_MATCHERS`

This is protocol as data.

## What Should Not Change In V1

Avoid changing protocol semantics:

- role names
- scope meanings
- fact wire layouts
- selector byte encodings, unless paired with migration
- matcher truth conditions
- projector authority over rows, offers, and intents

Do not introduce direct batch effects as part of this change. Broad fanout can be
made scalable by using SQL to enqueue pending projection rows, while projectors
still decide each affected fact's output.

## Migration Plan

1. Add typed durable `context_needs` and `context_offers` tables alongside the
   current row tables.
2. Implement exact matcher lookup from SQLite while keeping existing projectors
   and need/offer constructors unchanged.
3. Change fact lookup to load payloads on demand by `payload_ref`.
4. Move `pending_projection`, `intents`, and `time_wakes` to SQLite-first queue
   operations.
5. Make projection drain commit one owner at a time with owner context
   replacement, matcher lookup, wake insertion, row intents, and intent
   persistence in one transaction.
6. Add schema declarations for context roles and exact matcher metadata.
7. Add SELECT-only custom matcher SQL support.
8. Convert `range`, then `coverage`, then `wrap_source` to schema-backed
   declarations and generated/core query plans.
9. Reshape `wake_loop.rs` into the single-file orchestration facade described
   above: use owner-local temporary structs, one helper per drain/dispatch step,
   one shared handler-output application path, and transaction-local effects
   instead of field-level dirty tracking.
10. Delete in-memory context maps, exact indexes, dirty sets, and whole-graph
   load/save once the SQLite path owns the runtime.

## Target Invariant

After each committed projection transaction, SQLite contains the complete
recoverable scheduler state:

```text
facts
current needs/offers
matcher indexes
pending projection
time wakes
intents
projection rows
```

Restart resumes by reading pending work from SQLite, not by rebuilding a large
in-memory graph.
