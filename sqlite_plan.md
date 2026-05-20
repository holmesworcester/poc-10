# SQLite-First Runtime Pipelines And Matchers

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
IntentPipeline memory is only restart-local ephemeral intent state plus a small
fact cache for those ephemeral handlers.
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

## Runtime Pipelines V1

Runtime should be a small retryable job runner over three explicit
SQLite-backed pipelines: pending fact processing, context-change matching, and
intent dispatch.

Fact admission:

```text
submit_fact(fact):
  INSERT OR IGNORE INTO facts ...
  if inserted:
    INSERT OR IGNORE INTO pending_projection(owner = fact.id)
```

Pending fact processing:

```text
process_one_pending_fact:
  read one pending owner
  load owner fact
  load previous context for owner
  load matched context for owner's current needs
  run projector outside the SQLite write transaction

  BEGIN IMMEDIATE
    replace owner context with projector output
    apply atomic row intents
    persist deferred intents
    replace time wakes for owner
    record added needs/offers as pending context changes
    DELETE FROM pending_projection WHERE owner = current owner
  COMMIT
```

Context-change matching:

```text
process_context_changes:
  read pending need/offer changes

  BEGIN IMMEDIATE
    drop stale pending changes whose need/offer no longer exists
    match added needs/offers against stored context
    INSERT OR IGNORE pending_projection rows for matched need owners
    DELETE processed pending_context_changes rows
  COMMIT
```

Intent dispatch:

```text
dispatch_one_intent:
  claim one stored or restart-local intent
  load handler context
  run handler outside the SQLite write transaction

  BEGIN IMMEDIATE
    delete handled durable intent, if any
    purge requested facts
    admit emitted facts as pending
    apply atomic row intents
    persist emitted deferred intents
  COMMIT
```

Failure rule:

```text
If projection or commit fails, the owner remains pending and retries later.
```

This preserves the current full-state replay model. A projector does not need to
know whether it is running for the first time, after a duplicate wake, after a
crash, or after a transaction conflict.

## Pipeline Shape

The SQLite work removed the old long-lived in-memory scheduler state. Runtime
now calls explicit modules for fact processing, context-change matching, and
intent dispatch. Keep those modules focused on readable staged pipelines: one
top-level function names the steps, and lower helpers explain each transaction
boundary.

The public surface should stay small:

```text
submit_fact
process_pending_facts
process_context_changes
dispatch_*_intents
process_due_time_range
```

The private flow should read as a pipeline:

```text
claim pending fact
load projection inputs
project fact outside transaction
commit fact effects in one transaction
claim pending context changes
match stored context and wake dependent facts
claim intent
run handler outside transaction
commit handler output in one transaction
```

Useful internal structs:

- `OwnerSnapshot`: owner fact, previous owner context, matched projection
  context, and any context version/recheck token.
- `ContextReplacement`: normalized new context plus the owner-local delta
  against previous needs/offers.
- `ContextMatch`: matched need owners and payload refs discovered by exact or
  custom matcher lookup.
- `IntentEffects`: atomic row mutations and deferred intents derived from one
  projection or handler output.
- `HandlerEffects`: emitted facts, purged facts, emitted intents, and report
  increments after one handler invocation.

These structs are transaction-local data carriers. They should not rebuild an
in-memory scheduler model under new names.

SQLite owns these responsibilities directly:

- whole-graph fact map
- owner-to-context map
- in-memory exact need/offer indexes
- in-memory time-wake map
- pending projection deque and owner set
- durable intent queue and idempotence index
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
- Keep matcher lookup behind helper functions that return candidate rows. The
  context-change pipeline should decide when to mark facts pending, while
  matcher modules declare or implement the candidate query for their roles.

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
- removing whole-graph scheduler `load` / dirty `save` as the primary mechanism

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

Current status on `main`:

1. Done: core scheduler state is stored in typed SQLite tables:
   `facts`, `context_needs`, `context_offers`, `pending_projection`,
   `pending_time_ranges`, `pending_context_changes`, `time_wakes`, and
   `intents`.
2. Done: runtime projection drains through SQLite transactions for fact
   admission, pending fact processing, context replacement, context-change
   matching, time wakes, atomic row intents, and deferred intent persistence.
3. Done: runtime open/reload no longer rebuilds a whole scheduler graph.
   Runtime fact iteration, pending counts, and durable intent dispatch read
   SQLite directly.
4. Done: fact and intent storage now matches the data types directly: fact rows
   store id/scope/timestamp/bytes columns, and intent rows are keyed by
   `(kind, idempotence_key)` with execution and payload as ordinary columns.
5. Done: replay-style bulk fact admission uses one SQLite transaction instead
   of one transaction per fact.
6. Done: exact matcher lookup is SQLite-backed for committed wake insertion
   and projection input.
7. Done: context roles have protocol-owned declarations for exact selector
   matching and custom selector fields.
8. Done: custom matcher lookup for `range`, `coverage`, and `wrap_source` uses
   SELECT-only SQL candidate queries with named bound parameters.
9. Done: the custom matcher modules now expose schema-backed query plans while
   retaining pure relation functions for focused tests.

Previously remaining items now closed:

1. Done: the in-memory scheduler facade, context maps, exact indexes, dirty
   sets, and whole-graph `load`/`save` helpers are deleted. Restart-local
   ephemeral intents remain deliberately in memory.
2. Done: stale tests that depended on the deleted memory-only scheduler API
   were converted or removed; black-box runtime tests now exercise the SQLite
   path.

Original sequence:

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
9. Reshape projection work into explicit pipeline modules with one readable
   top-level function per pipeline, one shared handler-output application path,
   and transaction-local effects instead of field-level dirty tracking.
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
