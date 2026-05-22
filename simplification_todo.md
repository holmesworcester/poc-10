# Pipeline Simplification Todo

This is a working backlog for simplifying `src/core/pipeline.rs` and the
runtime model around it. Some older planning notes may be stale; this file is
about the code as it currently exists.

## Target Shape

Think of the runtime as a small set of SQLite-backed queues. Each worker handles
one queue item, commits its effects, and those effects may enqueue work for
another queue.

```text
fact admission -> pending_projection
projection -> context rows, row mutations, intents, time wakes
context matching -> pending_projection
time wakes -> pending_projection
intent dispatch -> facts, purges, row mutations, follow-up intents
incoming frames / commands -> facts and intents
```

The core simplification rule: make storage placement a table property, not a
Rust side channel. Durable work lives in durable SQLite tables. Restart-local
work lives in SQLite TEMP tables.

## 1. Store All Intents In SQLite Queues

Current pain:

- `IntentExecution::Ephemeral` creates a separate in-memory path in
  `IntentPipeline`.
- `IntentPipeline` owns `ephemeral_intents`, `ephemeral_intent_keys`, and a
  `fact_cache` just to make restart-local handlers look enough like stored
  handlers.
- `pipeline.rs` has separate stored and ephemeral dispatch implementations that
  are mostly the same pipeline with different claim/restore mechanics.

Target:

```text
Intent = kind + idempotence_key + payload

durable_intents: durable SQLite table
local_intents: TEMP SQLite table
```

Restart-local behavior comes from the queue table being memory-local, not from
an `Ephemeral` execution mode.

First migration steps:

1. Add a core `LOCAL_INTENTS` table declared with `Schema::memory_row_table`.
2. Store network/restart-local intents in `LOCAL_INTENTS` using the same row
   encoding as durable `INTENTS`.
3. Replace `dispatch_ephemeral_intents_matching` with the normal stored-intent
   dispatch path parameterized by queue table.
4. Delete `ephemeral_intents`, `ephemeral_intent_keys`, and `fact_cache`.
5. Load handler fact context from SQLite for both durable and local intents.
6. Remove `IntentExecution::Ephemeral` after constructors and registry metadata
   stop depending on it.

Open decision:

- A `LOCAL_INTENTS` temp row table can reuse the current `intent_row` byte
  encoding immediately. If we want `local_intents` to be a typed table like the
  durable `intents` table, extend schema application to support TEMP typed
  tables.
- Keep `IntentExecution::Deferred` temporarily as "handler work", or remove
  `IntentExecution` entirely once row mutations are no longer modeled as
  `AtomicIntent`.

## 2. Stop Modeling Row Mutations As Intents

Current pain:

- `AtomicIntent` is not really an intent queue item. It is a deterministic row
  mutation that must commit with projection or handler output.
- `ProjectionOutput::intents` mixes queued work with row writes.
- `HandlerOutput::intents` has the same split hidden inside it.

Target:

```rust
ProjectionOutput {
    needs,
    offers,
    time_wakes,
    row_mutations,
    intents,
}

HandlerOutput {
    facts,
    purged_facts,
    row_mutations,
    intents,
}
```

First migration steps:

1. Introduce a core `RowMutation` enum equivalent to current
   `AtomicIntent::{PutRow, DeleteRow}`.
2. Add `row_mutations` to `ProjectionOutput` and `HandlerOutput`.
3. Keep `AtomicIntent` as a compatibility adapter while projectors migrate.
4. Apply row mutations in the existing projection/handler commit transactions.
5. Remove `IntentExecution::Atomic` once no projector or handler emits row
   writes through `ProjectionOutput::intents`.

Result:

- Intent dispatch only handles handler work.
- Projection commit no longer has to split "atomic/durable/ephemeral" intent
  classes.
- The intent table becomes a real queue, not a mixed command/effect encoding.

## 3. Split `pipeline.rs` By Queue Responsibility

Current pain:

- One file owns fact admission, purge, time wakes, projection, context matching,
  stored dispatch, ephemeral dispatch, intent memory, and reporting.
- The code is readable locally, but the module boundary says "pipeline" for
  too many different pipelines.

Target modules:

```text
src/core/pipeline.rs              small facade / public runtime entry points
src/core/pipeline/admission.rs    submit facts, bulk submit, purge
src/core/pipeline/projection.rs   pending_projection worker
src/core/pipeline/context_wake.rs context matching worker
src/core/pipeline/time_wake.rs    time_wakes -> pending_projection
src/core/pipeline/dispatch.rs     intent queue worker
src/core/pipeline/effects.rs      common commit/apply helpers
src/core/pipeline/queues.rs       queue table helpers and claim APIs
```

First migration step:

- Move code without changing behavior. This should be a mechanical split that
  keeps tests stable before changing semantics.

## 4. Make Queue Workers Process One Item Shape

Current pain:

- `process_pending_facts_and_context_changes` hardcodes a linear alternation:
  context changes, projection, context changes, projection.
- Runtime then separately runs intent dispatch, then projection again.
- That shape makes it hard to see which pipelines are separate and which are
  merged only because of wake-loop scheduling.

Target:

```text
process_one_projection()
process_one_context_change()
process_one_time_wake_range()
dispatch_one_intent(queue)
```

Each function should:

1. Claim or read one bounded unit of work.
2. Load inputs.
3. Run pure Rust logic outside the write transaction when possible.
4. Commit effects in one transaction.
5. Return a small `WorkStatus`.

The runtime scheduler can then drain queues in a simple policy loop. Later, the
same shape can support independent workers.

## 5. Push More Selection And Fanout Into SQLite

Current pain:

- `pending_owner_batch` scans `pending_projection`, loads each fact, sorts in
  Rust, then truncates.
- `process_due_time_range` scans all `time_wakes` and filters in Rust.
- `process_context_changes` decodes rows into Rust deltas, then matching does a
  mix of SQL lookup and Rust fanout.
- Purge and owner replacement often collect keys before deleting rows SQLite can
  find by indexed columns.

SQLite-first simplifications:

1. Pending projection:

   ```sql
   SELECT p.owner
   FROM pending_projection p
   JOIN facts f ON f.id = p.owner
   ORDER BY f.timestamp, p.owner
   LIMIT :limit;
   ```

2. Time wakes:

   ```sql
   SELECT timeline, at, owner
   FROM time_wakes
   WHERE timeline = :timeline
     AND (:has_start = 0 OR at > :start_exclusive)
     AND at <= :end_inclusive
   ORDER BY at, owner
   LIMIT :limit;
   ```

3. Exact context wake insertion:

   ```sql
   INSERT OR IGNORE INTO pending_projection(owner)
   SELECT c.owner
   FROM pending_context_changes c
   JOIN context_needs n
     ON n.owner = c.owner
    AND n.role = c.role
    AND n.scope_key = c.scope_key
    AND n.selector = c.selector
   JOIN context_offers o
     ON o.role = c.role
    AND o.scope_key = c.scope_key
    AND o.selector = c.selector
   WHERE c.change_kind = 0

   UNION

   SELECT n.owner
   FROM pending_context_changes c
   JOIN context_offers o
     ON o.owner = c.owner
    AND o.role = c.role
    AND o.scope_key = c.scope_key
    AND o.selector = c.selector
   JOIN context_needs n
     ON n.role = c.role
    AND n.scope_key = c.scope_key
    AND n.selector = c.selector
   WHERE c.change_kind = 1;
   ```

4. Owner replacement:

   - Since context rows are keyed by owner and projection owns the complete
     context for that owner, prefer `DELETE WHERE owner = ?` plus insert next
     context over deleting the previous key set.

5. Purge:

   - Prefer indexed `DELETE WHERE owner = ?` helpers for context, time wakes,
     pending changes, and pending time ranges.

Store implication:

- The generic `Store` API currently exposes mostly row-key operations plus typed
  equality scans. To use SQLite declaratively without leaking raw SQL
  everywhere, add narrow typed helpers for:
  - bounded ordered selects,
  - delete by typed filters,
  - insert-select for known core queue fanout,
  - maybe transaction-local SELECT-only plans for context wake queries.

## 6. Reconsider `pending_context_changes`

Current pain:

- Projection commits context rows, writes pending context-change rows, then a
  separate worker reads those rows to wake facts.
- For exact matching, this can often be done as declarative SQL in the same
  transaction as context replacement.

Two possible directions:

1. Merge exact wake insertion into projection commit.

   - After inserting added needs/offers, immediately enqueue exact matches with
     SQL.
   - Keep a separate context-change queue only for expensive custom matchers.

2. Keep context changes as a queue, but make the queue declarative.

   - `pending_context_changes` remains the handoff between projection and
     matching workers.
   - Matching workers should use SQL fanout and delete-by-filter rather than
     reconstructing large Rust deltas.

Bias:

- Merge exact matching now; keep a separate queue only where it buys scheduling
  or boundedness.

## 7. Make Context More Generic

Current pain:

- `ContextNeed` and `ContextOffer` have the same storage shape.
- `context_needs`, `context_offers`, and `pending_context_changes` duplicate
  row encoding and decoding logic.
- Most wake logic cares about direction plus `(role, scope_key, selector)`.

Possible target:

```text
context_edges(
  owner,
  direction, -- need or offer
  role,
  scope_key,
  selector,
  primary key(owner, direction, role, scope_key, selector)
)

index by_match(direction, role, scope_key, selector)
index by_owner(owner, direction)
```

Advantages:

- One row codec.
- One owner replacement path.
- One pending context-change row shape.
- Exact matching becomes a self-join over opposite directions.

Open questions:

- Whether two tables remain faster and clearer than one table with a direction
  column.
- Whether future offers need `payload_ref` separate from `owner`. If yes,
  include it before doing this migration.

## 8. Treat Context As Mostly Monotonic, But Keep Replacement Local

Facts are immutable and admitted facts generally grow. Context is less strictly
monotonic because a projector can stop needing something after a later context
match, and purges remove rows.

Cleaner framing:

- Context rows are the current declared edges for one owner fact.
- Projection replaces only that owner's edges.
- Only added edges create new wake opportunities.
- Removed edges should usually not enqueue work; they only remove future match
  evidence.

This keeps the useful monotonic intuition without pretending every row is
append-only.

Possible simplification:

- Stop recording removed context in scheduler queues.
- Keep removed context only in tests/debug reports if needed.
- Make wake generation depend only on SQL-visible newly inserted edges.

## 9. Simplify Projector Row Writing With Ownership Rules

Current pain:

- Row mutations are applied via atomic intents.
- Idempotent insert rejects conflicting values for the same row key.
- Some projector rows are fact-owned and naturally stable. Others are semantic
  read-model rows that can change when later context appears.

Target row ownership modes:

1. Fact-owned rows.

   - Key includes `fact_id`, or table has a `fact_id` ownership column.
   - Replay of the same fact replaces exactly the same rows.
   - Purge can remove rows for that fact.

2. Semantic view rows.

   - Key is a domain id such as `(workspace_id, message_id)`.
   - Multiple facts may contribute over time.
   - Prefer append-only fact-owned projection rows plus SQL views/queries, or an
     explicit deterministic replacement policy.

First migration steps:

1. Inventory projection tables by row key.
2. Mark each table as fact-owned or semantic-view.
3. For fact-owned tables, use replace/upsert semantics during replay.
4. For semantic-view tables, avoid hidden last-writer behavior. Either make the
   row key include source fact id or define the merge policy declaratively.

Design goal:

- Replaying a projector with unchanged context changes nothing.
- Replaying with changed context replaces exactly the rows owned by that
  projection.
- Projector rows should not need idempotent intent conflict semantics to protect
  correctness.

## 10. Unify Commands, Incoming Facts, And Handler Output Admission

Current pain:

- Commands return `CommandOutput`.
- Handlers return `HandlerOutput`.
- Incoming network frames become local receive intents, which then return facts.
- Each path eventually needs the same admission operation: insert facts, mark
  projections pending, record intents.

Target:

```text
RuntimeEffects {
  facts,
  purged_facts,
  row_mutations,
  durable_intents,
  local_intents,
}
```

Use this as the common commit boundary for:

- command output,
- received/incoming facts,
- handler output,
- possibly projection output after row mutations are split out.

This would merge "handling commands" and "handling received incoming facts" at
the runtime boundary without making commands or network handlers know about the
pipeline internals.

## 11. Prepare For Parallel Queue Workers Later

Current state:

- The store uses one SQLite connection per `Runtime`.
- Queue reads are mostly scan/read then delete during commit.
- There is no lease/claim state, so multiple workers could duplicate work.

Before real parallelism:

1. Add queue claim semantics:

   ```text
   pending_projection(owner, claimed_by, claimed_until_ms)
   intents(kind, key, queue, claimed_by, claimed_until_ms, payload)
   ```

2. Use `UPDATE ... WHERE claimed_until_ms < now LIMIT ... RETURNING ...` style
   claims where SQLite version permits, or a transaction-local select/update
   fallback.
3. Make every worker idempotent at commit.
4. Use separate `Store` handles per worker with WAL enabled.

Do not add parallel execution before the queues have explicit claim/lease
columns. The current code can be reorganized into queue workers first while
still running in one thread.

## 12. Suggested Order

1. Mechanical file split for `pipeline.rs`.
2. Add `LOCAL_INTENTS` TEMP table and dispatch local intents through the stored
   intent path.
3. Remove `IntentExecution::Ephemeral` and the in-memory intent cache.
4. Introduce `RowMutation` and migrate projectors/handlers off `AtomicIntent`.
5. Collapse stored intent dispatch to one queue-parameterized implementation.
6. Add narrow declarative SQLite helpers for pending projection and time wakes.
7. Move exact context wake fanout into SQL.
8. Decide whether to merge context tables into `context_edges`.
9. Inventory projection row ownership and fix replay/upsert semantics.
10. Introduce queue claim/lease columns only after the single-worker model is
    simpler.
