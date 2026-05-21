# Pipeline Simplification Todo

Working backlog for simplifying `src/core/pipeline.rs` and the runtime model.
Some older `sqlite_plan` notes may be stale; this file tracks the desired core
shape directly.

## Target Shape

Think of the runtime as a small set of SQLite-backed queues. Each worker handles
one item, commits its effects, and those effects may enqueue work for another
queue.

```text
fact admission -> pending_projection
projection -> context rows, row mutations, intents, time wakes
context matching -> pending_projection
time wakes -> pending_projection
intent dispatch -> facts, purges, row mutations, follow-up intents
incoming frames / commands -> facts and intents
```

Keep the scheduler single threaded for now. Parallel workers should wait until
queues have explicit claim/lease state.

## Status

- Done in this branch: restart-local intents now use a SQLite TEMP
  `local_intents` queue.
- Done in this branch: stored and local intent dispatch share the same
  queue-dispatch path.
- Done in this branch: the `IntentPipeline` compatibility shell and
  `ephemeral_intents()` surface are gone.
- Done in this branch: `Intent` no longer carries durability. The destination
  queue table owns durable versus restart-local storage.
- Done in this branch: common commit work now flows through `PipelineEffects`.
- Done in this branch: core pipeline table names moved to `core::schema`, and
  `local_intents` is declared as a memory row table in `src/core/schema.p8sql`.
- Done in this branch: `driver.rs` is now `fact_context.rs`, and due time
  wakes live with the fact/context fixed-point loop.
- Done in this branch: row writes are `RowMutation` output, not `Intent`
  values. `IntentExecution::Atomic`, `AtomicIntent`, and the atomic dispatch
  pass are gone from production code.
- Done in this branch: `core::pipeline` is now a small facade over
  queue-responsibility modules under `src/core/pipeline/`.
- Important lesson: local intent dispatch must preserve FIFO insertion order.
  Lexicographic key order can starve multi-daemon bootstrap and receive work.

## 1. Store All Intents In SQLite Queues

Target:

```text
durable handler work -> durable INTENTS table
restart-local handler work -> TEMP LOCAL_INTENTS table
```

The storage table determines durability. `Intent` carries only kind,
idempotence key, and payload. Protocol metadata now declares durable/local
queue class without changing the queued row format.

Next steps:

1. Done: keep `LOCAL_INTENTS` as a TEMP row table.
2. Done: preserve FIFO claim order for local queues.
3. Done: remove the remaining `ephemeral_intents()` compatibility surface.
4. Done: collapse intent execution classes after row mutations stopped being
   encoded as intents.

## 2. Stop Modeling Row Mutations As Intents

`AtomicIntent` is not queue work. It is a deterministic row mutation that must
commit with projection or handler output.

Target:

```rust
ProjectionOutput {
    needs,
    offers,
    time_wakes,
    row_mutations,
    intents,
    local_intents,
}

HandlerOutput {
    facts,
    purged_facts,
    row_mutations,
    intents,
    local_intents,
}
```

Migration:

1. Done: introduce `RowMutation::{PutRow, DeleteRow}`.
2. Done: add `row_mutations` to projection and handler output.
3. Done: migrate protocol projectors and tests off row intents.
4. Done: remove `IntentExecution::Atomic` and the atomic dispatch pass.

## 3. Split `pipeline.rs` By Queue Responsibility

Status: done mechanically in this branch. The facade remains
`src/core/pipeline.rs`; implementation lives under `src/core/pipeline/`.

Target modules:

```text
src/core/pipeline.rs              facade / runtime entry points
src/core/pipeline/admission.rs    submit facts, bulk submit, purge
src/core/pipeline/fact_context.rs fact/context loop, due time wake admission
src/core/pipeline/projection.rs   pending_projection worker
src/core/pipeline/context_wake.rs context matching worker
src/core/pipeline/dispatch.rs     intent queue worker
src/core/pipeline/effects.rs      common commit helpers
```

The current split is intentionally conservative and keeps behavior unchanged.
Further cleanup should simplify module internals. `pipeline_storage.rs` is the
main remaining complexity sink because it still mixes row codecs, mutation
helpers, context reads, and matching queries.

## 4. Process One Queue Item At A Time

The core worker shape should be:

```text
claim/read one item
load inputs
run Rust logic outside the write transaction where possible
commit effects in one transaction
return WorkStatus
```

This applies to projection, context wake, time wake, and intent dispatch. The
single-threaded scheduler can then drain queues using a clear policy loop.

## 5. Push More Fanout Into SQLite

Good candidates:

1. Pending projection order:

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

3. Exact context wake insertion can be an `INSERT OR IGNORE ... SELECT` over
   needs and offers instead of decoding broad Rust deltas.

Add narrow store helpers for bounded ordered selects, delete-by-filter, and
known insert-select fanout. Avoid scattering raw SQL through protocol code.

## 6. Reconsider `pending_context_changes`

Exact context wake insertion can probably merge into projection commit. Keep a
separate context-change queue only for custom matchers or where bounded
scheduling matters.

Bias:

- Insert exact wakes with SQL immediately after context rows are updated.
- Stop tracking removed context as scheduler work unless a concrete use appears.

## 7. Make Context More Generic

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
```

This would replace duplicated need/offer codecs and make exact matching a
self-join over opposite directions.

## 8. Treat Context As Mostly Monotonic

Facts are immutable and admitted facts generally grow. Context rows are the
current declared edges for one owner fact.

Rules:

- Projection replaces only one owner's edges.
- Added edges create wake opportunities.
- Removed edges normally just remove future evidence.

This gives the useful monotonic mental model without pretending projection rows
are append-only.

## 9. Simplify Projector Row Writing

Separate projection tables into two ownership modes:

- Fact-owned rows: key includes `fact_id`, or table has a `fact_id` ownership
  column. Replay replaces exactly that fact's rows.
- Semantic view rows: key is a domain id and multiple facts may contribute.
  These need either declarative merge rules or append-only fact-owned source
  rows plus query-time views.

Design goal:

- Replaying a projector with unchanged context changes nothing.
- Replaying with changed context replaces exactly the rows owned by that
  projection.

## 10. Unify Admission Effects

Use one common effect boundary for commands, incoming network work, handlers,
and eventually projection:

```text
PipelineEffects {
  facts,
  purged_facts,
  row_mutations,
  durable_intents,
  local_intents,
}
```

Status: started. Handler output and command output now reduce to
`PipelineEffects`, and projection stores its row/intents side effects inside
`PipelineEffects` while keeping projection-owned context and time-wake changes
separate.

## 11. Defer Parallelism

Before real parallel workers:

1. Add queue claim/lease columns.
2. Claim with transaction-local update/select semantics.
3. Keep commits idempotent.
4. Use one `Store` handle per worker with WAL enabled.

For now, target a simpler single-threaded queue scheduler.
