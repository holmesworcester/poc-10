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
projection -> context_edges, row mutations, intents, time wakes
context matching -> pending_projection
time wakes -> pending_projection
intent dispatch -> facts, purges, row mutations, follow-up intents
incoming frames / commands -> facts and intents
```

Keep the scheduler single threaded for now. Parallel workers should wait until
queues have explicit claim/lease state.

## Ambitious Success Criteria

This rewrite is successful when the runtime reads as queue workers plus
declarative storage, not as one central storage module with pipeline-shaped
branches.

Accountable criteria:

1. `pipeline_storage.rs` is gone, or reduced below 250 lines and renamed to a
   codec-only module. It must not contain queue scheduling, context matching,
   projection commit policy, or intent dispatch policy.
2. Each pipeline worker owns the SQL for the tables it drains or updates:
   `fact_context.rs` owns due time wake admission, `projection.rs` owns pending
   projection selection and fact-owned context/time-wake replacement,
   `context_wake.rs` owns context-match fanout, and `dispatch.rs` owns intent
   queue claim/delete/ordering.
3. Pipeline control flow no longer sorts or filters decoded table rows in Rust
   when the same operation is an indexed SQLite query. In particular, pending
   projection order, due time wake selection, and exact context wake insertion
   should be SQL-first.
4. Byte layout is not part of pipeline control flow. Remaining byte codecs are
   limited to fact payloads, intent payloads, opaque protocol row values, and
   transitional row encoding that cannot yet be represented by typed schema
   columns.
5. `Store` stays generic. Any new SQL affordance is narrow and reusable, such
   as typed bounded selects, delete-by-declared-filter, or checked
   `INSERT OR IGNORE ... SELECT` helpers. Protocol modules still cannot issue
   arbitrary writes through core.
6. Projection replay has a simple ownership rule: a projection replaces exactly
   the context/time-wake rows owned by its `fact_id`, applies protocol
   `RowMutation`s through `PipelineEffects`, and is idempotent when inputs are
   unchanged.
7. Commands, incoming frames, projection, and handlers all reduce committed
   side effects through `PipelineEffects` or an equally small successor shape.
   There must not be a second ad hoc effect path for row writes or emitted
   intents.
8. Runtime remains single threaded until queues have explicit claim/lease
   columns. The code should nevertheless read as independent workers whose
   outputs enqueue each other.
9. Black-box behavior is unchanged. At minimum, every major step must pass
   `cargo test --test black_box_sync_test -- --nocapture --test-threads=1`,
   and the final rewrite must pass full `cargo test`.
10. The end state should reduce complexity, not only relocate it. Track this
    with rough thresholds: `src/core/pipeline/*.rs` should stay split by worker,
    no single pipeline worker should grow into a new 1k-line sink, and the total
    code for pipeline storage/query helpers should be materially smaller than
    the current `pipeline_storage.rs` plus duplicated callers.

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
- Done in this branch: due time wake admission, pending projection selection,
  exact context wake fanout, pending time range load/delete, and projection
  context/time-wake replacement now use declared SQLite columns in their owning
  pipeline modules instead of byte-row scans in `pipeline_storage.rs`.
- Done in this branch: intent queue row encoding, decoding, and insertion live
  with the pipeline queue code in `pipeline/intent_queue.rs`, not in the
  generic fact/context storage module.
- Done in this branch: context edge reads, context matching, scope-key
  handling, and pending context-change queue operations use declared typed
  SQLite rows instead of byte-row scans.
- Done in this branch: `context_store.rs` was removed as a sink. Standing
  context row access now lives in `pipeline/context_rows.rs`; matcher assembly
  and custom matcher fanout live in `pipeline/context_matching.rs`.
- Done in this branch: separate `context_needs` and `context_offers` storage
  was collapsed into one typed `context_edges` relation keyed by
  `(owner, direction, role, scope_key, selector)`.
- Done in this branch: fact insertion, pending-projection marking, and fact
  reads use declared typed SQLite columns; `pipeline_storage.rs` is now fact
  storage plus generic row-mutation helpers.
- Done in this branch: exact context wake fanout runs inside projection commit
  with typed `INSERT OR IGNORE ... SELECT`; `pending_context_changes` is now
  only populated for custom matcher roles.
- Done in this branch: row-mutation validation and splitting moved into
  `pipeline/effects.rs`; `pipeline_storage.rs` is below the 250-line target and
  is limited to fact storage and fact purge helpers.
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
Further cleanup should simplify module internals. `pipeline_storage.rs` has
been narrowed to fact storage and fact purge helpers; context row access and
matching now live with the context/projection pipeline modules.

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

3. Done in this branch: due time wake selection uses typed SQL; pending
   projection selection uses typed SQL; exact context wake fanout uses typed
   `INSERT OR IGNORE ... SELECT` during projection commit.

Done in this branch: add narrow store helpers for bounded ordered selects,
delete-by-filter, and checked insert-select fanout. Avoid scattering raw SQL
through protocol code.

## 6. Reconsider `pending_context_changes`

Exact context wake insertion now runs during projection commit. Keep the
separate context-change queue only for custom matchers or where bounded
scheduling matters.

Bias:

- Done: insert exact wakes with SQL immediately after context edges are updated.
- Done: stop tracking exact context changes as scheduler work.
- Still true: stop tracking removed context as scheduler work unless a concrete
  use appears.

## 7. Make Context More Generic

Done in this branch: needs and offers are stored as opposite directions in one
declared SQLite relation:

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

This replaced duplicated need/offer storage tables and makes exact matching a
direction-filtered query over one relation. The in-memory Rust vocabulary still
uses `ContextNeed` and `ContextOffer` because projectors and matchers benefit
from the type distinction.

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
