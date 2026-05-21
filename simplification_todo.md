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

1. `pipeline_storage.rs` is gone. Fact persistence lives in
   `src/core/fact_store.rs`, and it must not contain queue scheduling, context
   matching, projection commit policy, or intent dispatch policy.
2. Each pipeline worker owns the SQL for the tables it drains or updates:
   `fact_context.rs` owns due time wake admission, `projection.rs` owns pending
   projection selection, `projection_commit.rs` owns fact-owned context/time-wake
   replacement and context-match fanout, and `dispatch.rs` owns intent queue
   claim/delete/ordering.
3. Pipeline control flow no longer sorts or filters decoded table rows in Rust
   when the same operation is an indexed SQLite query. In particular, pending
   projection order, due time wake selection, and context wake insertion should
   be SQL-first.
4. Byte layout is not part of pipeline control flow. Remaining byte codecs are
   limited to fact payloads, intent payloads, opaque protocol row values, and
   transitional row encoding that cannot yet be represented by typed schema
   columns.
5. `Store` stays generic and small enough to justify its public surface. Core
   pipeline modules that own typed runtime tables use `store.conn()` and direct
   SQL. Protocol modules still use row-table helpers for opaque read-model
   rows and cannot issue arbitrary writes through core.
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
    code for fact/context storage helpers should stay materially smaller than
    the old `pipeline_storage.rs` plus duplicated callers.

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
  context wake fanout, pending time range load/delete, and projection
  context/time-wake replacement now use declared SQLite columns in their owning
  pipeline modules instead of byte-row scans in `pipeline_storage.rs`.
- Done in this branch: intent queue row encoding, decoding, and insertion live
  with the pipeline queue code in `pipeline/intent_queue.rs`, not in the
  generic fact/context storage module.
- Done in this branch: context edge reads, context matching, and scope-key
  handling use declared typed SQLite rows instead of byte-row scans.
- Done in this branch: `context_store.rs` was removed as a sink. Standing
  context row access now lives in `pipeline/context_rows.rs`; matcher assembly
  lives in `pipeline/context_matching.rs`; context wake assembly lives in
  `pipeline/context_wakes.rs`; reusable checked insert-select execution lives
  in `core::select`.
- Done in this branch: separate `context_needs` and `context_offers` storage
  was collapsed into one typed `context_edges` relation keyed by
  `(owner, direction, role, scope_key, selector)`.
- Done in this branch: `facts` stores only content-addressed fact bytes.
  Scope and local receive time live in `local_fact_admissions`, an encoded
  local-only admission fact about the actual fact. The Rust `Fact.timestamp`
  field is still compatibility debt: core storage treats it as the local
  `received_at` value for now, while protocol event timestamps belong inside
  protocol fact bytes. Removing that overload requires moving sync/range
  ordering to protocol-derived event-time indexes instead of `Fact.timestamp`.
- Done in this branch: fact insertion, local-admission insertion,
  pending-projection marking, fact purge, and fact reads use declared typed
  SQLite columns in `core::fact_store`; `pipeline_storage.rs` is gone.
- Done in this branch: context wake fanout runs inside projection commit with
  typed `INSERT OR IGNORE ... SELECT`; the `pending_context_changes` queue and
  table are gone.
- Done in this branch: time wake admission now uses the same checked
  insert-select wake shape. The scheduler supplies the current timeline range
  instead of an incoming offer.
- Done in this branch: context wakes and time wakes share `select::Select` plus
  the same checked insert-select executor.
- Done in this branch: context matchers are SQL/store backed only. The old
  `ContextMatch`, `match_new_need`, `match_new_offer`, and Rust wake fallback
  path are gone; protocol range, coverage, and wrap-source matchers share a
  small SQL-backed matcher helper.
- Done in this branch: row-mutation validation and splitting moved into
  `pipeline/effects.rs`, leaving fact storage separate from effect commit
  policy.
- Done in this branch: row writes are `RowMutation` output, not `Intent`
  values. `IntentExecution::Atomic`, `AtomicIntent`, and the atomic dispatch
  pass are gone from production code.
- Done in this branch: `core::pipeline` no longer re-exports schema constants
  or fact/context read helpers for internal use; pipeline modules import their
  own dependencies from `core::schema`, `core::fact_store`, or sibling modules.
- Done in this branch: externally materialized projected-context offers now
  wake matching facts in the same transaction that inserts the offers and
  clears completed pending projection rows.
- Done in this branch: stale worker scaffolding is gone: projection reports no
  longer carry `context_matches`, the old context-change drain name is now
  `drain_pending_projection`, handler context mode is no longer an enum with
  one variant, handler commits always consume an explicit queued intent, and
  intent validation no longer accepts an unused ignored key.
- Important lesson: local intent dispatch must preserve FIFO insertion order.
  Lexicographic key order can starve multi-daemon bootstrap and receive work.
- Done in this branch: handler routes now declare their `intent_kind`, and
  dispatch looks for the next queued row of that kind before using the handler
  as a guard. `handler.accepts()` is no longer the routing mechanism.
- Done in this branch: the old `core::wake` module was renamed to
  `core::select`. It was already a checked SELECT descriptor plus
  `INSERT OR IGNORE ... SELECT` executor, not wake-specific policy.
- Done in this branch: the explicit Rust `Schema`/`SCHEMAS` registration path
  is gone. Core, network, fact, and intent tables are all declared through
  p8sql schema sources.
- Done in this branch: the local clock is a typed core table accessed through
  direct SQL, not an opaque `TableRow`.
- Done in this branch: the generic Store selected-row API is gone. Core
  pipeline modules and protocol matchers prepare their own typed SQL instead
  of routing through `ColumnValue`/`SelectedRow` adapters.
- Done in this branch: `schema_dsl.rs` is a small line-oriented parser for the
  declaration language we actually use, not a general token parser.
- Done in this branch: the generic store surface no longer has an unused
  replace-row path. `PutRow` commits are idempotent inserts, while replacement
  is modeled explicitly as delete plus put when a protocol needs it.
- Done in this branch: the schema DSL no longer accepts an unused `i64` column
  type, and `parse_schema` returns the table declarations directly.
- Done in this branch: `core::wire` no longer has scalar fixed-layout wrapper
  structs (`U8`, `U16be`, `U32be`, `U64be`, `Bool8`) or unused crypto-size
  aliases. Callers use direct `put_*`/`take_*` helpers for primitive fields.
- Done in this branch: Store no longer reconstructs typed SQLite tables back
  into opaque key/value rows for reads. Protocol read models query typed
  columns directly, and production-dead typed row decoders were removed.
- Done in this branch: Store no longer writes typed SQLite tables through the
  opaque key/value row adapter. Opaque row helpers are limited to declared row
  tables; typed read-model writes now commit as `PipelineEffects` SQL value
  inserts/deletes against schema columns.
- Done in this branch: the protocol registry boilerplate was collapsed around
  compact declaration macros for commands, facts, projector routes, and handler
  routes. Tests now compare the runtime handler descriptor directly instead of
  parsing source text.
- Done in this branch: the documentation-only `ProtocolRegistry` metadata layer
  was deleted. Executable protocol tables (`MATCH_COMMANDS`, schema sources,
  row-mutation tables, projector routes, context matchers, and handler routes)
  are now the source of truth.
- Done in this branch: stale context matcher declaration metadata was deleted.
  Matcher registry entries now declare only role plus exact-vs-SQL kind, while
  executable SQL lives with the matcher implementation.
- Done in this branch: the remaining matcher declaration shell is gone. Exact
  context roles are a core SQL relation, and protocol registers only exact role
  names plus the real SQL-backed custom matchers.

## 1. Store All Intents In SQLite Queues

Target:

```text
durable handler work -> durable INTENTS table
restart-local handler work -> TEMP LOCAL_INTENTS table
```

The storage table determines durability. `Intent` carries only kind,
idempotence key, and payload. Producers choose durable versus local by emitting
through the durable or local effect path; the queued row format is unchanged.

Next steps:

1. Done: keep `LOCAL_INTENTS` as a TEMP row table.
2. Done: preserve FIFO claim order for local queues.
3. Done: remove the remaining `ephemeral_intents()` compatibility surface.
4. Done: collapse intent execution classes after row mutations stopped being
   encoded as intents.

## 2. Stop Modeling Row Mutations As Intents

`AtomicIntent` is not queue work. It is a deterministic row mutation that must
commit through the same effect boundary as facts and follow-up intents.

Target:

```rust
ProjectionOutput {
    needs,
    offers,
    time_wakes,
    effects: PipelineEffects,
}
```

Migration:

1. Done: introduce `RowMutation::{PutRow, DeleteRow}`.
2. Done: add `row_mutations` to the shared effect shape.
3. Done: migrate protocol projectors and tests off row intents.
4. Done: remove `IntentExecution::Atomic` and the atomic dispatch pass.
5. Done: delete `HandlerOutput`; handlers now return `PipelineEffects`
   directly, and `ProjectionOutput` embeds `PipelineEffects` for row/intents
   side effects.

## 3. Split `pipeline.rs` By Queue Responsibility

Status: done mechanically in this branch. The facade remains
`src/core/pipeline.rs`; implementation lives under `src/core/pipeline/`.

Target modules:

```text
src/core/pipeline.rs              facade / runtime entry points
src/core/pipeline/admission.rs    submit facts, bulk submit, purge
src/core/pipeline/fact_context.rs fact/context loop, due time wake admission
src/core/pipeline/projection.rs   pending_projection worker
src/core/pipeline/dispatch.rs     intent queue worker
src/core/pipeline/effects.rs      common commit helpers
```

The current split is intentionally conservative and keeps behavior unchanged.
Further cleanup should simplify module internals. `core::fact_store` owns fact
storage and fact purge helpers; context row access and matching now live with
the context/projection pipeline modules.

## 4. Process One Queue Item At A Time

The core worker shape should be:

```text
claim/read one item
load inputs
run Rust logic outside the write transaction where possible
commit effects in one transaction
return WorkStatus
```

This applies to projection, time wake, and intent dispatch. The single-threaded
scheduler can then drain queues using a clear policy loop.

## 5. Push More Fanout Into SQLite

Good candidates:

1. Pending projection order:

   ```sql
   SELECT p.owner
   FROM pending_projection p
   JOIN local_fact_admissions a ON a.fact_id = p.owner
   ORDER BY a.received_at, p.owner
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

3. Done in this branch: due time wake admission uses checked insert-selects;
   pending projection selection uses typed SQL; context wake fanout uses typed
   `INSERT OR IGNORE ... SELECT` during projection commit.

Done in this branch: core pipeline reads/writes typed runtime tables directly
with SQL. `Store` now provides connection/transaction ownership plus the
remaining protocol-facing row-table adapter.

Store cleanup note: `Store` is still large because it owns connection lifecycle,
generic row-table operations, typed-table row encoding for protocol read
models, and schema application/validation. The public Rust `Schema` path has
been removed, so the next safe split is internal only: keep `Store` as the
facade and move typed-table/schema helpers behind narrower private modules
without changing callers.

## 6. Remove `pending_context_changes`

Context wake insertion now runs during projection commit. The separate context
delta queue no longer exists.

Bias:

- Done: insert exact wakes with the same SQL select path as protocol matchers.
- Done: stop tracking context additions as scheduler work.
- Done: insert protocol matcher wakes from protocol-owned wake selects.
- Done: remove the `pending_context_changes` table and queue worker.
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
  intents,
  local_intents,
}
```

Status: done for the current output shapes. `PipelineEffects` now lives in
`core::effects`; handlers return it directly, commands carry it alongside
their typed receipt, and projection stores its row/intents side effects inside
it while keeping projection-owned context and time-wake changes separate.

## 11. Defer Parallelism

Before real parallel workers:

1. Add queue claim/lease columns.
2. Claim with transaction-local update/select semantics.
3. Keep commits idempotent.
4. Use one `Store` handle per worker with WAL enabled.

For now, target a simpler single-threaded queue scheduler.
