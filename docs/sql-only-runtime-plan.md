# SQL Runtime Storage Model

The runtime uses SQLite as the storage and query engine. Core persists facts as
opaque content-addressed bytes, projectors emit typed mutations for projected
tables, and protocol query modules run bounded SQL over projected tables.

## Boundaries

- `core/db.rs` owns the SQLite connection, schema execution, transactions,
  trusted identifier quoting, and generic typed row mutation mechanics.
- `core/fact_db.rs` owns retained fact rows, local fact admissions, incoming
  fact rows, fact purge cleanup, and pending-projection admission rows.
- `core/project_fact.rs` owns projection commit ordering: pending queue claim,
  context replacement, due time wakes, row mutations, emitted facts, intents,
  and queue deletion.
- `core/handle_intent.rs` owns intent queue SQL, handler dispatch, retry
  behavior, and atomic commit of handler output.
- `core/replay.rs` owns replay reset and replay-mode projection/intent driving.
- `core/replay_check.rs` owns state summaries and replay-check pass diffs.
- `core/network.rs` owns TCP and memory-local network queue SQL.
- Protocol fact-family roots own projected table names, column order, key
  columns, and typed row builders.
- Protocol `queries.rs` modules own bounded SQL reads over projected rows.

Projectors stay pure: they decode and validate one fact plus supplied context,
then return `ProjectionOutput`. They do not query SQLite.

## Db Surface

`Db` is connection plumbing, not a broad store abstraction:

- open disk or memory databases from schema sources
- expose `conn()` inside the crate for modules that own SQL
- run `write_transaction`
- apply typed table inserts/deletes for projected rows and seed data
- count declared tables
- snapshot the SQLite database for replay diagnostics

There is no generic `(row_key, row_value)` API and no generic read helper layer.
Table owners write the SQL shape they need directly.

## Query Rules

Queries may use full SQL against projected tables. The guardrails are:

- no semantic scans of `facts`
- no unbounded result sets
- no loading broad rows and filtering in Rust
- use indexed predicates, `COUNT`, `EXISTS`, `ORDER BY ... LIMIT`, joins, and
  pages
- load fact bytes only by exact selected ids and bounded batches

SQLite is the abstraction for reads.

## Replay

Replay clears schema-declared derived state, queues retained facts for
projection, and rebuilds projected state by running the normal projection and
intent commit paths in replay mode. Replay does not own protocol-specific
rebuild logic; projectors decide what their facts materialize in replay mode.

Replay-check is separate diagnostic work. It hashes declared summary tables
after replay and compares canonical, idempotent, reverse, and scrambled passes.
