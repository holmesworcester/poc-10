# DB, Schema, And SQL Ownership

The runtime should not hide SQLite behind a broad store abstraction. SQLite is
the query engine, and the module that owns a table owns the SQL for that
table's behavior.

## Current Split

- `core/schema.rs` owns core table names, schema batches, and rebuild lifecycle
  declarations.
- `core/db.rs` owns the SQLite connection, schema execution, transactions,
  trusted identifier quoting, and generic typed row mutation mechanics.
- `core/project_fact.rs` owns retained and incoming fact admission, pending
  projection queue selection, projection commit ordering, exact fact purge
  cleanup, standing context SQL, due time wake SQL, rebuild effect commit, and
  row mutation commit.
- `core/handle_intent.rs` owns durable and local intent queue SQL plus exact
  handler input fact loading.
- `core/network.rs` owns network queue SQL.
- `protocol/versioning/state_summary.rs` owns state-summary diagnostics over
  schema-declared summary tables.
- Protocol fact-family roots own projected table declarations and row builders.
- Protocol `queries.rs` modules own bounded SQL reads over projected rows.

Projectors remain pure. They do not execute SQL. They emit row mutations,
facts, intents, context, and time wakes; core commits that output atomically.

## Schema

Schema sources are declarative. They provide executable DDL plus replay
lifecycle declarations:

- `protected` tables are retained fact-storage tables that replay must not
  clear.
- `reset` tables are derived, queued, or local runtime state that replay clears
  before rebuilding.
- `summary` tables are included in state-summary digests.

Schema declarations do not own live database execution. Runtime modules that
own behavior call `Db::conn()` and `Db::write_transaction()`.

## Db

`Db` is deliberately small:

- open disk or memory databases from schema sources
- expose the SQLite connection inside the crate
- run explicit write transactions
- quote trusted table/column identifiers
- apply typed row mutations
- count declared tables

`Db` must not grow generic read helpers or queue-specific APIs. If a module
owns a table, that module writes the SQL shape it needs.

## Facts

Core fact tables are declared in `schema.rs` and acted on by the runtime
boundary that changes their lifecycle. `project_fact.rs` stores immutable fact
bytes by content id, records local admission metadata, stages incoming fact
rows, queues retained facts for projection, and purges core-owned rows keyed by
a fact id.

`facts` stores the content-addressed bytes. `local_fact_admissions` stores the
first local admission metadata needed for deterministic ordering and scope
checks. Incoming rows remain separate until their projection either retains the
fact or drops it as a one-shot input.

Fact SQL does not decode protocol payloads. Protocol meaning belongs to
fact-family projectors and query modules.

## Projection

`project_fact.rs` owns the commit boundary from fact bytes to derived state. A
projection commit may:

- clear consumed pending work
- retain or drop an incoming fact
- replace standing needs
- append offers
- queue dependents whose needs now match
- replace time wakes
- apply typed row mutations
- admit emitted facts
- record emitted intents

Projectors supply data. `project_fact.rs` supplies SQL and ordering.

## Intents

`handle_intent.rs` owns queue selection, handler context loading, and the
transaction that deletes handled work while committing handler output. Durable
intent rows are replayable; local intent rows are connection local and
disappear on restart.

## Queries

Protocol `queries.rs` modules may use full SQL against projected tables. The
rules are:

- no semantic scans of `facts`
- no unbounded result sets
- no loading broad rows and filtering in Rust
- use indexed predicates, joins, counts, `EXISTS`, `ORDER BY ... LIMIT`, and
  pages
- load fact bytes only by exact selected ids and bounded batches

SQLite is the read abstraction.

## Rebuild

Rebuild clears schema-declared reset tables and marks retained facts pending in
replay mode. That work is requested by a projection effect and then drained by
the normal bounded projection and intent workers.

Rebuild projection must not perform network IO, fire recurring live schedules,
or make wall-clock decisions. Projectors decide how their fact materializes under
`ProjectionContext::is_replay()`.

`protocol/versioning/state_summary.rs` is diagnostic. It hashes summary tables
after ordinary runtime work has drained. Whole-table summary scans stay there,
not in `db.rs`.
