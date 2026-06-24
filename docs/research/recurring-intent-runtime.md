# Recurring Intent Runtime Target

This note records a target runtime shape where core stops owning durable queue
state. The protocol owns all persistent tables, including the tables that act
as queues. Core becomes a protocol-neutral turn driver: it opens SQLite, gives
registered recurring intents the current time, and runs those intents in
declaration order. Each intent decides from SQL state and `now_ms` whether it
has work to do.

The point of the split is proof focus. If row writes are faithful, then
projector proofs can concentrate on safety: a valid fact plus trusted context
produces exactly the allowed row writes. Runtime liveness remains operational
behavior, not a theorem the projector layer tries to prove.

## Current Starting Point

Current poc-10 already has part of this shape. `Runtime::run_turn` gives
registered recurring builders a chance to enqueue local work, then drains
core-owned queues for projection, time wakes, local intents, durable intents,
incoming network rows, and outgoing network rows. Projectors are pure over one
fact plus supplied context, and they return declarative output that core
commits atomically. Handlers are the bounded stateful path and may read SQL.

The target keeps the turn discipline and the projector proof style, but changes
queue ownership. Core stops having special persisted tables for pending
projection, context matching, time wakes, and durable intents. Those become
protocol-owned rows drained by recurring intents.

## Target Model

Every queue is a protocol table with protocol meaning:

- fact admission queues
- need rows and offer rows
- need/offer match work
- time-based offer work
- durable operational work
- process-local operational work
- outgoing and incoming transport work

Core does not know which of those rows are "pending projection",
"time wakes", or "intents". Those names can remain useful protocol vocabulary,
but the persisted ownership belongs beside the protocol tables and row helpers
that understand the meaning.

Core's turn loop is therefore small:

```text
now_ms = clock()
for recurring_intent in protocol_manifest.recurring_intents:
    recurring_intent.run(db, now_ms, host_context)
```

A recurring intent may be a maintenance loop, a queue worker, or a matcher. It
may read and write arbitrary SQL through the same transaction discipline as any
other protocol-owned worker. Its idempotence and backpressure are ordinary
protocol row invariants, not core queue policy.

This does not mean every recurring intent runs on every turn. The manifest only
defines the order and gives the worker `now_ms` plus host context. The worker
decides from SQL whether it should claim work, skip because a retry window has
not elapsed, or no-op because the host does not have the required IO resource.

## Projector Output

Projector output becomes row writes. A projector does not return a separate
intent object, context object, time-wake object, or purge command to core. It
returns a batch of typed row writes for tables declared by the protocol. If
emitting an intent is needed, the projector writes a row to that intent's queue
table. If publishing context is needed, it writes offer or need rows. If a
future time should matter, it writes a time-indexed row that a recurring intent
will later inspect.

This makes projector proof stronger under one mechanical assumption: row writes
are faithful. A projector proof can say:

1. The primary fact is well formed and authenticated for the policy branch.
2. Matched context rows are trusted evidence because their producers already
   proved them before writing those rows.
3. The projector writes only rows justified by the primary fact and context.
4. The row batch is atomic.

Core row-write validation still matters, but it is generic: declared table,
declared columns, canonical value encodings, and transaction atomicity. Core
does not need to understand the semantic difference between a materialized
message row and an emitted intent row.

## Recurring Intent Classes

The following current runtime responsibilities become recurring intents:

- **projection worker**: claims one fact input row, loads the primary fact and
  attached context rows, calls the registered projector, and commits the
  projector's row writes.
- **need/offer matcher**: processes newly written need and offer rows, writes
  match rows, and queues affected owners for projection.
- **time offer worker**: compares `now_ms` with protocol time indexes and
  writes due offer or queue rows.
- **durable intent workers**: claim one durable operational row and run the
  matching stateful worker.
- **local intent workers**: claim one process-local operational row and run the
  matching stateful worker.
- **transport workers**: move opaque bytes between protocol-owned transport
  rows and host IO resources.
- **version/update workers**: inspect protocol-owned storage markers and emit
  update work when needed.

These are all the same shape to core. They are recurring intents that receive
time and host context, then decide whether they run.

## Need/Offer Matching

Need and offer matching becomes a protocol worker instead of a core commit
substage. Projectors write need rows, offer rows, and enough delta/index rows
for the matcher to process newly visible relationships incrementally. The
matcher reads those rows, records matches, and writes projection-queue rows for
the affected owners.

The important safety condition is that the matcher remains mechanical. It
matches only declared role/scope/range overlap and copies already-written offer
identity/value references into match rows. It does not decide whether an offer
proves semantic authority. The woken projector still validates the matched row
against the primary fact before materializing anything.

## Time-Based Offers

Time wakes become time-indexed protocol rows. A projector that wants future
time context writes a row that says which owner or offer should become
considerable at a timestamp. The recurring time worker receives `now_ms`,
selects due rows, and writes ordinary offer, match, or projection-queue rows.

This removes a special core time-wake admission stage. Time is just another
input to a recurring intent. Rebuild and replay do not need to replay timers as
wall-clock events; they rebuild the time-index rows, and live turns decide what
is due from the current clock.

## Safety Boundary

The safety boundary moves toward projectors and row helpers:

- Projectors prove fact validity, context validity, and justified row output.
- Row helpers prove canonical row shape and table ownership.
- Recurring intents prove queue discipline, idempotence, and bounded SQL work.
- Core proves transaction atomicity, manifest order, and faithful application
  of declared row writes.

The model deliberately does not try to prove liveness. A recurring matcher may
fall behind, a transport worker may be offline, and a time worker may run late.
Those are progress properties of the host loop and deployment. The safety claim
is narrower: whenever a worker does commit, the committed rows were justified
by the protocol proof attached to that worker.

## Consequences

- Core no longer has to expose separate effect kinds for context, time wakes,
  durable intents, local intents, or purges. They are all typed row writes.
- Projector review gets simpler because every visible consequence is a row
  write through a table-owned helper.
- Recurring workers become the only moving parts with arbitrary SQL reads and
  writes. Their proofs are queue discipline and idempotence proofs, not fact
  semantic proofs.
- Replay becomes "rebuild protocol-owned rows from retained facts and run the
  recurring workers needed for materialization" rather than a core-owned
  projection/time/intent fixpoint.
- Liveness tests stay black-box and operational. They can assert that repeated
  turns eventually deliver work, but the static proof target remains safety.

## Open Questions

- Whether fact storage itself remains a core table or moves behind a
  protocol-owned row interface. The target here only requires core to stop
  owning persisted queue state; immutable fact bytes may still be a generic
  substrate if that keeps admission and hash identity simpler.
- Whether recurring intents should run one SQL transaction each, or whether a
  worker can claim and commit multiple bounded items per turn.
- How much row-write validation core should keep once all queue tables are
  protocol owned. The minimum useful boundary is declared table/column/value
  shape plus atomic commit.
- How to represent process-local rows in the same manifest vocabulary as
  durable rows without hiding restart semantics.
- Whether need/offer matching should be one global protocol worker or multiple
  table-local workers generated from context-role declarations.

## Migration Sketch

1. Introduce protocol-owned queue tables for one narrow path while keeping the
   existing core queue as the driver.
2. Move projector output for that path to typed row writes, including emitted
   intent rows.
3. Add a recurring worker that drains the protocol-owned queue through the
   current handler/projector implementation.
4. Move need/offer matching from core commit code into a recurring matcher that
   consumes protocol-owned need/offer delta rows.
5. Replace core time-wake admission with a recurring time-offer worker that
   receives `now_ms`.
6. Collapse the core runtime turn into ordered recurring intent execution after
   all durable queue paths have protocol owners.
7. Commit the completed work on that same worktree branch before handoff or
   review.
