# Recurring Intent Runtime Target

This note records a target runtime shape where core stops owning persisted
data. The protocol owns all persistent tables, including fact storage and the
tables that act as queues. Core becomes a protocol-neutral turn driver: it
opens SQLite, gives registered recurring intents the current time, and runs
those intents in declaration order. Each intent decides from SQL state and
`now_ms` whether it has work to do.

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
data ownership. Core stops having special persisted tables for retained facts,
local fact admissions, pending projection, context matching, time wakes, and
durable intents. Those become protocol-owned rows drained by recurring
intents.

## Target Model

Every queue is a protocol table with protocol meaning:

- fact storage and admission queues
- need rows and offer rows
- need/offer match work
- time-based offer work
- durable operational work
- process-local operational work
- outgoing and incoming transport work

Core does not know which of those rows are "pending projection",
"stored facts", "time wakes", or "intents". Those names can remain useful
protocol vocabulary, but the persisted ownership belongs beside the protocol
tables and row helpers that understand the meaning.

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

## Intent Queue Durability

Intent queues are ordinary schema declarations with a durability choice:

- **persisted queues** survive restart and rebuild. They are for durable
  operational obligations whose loss would change protocol-visible behavior.
- **volatile queues** are temp or memory-local tables. They are for host input,
  sockets, in-flight bytes, and other process observations that can disappear
  on restart.

The queue's owning module defines the table, row shape, claim order, and
idempotence key. Core only applies the schema source and gives the recurring
worker a database handle. The same recurring-intent interface drains both
persisted and volatile queues; restart semantics come from the table
declaration, not from a separate core local-intent path.

## Fact Storage As A Queue

Fact storage is also a protocol queue. A fact-storage row is not just passive
content-addressed bytes; it is the input row that makes a fact available for
projection. The owning protocol module declares the retained fact table,
admission metadata, uniqueness policy, replay/reset behavior, and the
projection queue or index rows derived from admission.

Core may still provide generic helpers for hashing canonical bytes,
transactional row writes, and table declaration validation, but it does not own
a global `facts` table or a global `local_fact_admissions` table. Storing a
fact is a typed row write to a protocol-owned fact queue. Emitting a fact from a
projector or recurring worker means writing the corresponding fact-storage row
and whatever protocol-owned queue/index rows make it eligible for later
projection.

This makes fact admission follow the same proof shape as other queue output:
the writer proves it is allowed to publish those canonical bytes, the row
helper proves the storage shape is faithful, and the recurring projection
worker later decides when to claim the row.

## Network Ingress

Network ingress should be a volatile incoming-intent row, not a core incoming
fact table. The host adapter accepts bytes from the socket and calls the
protocol-declared network-ingress enqueue function once per received frame. The
enqueue function writes a row to a volatile incoming-frame intent queue with:

- opaque frame bytes
- host `received_at_ms`
- origin observation, such as peer socket address and transport metadata

Core does not parse the bytes and does not decide whether the origin
observation is durable evidence. It only performs host IO, captures the local
observation, and admits the volatile row through the protocol's declared
ingress table helper.

A recurring incoming-frame worker drains that volatile queue. It may classify a
connection request, established frame, receipt, bundle, or unknown bytes. If
the observation needs to survive parking, replay, or later proof, the worker
must write an ordinary durable observation row or a protocol-owned fact-storage
row for an observation fact. If the process crashes before the volatile row is
handled, only the unclassified host observation is lost; durable protocol state
changes only after protocol-owned row writes commit.

The ingress path is therefore:

```text
socket frame
  -> host adapter captures received_at_ms + origin observation
  -> volatile incoming-frame intent row
  -> recurring incoming-frame worker
  -> protocol-owned fact-storage, offer, materialized, or follow-up queue rows
```

## Projector Output

Projector output becomes row writes. A projector does not return a separate
intent object, context object, time-wake object, or purge command to core. It
returns a batch of typed row writes for tables declared by the protocol. If
emitting an intent is needed, the projector writes a row to that intent's queue
table. If emitting a fact is needed, it writes the protocol-owned fact-storage
row and admission/index rows. If publishing context is needed, it writes offer
or need rows. If a future time should matter, it writes a time-indexed row that
a recurring intent will later inspect.

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

- **fact admission worker**: claims newly written fact-storage rows or admission
  deltas and writes projection-eligible queue/index rows.
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
- **incoming-frame workers**: claim one volatile network-ingress row, classify
  opaque frame bytes, and write any durable observation or fact-input rows that
  the protocol can justify.
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
  durable intents, local intents, facts, or purges. They are all typed row
  writes.
- Projector review gets simpler because every visible consequence is a row
  write through a table-owned helper.
- Recurring workers become the only moving parts with arbitrary SQL reads and
  writes. Their proofs are queue discipline and idempotence proofs, not fact
  semantic proofs.
- Inbound network bytes have explicit restart semantics: unclassified frames
  are volatile, while durable origin evidence must be promoted by protocol row
  writes.
- Replay becomes "rebuild protocol-owned derived rows from protocol-owned
  retained fact-storage rows and run the recurring workers needed for
  materialization" rather than a core-owned projection/time/intent fixpoint.
- Liveness tests stay black-box and operational. They can assert that repeated
  turns eventually deliver work, but the static proof target remains safety.

## Open Questions

- Whether recurring intents should run one SQL transaction each, or whether a
  worker can claim and commit multiple bounded items per turn.
- How much row-write validation core should keep once all queue tables are
  protocol owned. The minimum useful boundary is declared table/column/value
  shape plus atomic commit.
- Whether fact hash computation stays a core helper or becomes a protocol
  helper. The target requires protocol-owned fact storage either way.
- How to represent process-local rows in the same manifest vocabulary as
  durable rows without hiding restart semantics.
- Whether need/offer matching should be one global protocol worker or multiple
  table-local workers generated from context-role declarations.
- Whether the network host adapter should call an enqueue function that writes
  the volatile row directly, or return a typed row batch that core commits
  through the same row-write validation path as projectors.

## Migration Sketch

1. Introduce protocol-owned queue tables for one narrow path while keeping the
   existing core queue as the driver.
2. Add queue schema declarations that name persisted versus volatile queue
   tables and their claim order.
3. Move one fact family to protocol-owned fact-storage and admission rows, with
   core only applying typed row writes.
4. Route incoming network frames into a volatile incoming-frame intent queue
   with frame bytes, received time, and origin observation.
5. Move projector output for that path to typed row writes, including emitted
   fact-storage rows and emitted intent rows.
6. Add a recurring worker that drains the protocol-owned queue through the
   current handler/projector implementation.
7. Move need/offer matching from core commit code into a recurring matcher that
   consumes protocol-owned need/offer delta rows.
8. Replace core time-wake admission with a recurring time-offer worker that
   receives `now_ms`.
9. Collapse the core runtime turn into ordered recurring intent execution after
   all durable queue paths have protocol owners.
10. Commit the completed work on that same worktree branch before handoff or
   review.
