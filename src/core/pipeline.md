# Core Runtime Work

The runtime work model is core's fact lifecycle plus the SQL-backed loop that
commits it. It turns durable facts, candidate facts, standing
context, scheduled fact wake-ups whose timestamps have arrived, and queued
intents into committed runtime state. Core does not know protocol semantics; it
owns route invocation, context fanout, replay mode, retry behavior, and
transaction boundaries.

## Interface To Core And Protocol

The projection contract and fact queue worker live in `src/core/project_fact.rs`;
handler routing and the intent queue worker live in `src/core/handle_intent.rs`.
`src/core/runtime.rs` composes them into bounded command, daemon, and replay
turns. Runtime code uses those workers to:

- submit durable facts to `facts`, `local_fact_admissions`, and
  `pending_projection`.
- commit command-authored facts.
- commit `PipelineEffects` from projectors and handlers.
- record candidate facts in `candidate_facts`.
- submit durable intents to `intents`.
- submit local (ephemeral, not-replayed) intents to `local_intents`.
- mark facts whose scheduled wake-up time has arrived as pending projection
  work.
- enqueue retained facts and scheduled replay wake-ups as replay projection
  work.
- drain pending projection and candidate facts with the registered
  protocol projector.
- dispatch queued intents with the registered protocol handlers.
- purge exact facts and their core-owned derived rows.
- run command, daemon, and replay work orders through one runtime facade.

Protocol code participates through `Projector`, `ProjectionOutput`,
`PipelineEffects`, `IntentHandler`, and `HandlerRoute`. Fact families own raw
body decoding, fact-boundary validation, compatibility adaptation, semantic
projection, replay-mode decisions, and any protocol-local admission checks. Core
decides when the emitted output becomes durable.

## Read Projection Path

The routed fact path is:

```text
raw fact -> tag route -> projector -> ProjectionOutput -> commit
```

The core projection worker stays protocol-neutral: it loads the fact, matched
context already attached to pending work, due time ranges, and projection mode,
then invokes the registered protocol projector. The projector decides what the
bytes mean. A typical projector locally decodes the raw body, validates the fact
id and cryptographic/container proof, requests missing context as needs,
validates matched offers when present, adapts any legacy payload shape, and
projects rows, context, time wakes, purges, or intents.

Missing context is normal projection output, not a separate core stage. The
projector emits standing needs; core records those replacement needs and parks
the fact. When a later offer matches a parked need, core records
that offer in `pending_projection_matches` for the parked owner and queues the
owner again. The retried projector reads the matched payload through
`ProjectionContext` instead of doing a database search.

Detached signature evidence, key material, deletion markers, receipts, and
other cross-fact proof are ordinary facts that may publish context offers after
their own projector accepts them. A consumer projector still validates that the
matched offer applies to the current fact before treating it as authority.
`ProjectionContext` also exposes the projection mode and due time ranges without
giving projectors a storage handle or a clock read.

## Write Authoring Path

The write-side shape is:

```text
command -> author -> encode -> protocol self-check -> AuthoredCommand facts -> admit -> projection
```

Commands own user intent, argument parsing, local capability lookup, receipts,
and the decision to author facts. They return `AuthoredCommand` facts plus a
receipt, not row mutations, purges, or intents. Family `author.rs` owns
construction crypto: signing, encryption, and typed assembly. Family `encode.rs`
owns canonical byte encoding only. Before storage, the runtime may call the
protocol-owned `FactAdmissionFn`; poc-10 installs one that dispatches by fact
tag to protocol-local decode and validation helpers. After admission each fact
is queued for projection like any other durable fact. The self-check rejects
byte, id, signature, or construction drift before local facts are emitted.

## Data Flow

```text
submit_fact_to_store
  -> facts/local_fact_admissions
  -> pending_projection(normal)

PipelineEffects.candidate_facts
  -> candidate_facts

project_fact::drain_projection
  -> load durable pending_projection rows, then candidate_facts
  -> load fact, queued matched payload facts, standing context, and due ranges
  -> run the routed projector
  -> replace needs and time wakes for that owner
  -> append new offers
  -> record matches for newly matched needs/offers and queue the matched owners
  -> wake newly matched dependents with pending_projection_matches
  -> commit purges, admitted durable facts, candidate facts, row mutations, and intents

dispatch_queued_intent
  -> claim one durable or local intent row
  -> load handler-declared fact inputs
  -> run handler
  -> delete handled row and commit handler PipelineEffects
```

Scheduled wake-ups use the same projection path. A projector can schedule its
own fact on a protocol timeline. When the daemon advances that timeline, core
marks matching fact owners in `pending_projection`, stores the due `TimeRange`,
and projection context exposes that range without allowing projectors to read
the clock.

Replay also uses the same path. Replay queues retained facts and scheduled
replay wake-ups into `pending_projection` with mode `replay`, exposes that mode
through `ProjectionContext::is_replay()`, and keeps facts emitted during replay
in replay projection mode. Projectors use replay mode to avoid live-only
projection intents. During replay dispatch, handler output is filtered unless
the matching `HandlerRoute` declares `runs_during_replay`. Recurring work is
represented as recurring intents; the live daemon's in-memory cadence is only
the scheduling mechanism that enqueues due work.

## Invariants

- Queue consumption and output commit are atomic. A fact is not removed from
  pending projection until its replacement needs, append-only offers, and
  effects commit. An intent row is not deleted until its handler output commits.
- Retry is represented by keeping work queued. Fatal handler errors and SQL
  commit failures abort the pass. Handler retry errors leave the intent row in
  place; local (ephemeral, not-replayed) retry rows rotate to the tail.
- Durable intents win over matching local (ephemeral, not-replayed) intents.
  When a durable intent is handled, the duplicate local intent row is removed
  in the same transaction.
- Projection mode is sticky toward replay. If an owner is already queued in
  replay mode, later normal wakes do not downgrade it.
- Needs are replacement subscriptions. The settled `ProjectionOutput` is the
  complete standing need set for that fact; emitting no needs marks the fact no
  longer parked on context.
- Durable offers are append-only evidence. Once a fact offers context, that
  offer remains until the fact is purged.
- Wake fanout is based on newly added context rows from the replacement delta.
  Stable unmet needs do not self-wake forever. Matching rows are written to
  `pending_projection_matches` when an owner is queued, so the pending item
  already carries the context that woke it.
- Projector output may purge only the fact being projected. Cross-fact purge is
  rejected before commit.
- Rejected durable projection items do not stall the batch. Context-free
  rejection purges the fact; context-dependent rejection keeps the fact bytes as
  evidence and clears only the pending row.
- Candidate facts start as temp rows. A projector may keep a candidate retained
  while parked on standing context needs, retain it as protocol evidence, or
  drop it. Dropped candidates cannot leave standing offers or time wakes; if
  dropped while transient needs remain, they cannot emit effects in the same
  projection.
- Row mutations are validated against the runtime allowlist before SQL writes.
- Typed-table inserts are idempotent only when the existing row matches every
  supplied column; changing typed projection state is expressed as
  `DeleteWhere` followed by `InsertValues`.

## Runtime Work Files

The active transaction bodies are split into named files so the n=1 work
boundaries stay readable.

- `runtime.rs` owns the bounded ordering for command, daemon, and replay turns:
  fact admission, scheduled wake admission, projection drains, intent dispatch,
  and replay queue seeding. It queues replay work and drains pending projection
  over durable and candidate facts.
- `project_fact.rs::route` owns tag route declarations, projector route
  metadata, and the optional protocol-owned fact admission hook type.
- `project_fact.rs::context` owns the in-memory `ProjectionContext`, matched
  payload facts, projection mode, and due time ranges visible while processing
  one fact.
- `project_fact.rs::effects` owns `ProjectionOutput`, time wakes, and due time
  ranges.
- `project_fact.rs::context_store` owns persisted context edges,
  range-overlap matching, projection context assembly from pending queue
  matches, and wake fanout.
- `project_fact.rs` owns one queued fact projection item: matched-context and due
  time-range loading, routed projector execution, durable/candidate source
  rules, rejection handling, context resolution, and the projection commit
  boundary.
- `handle_intent.rs` owns intent queue claiming, handler input loading, retry
  handling, handler route metadata, replay dispatch filtering, and
  handler-output commit.
- `commit_effects` owns shared effect validation and the ordered SQL commit
  of purges, admitted durable facts, candidate facts, row
  mutations, and follow-up intents.

## Projection Commit Boundary

For a durable fact, one projection commit performs this ordered unit:

```text
delete durable pending row
delete queued pending_projection_matches for this owner
clear due time range rows for this owner
delete old needs and time wakes owned by fact
insert new needs, append new offers, and insert new time wakes
wake owners whose needs match newly added offers and record their matched context
apply PipelineEffects through commit_effects
```

For a retained candidate fact, the commit moves the candidate into `facts` and
`local_fact_admissions`, then applies the same context/time/effect commit as a
durable fact. For a dropped candidate fact, the commit validates that no durable
offers or time wakes remain, deletes any old context for that input id, deletes
the candidate fact row, and applies `PipelineEffects` through `commit_effects`.

Before that boundary, projector runs are calculation. Durable pending items
start with the matched context already attached to their queue row. Newly
declared needs are matched during commit and wake a later queue item; the
projector does not search the store for more context during the same run.

## Handler Commit Boundary

One handler commit performs this ordered unit:

```text
delete claimed intent row
delete shadowed local (ephemeral, not-replayed) duplicate intent when the claimed row was durable
purge exact facts
admit emitted facts and mark them pending
insert emitted candidate facts
apply row mutations
record durable follow-up intents
record local (ephemeral, not-replayed) follow-up intents
```

If any step fails, SQLite rolls back the whole unit. This is what makes handler
replay and process restart safe.

## What Does Not Belong Here

Do not add protocol policy, concrete fact layout decoding, context role meaning,
sync range semantics, connection routes, command formatting, or network frame
parsing to the runtime work modules. Core can define when a raw fact is routed
to a projector and what output shape can be committed, but the protocol family
must own what the bytes, rows, context roles, signatures, or commands mean. If a
change needs semantic knowledge, make it in the owning protocol scope and return
the appropriate core effect.
