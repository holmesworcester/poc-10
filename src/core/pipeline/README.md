# Core Pipeline

The pipeline is core's SQL-backed runtime work loop. It turns admitted facts,
standing context, due time wakes, and queued intents into committed runtime
state. The pipeline does not know protocol semantics; it owns queue mechanics,
context fanout, retry behavior, and transaction boundaries.

## Interface To Core And Protocol

The public facade is `src/core/pipeline.rs`. Runtime code calls it to:

- submit facts to `facts` and `pending_projection`.
- submit durable intents to `intents`.
- submit local intents to `local_intents`.
- admit due time wakes as pending projection work.
- drain pending projection with the registered protocol projector.
- dispatch queued intents with the registered protocol handlers.
- purge exact facts and their core-owned derived rows.

Protocol code does not call pipeline modules directly. It participates through
`Projector`, `IntentHandler`, `ProjectionOutput`, and `PipelineEffects`.
Projectors decide what facts need or offer, what rows they materialize, and
what follow-up intents to enqueue. Handlers decide what bounded stateful work to
perform. The pipeline decides when those outputs become durable.

## Read Projection Path

The direction for routed facts is a first-class staged read path:

```text
fact bytes -> decode -> authenticate -> adapt -> project -> ProjectionOutput
```

Converted routes declare those stages in `FactRoute.pipeline` as
`FactPipeline::Staged`. The core projection worker still stays
protocol-neutral: it loads the fact and context, then invokes the registered
protocol projector. The protocol router selects the tag route, runs the staged
helper, and hands the settled `ProjectionOutput` back to the same commit
boundary.

The legacy path remains for fact-by-fact cutover. Routes marked
`FactPipeline::ProjectorComposed` still call the family projector directly, and
that projector may invoke the old composed authentication helper internally.
That compatibility path should preserve existing fact behavior until a family is
split into explicit `decode.rs`, `authenticate.rs`, `adapt.rs`, and `project.rs`
roles.

## Data Flow

```text
submit_fact_to_store
  -> facts/local_fact_admissions
  -> pending_projection

drain_pending_projection
  -> load fact, standing context, matched payload facts, and due time ranges
  -> run staged route or legacy composed projector route
  -> replace context and time wakes for that owner
  -> wake newly matched dependents
  -> commit row mutations, admitted facts, purges, and intents

dispatch_queued_intent
  -> claim one durable or local intent row
  -> load handler-declared fact inputs
  -> run handler
  -> delete handled row and commit handler PipelineEffects
```

Time wakes use the same projection path. The daemon asks for a due timeline
range; `project_pending_facts` inserts matching owners into
`pending_projection`, stores the due `TimeRange`, and projection context exposes
that range without allowing projectors to read the clock.

## Invariants

- Queue consumption and output commit are atomic. A fact is not removed from
  pending projection until its replacement context and effects commit. An
  intent row is not deleted until its handler output commits.
- Retry is represented by keeping work queued. Projection failures and fatal
  handler errors abort the pass. Handler retry errors leave the intent row in
  place; local retry rows rotate to the tail.
- Durable intents win over matching local intents. When a durable intent is
  handled, the duplicate local row is removed in the same transaction.
- Context is replacement by owner. The settled `ProjectionOutput` is the
  complete standing needs/offers/time-wake set for that fact.
- Wake fanout is based on newly added context rows from the replacement delta.
  Stable unmet needs do not self-wake forever.
- Projector output may purge only the fact being projected. Cross-fact purge is
  rejected before commit.
- Row mutations are validated against the runtime allowlist before SQL writes.
- `insert_select` accepts only static, comment-free `SELECT` statements over
  declared source tables and bound parameters.

## Module Responsibilities

- `project_pending_facts.rs` owns fact admission, pending projection drain,
  time-wake admission, projection context fixpoint growth, and the projection
  commit boundary.
- `context.rs` owns persisted context edges, range-overlap matching, projection
  context assembly, and wake fanout.
- `dispatch.rs` owns intent queue claiming, handler input loading, retry
  handling, and handler-output commit.
- `commit_effects.rs` owns shared effect validation and the ordered SQL commit
  of purges, admitted facts, ephemeral facts, row mutations, and follow-up
  intents.
- `insert_select.rs` owns the narrow checked `INSERT OR IGNORE ... SELECT`
  helper used by pipeline fanout operations.

## Projection Commit Boundary

One projection commit performs this ordered unit:

```text
delete pending row
delete old context and time wakes owned by fact
insert new needs, offers, and time wakes
wake owners whose needs match newly added offers
apply PipelineEffects through commit_effects
clear due time range rows for this owner
```

Before that boundary, projector runs are calculation. The projection loop may
grow `ProjectionContext` and rerun a projector when the just-declared needs
already match stored offers. Only the settled output commits.

## Handler Commit Boundary

One handler commit performs this ordered unit:

```text
delete claimed intent row
delete shadowed local duplicate when the claimed row was durable
purge exact facts
admit emitted facts and mark them pending
insert emitted ephemeral facts
apply row mutations
record durable follow-up intents
record local follow-up intents
```

If any step fails, SQLite rolls back the whole unit. This is what makes handler
replay and process restart safe.

## What Does Not Belong Here

Do not add protocol policy, fact layout decoding, context role meaning, sync
range semantics, connection routes, command formatting, or network frame
parsing to the pipeline. The pipeline should stay a protocol-blind scheduler
and commit layer. If a change needs to know what a row or fact means, make the
change in the owning protocol scope and return the appropriate core effect.
