# Core Pipeline

The pipeline is core's fact lifecycle plus the SQL-backed runtime work loop that
commits it. It turns admitted facts, standing context, due time wakes, and
queued intents into committed runtime state. The pipeline does not know protocol
semantics; it owns route invocation, context fanout, retry behavior, and
transaction boundaries.

## Interface To Core And Protocol

The public facade and work driver is `src/core/pipeline.rs`. Runtime code calls
it to:

- submit facts to `facts` and `pending_projection`.
- submit durable intents to `intents`.
- submit local intents to `local_intents`.
- admit due time wakes as pending projection work.
- drain pending projection with the registered protocol projector.
- dispatch queued intents with the registered protocol handlers.
- purge exact facts and their core-owned derived rows.
- run command, daemon, and replay work orders through one pipeline engine.

Protocol code participates through `Projector`, `FactCodec`,
`DecodedAuthenticator`, `Adapter`, `SemanticProjector`, `IntentHandler`,
`ProjectionOutput`, and `PipelineEffects`. Fact families own the concrete stage
implementations.
Projectors decide what facts need or offer, what rows they materialize, and what
follow-up intents to enqueue. Handlers decide what bounded stateful work to
perform. The pipeline decides when those effects become durable.

## Read Projection Path

The direction for routed facts is a first-class staged read path:

```text
route -> decode -> authenticate -> adapt -> project -> effects -> commit
```

Every routed fact declares those stages in `FactRoute.pipeline` as
`FactPipeline::Staged`. The core projection worker stays protocol-neutral: it
loads the fact and context, then invokes the registered protocol projector. The
protocol router selects the tag route, core's staged helper runs
decode/authenticate/adapt/project, and the settled `ProjectionOutput` hands
context replacement plus `PipelineEffects` to the same commit boundary.

## Write Authoring Path

The write-side shape is:

```text
command -> author -> encode -> authenticate self-check -> admit -> read pipeline
```

Commands own user intent, argument parsing, local capability lookup, receipts,
and the decision to author a fact. Family `author.rs` owns construction crypto:
signing, encryption, and typed assembly. Family `encode.rs` owns canonical byte
encoding only. Before storage, the runtime may call the protocol-owned
`FactAdmissionFn`; poc-10 installs one that routes every fact tag to the same
family `Codec` and `DecodedAuthenticator` used by the read path. After
admission the fact is just queued for projection.

## Data Flow

```text
submit_fact_to_store
  -> facts/local_fact_admissions
  -> pending_projection

drain_projection_queue
  -> load fact, standing context, matched payload facts, and due time ranges
  -> run staged route and resolve already-satisfied declared needs
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
range; projection inserts matching owners into `pending_projection`, stores the
due `TimeRange`, and projection context exposes that range without allowing
projectors to read the clock.

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

- `pipeline.rs` owns `WorkStatus`, handler route metadata, handler sets, and
  `PipelineEngine`, the generic state machine that orders projection, due
  time-wake admission, and intent dispatch.
- `route.rs` owns tag route declarations, staged route metadata, and the
  optional protocol-owned fact admission hook type.
- `decode.rs` owns the decode trait core invokes at the read-stage boundary.
- `authenticate.rs` owns authentication result types, authentication traits,
  the authored-fact self-check helper, and the fact-id self-check helper.
- `adapt.rs` owns the adapter trait that converts authenticated source values to
  the semantic value projected at the active head version.
- `project.rs` owns authenticated and semantic projector traits plus the staged
  helper functions that compose decode/authenticate/adapt/project.
- `context.rs` owns the in-memory `ProjectionContext` and matched payload
  helpers visible while processing one fact.
- `effects.rs` owns `ProjectionOutput`, time wakes, and due time ranges.
- `projection.rs` owns one-item fact projection: fact admission, time-wake
  queue admission, matched-context loading, projector execution, and the
  projection commit boundary.
- `projection_queue.rs` owns pending projection draining over durable facts and
  ephemeral inputs.
- `context_store.rs` owns persisted context edges, range-overlap matching, projection
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
clear due time range rows for this owner
delete old context and time wakes owned by fact
insert new needs, offers, and time wakes
wake owners whose needs match newly added offers
apply PipelineEffects through commit_effects
```

Before that boundary, projector runs are calculation. The projection loop may
grow `ProjectionContext` for this one item and rerun the projector when the
just-declared needs already match stored offers. Only the settled output
commits.

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

Do not add protocol policy, concrete fact layout decoding, context role meaning,
sync range semantics, connection routes, command formatting, or network frame
parsing to the pipeline. The pipeline can define when decode/authenticate/adapt/
project run and what data shape each stage exchanges, but the protocol family
must own what the bytes, rows, context roles, signatures, or commands mean. If a
change needs semantic knowledge, make it in the owning protocol scope and return
the appropriate core effect.
