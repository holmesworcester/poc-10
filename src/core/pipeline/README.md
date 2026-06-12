# Core Pipeline

The pipeline is core's fact lifecycle plus the SQL-backed runtime work loop that
commits it. It turns durable facts, ephemeral projection inputs, standing
context, scheduled fact wake-ups whose timestamps have arrived, and queued
intents into committed runtime state. The pipeline does not know protocol
semantics; it owns route invocation, context fanout, replay mode, retry
behavior, and transaction boundaries.

## Interface To Core And Protocol

The public facade and work driver is `src/core/pipeline.rs`. Runtime code calls
it to:

- submit durable facts to `facts`, `local_fact_admissions`, and
  `pending_projection`.
- commit `PipelineEffects` from commands, projectors, and handlers.
- record ephemeral projection inputs in `ephemeral_projection_inputs`.
- submit durable intents to `intents`.
- submit local (ephemeral, not-replayed) intents to `local_intents`.
- mark facts whose scheduled wake-up time has arrived as pending projection
  work.
- enqueue retained facts and scheduled replay wake-ups as replay projection
  work.
- drain pending projection and ephemeral projection inputs with the registered
  protocol projector.
- dispatch queued intents with the registered protocol handlers.
- purge exact facts and their core-owned derived rows.
- run command, daemon, and replay work orders through one pipeline engine.

Protocol code participates through `Projector`, `FactCodec`,
`DecodedAuthenticator`, `Adapter`, `SemanticProjector`, `IntentHandler`,
`ProjectionOutput`, `PipelineEffects`, and `HandlerRoute`. Fact families own the
concrete stage implementations. Projectors decide what facts need or offer,
what rows they materialize, what facts or ephemeral projection inputs they emit,
and what follow-up intents to enqueue. Handlers decide what bounded stateful
work to perform. Handler routes declare whether their intents may run during
replay and whether the daemon should fire a live-only recurring intent for that
route. The pipeline decides when those effects become durable.

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

In this pipeline, `authenticate` means family-owned fact-boundary proof, not
complete semantic authority. It proves the decoded bytes are admissible as that
fact family: canonical layout, content id, and any embedded fact-boundary
signature, sealed envelope, or local cryptographic context needed before the
payload can be interpreted. Detached signature evidence is itself a fact that
authenticates independently and then offers context. Facts that depend on that
evidence check it in `project`, alongside scope, authority, parent/deletion, and
other semantic relationships.

`Authentication::NeedsAuthentication` becomes standing context needs, so the
fact can park until the required verifier, key, or envelope context appears.
`ProjectionContext` also exposes the projection mode and due time ranges without
giving projectors a storage handle or a clock read.

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
admission the fact is just queued for projection. The authored-fact self-check
accepts `NeedsAuthentication` because some valid facts require context that is
unavailable at authoring time; it rejects `Invalid` because that means
authoring, encoding, signing, or id construction drifted.

## Data Flow

```text
submit_fact_to_store
  -> facts/local_fact_admissions
  -> pending_projection(normal)

PipelineEffects.ephemeral_facts
  -> ephemeral_projection_inputs

PipelineEngine::drain_projection
  -> load durable pending_projection rows, then ephemeral_projection_inputs
  -> load fact, standing context, matched payload facts, and due time ranges
  -> run staged route and resolve already-satisfied declared needs
  -> replace context and time wakes for that owner
  -> wake newly matched dependents
  -> commit purges, admitted durable facts, ephemeral inputs, row mutations, and intents

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
through `ProjectionContext::is_replay()`, and suppresses follow-up intents
unless the matching `HandlerRoute` declares `runs_during_replay`. Recurring
intents are live-only daemon work: the daemon installs their cadence in memory
after startup, and replay never fires those recurring runs.

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
  Stable unmet needs do not self-wake forever.
- Projector output may purge only the fact being projected. Cross-fact purge is
  rejected before commit.
- Rejected durable projection items do not stall the batch. Context-free
  rejection purges the fact; context-dependent rejection keeps the fact bytes as
  evidence and clears only the pending row.
- Ephemeral projection inputs are one-shot temp rows. They may read durable
  context and emit facts, other ephemeral inputs, rows, or intents, but they
  cannot leave standing offers or time wakes; if transient needs remain, they
  cannot emit effects in the same projection.
- Row mutations are validated against the runtime allowlist before SQL writes.
- Typed-table inserts are idempotent only when the existing row matches every
  supplied column; changing typed projection state is expressed as
  `DeleteWhere` followed by `InsertValues`.
- `insert_select` accepts only static, comment-free `SELECT` statements over
  declared source tables and bound parameters.

## Module Responsibilities

- `pipeline.rs` owns `WorkStatus`, handler route metadata, handler sets, and
  `PipelineEngine`, the generic state machine that admits facts and scheduled
  wake-ups, queues replay work, drains pending projection over durable and
  ephemeral inputs, and orders intent dispatch.
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
- `pipeline_one.rs` owns one queued fact pipeline item: matched-context and due
  time-range loading, staged decode/authenticate/adapt/project execution,
  durable/ephemeral source rules, rejection handling, context resolution, and
  the projection commit boundary.
- `context_store.rs` owns persisted context edges, range-overlap matching,
  projection context assembly, and wake fanout.
- `dispatch.rs` owns intent queue claiming, handler input loading, retry
  handling, and handler-output commit.
- `commit_effects.rs` owns shared effect validation and the ordered SQL commit
  of purges, admitted durable facts, ephemeral projection inputs, row
  mutations, and follow-up intents, including replay-mode intent suppression.
- `insert_select.rs` owns the narrow checked `INSERT OR IGNORE ... SELECT`
  helper used by pipeline fanout operations.

## Projection Commit Boundary

For a durable fact, one projection commit performs this ordered unit:

```text
delete durable pending row
clear due time range rows for this owner
delete old needs and time wakes owned by fact
insert new needs, append new offers, and insert new time wakes
wake owners whose needs match newly added offers
apply PipelineEffects through commit_effects
```

For an ephemeral projection input, the commit validates that no durable offers
or time wakes remain, deletes any old context for that input id, deletes the
ephemeral input row, and applies `PipelineEffects` through `commit_effects`.
Ephemeral inputs do not write `facts` or `local_fact_admissions` for themselves.

Before that boundary, projector runs are calculation. The projection loop may
grow `ProjectionContext` for this one item and rerun the projector when the
just-declared needs already match stored offers. Only the settled output
commits.

## Handler Commit Boundary

One handler commit performs this ordered unit:

```text
delete claimed intent row
delete shadowed local (ephemeral, not-replayed) duplicate intent when the claimed row was durable
purge exact facts
admit emitted facts and mark them pending
insert emitted ephemeral facts
apply row mutations
record durable follow-up intents
record local (ephemeral, not-replayed) follow-up intents
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
