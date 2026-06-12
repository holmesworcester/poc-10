# Pipeline Simplification Plan

## Goal

Simplify the `poc-10` pipeline so `src/core/pipeline.rs` owns only durable
runtime mechanics:

- queueing projection work,
- running projectors,
- reading and writing projection state,
- recording emitted effects,
- replacing unmet needs while a fact is parked,
- recording append-only offers,
- carrying matched context on pending projection work,
- unparking facts whose needs are satisfied by new offers.

Projectors should own the meaning of facts. That means each projector should
handle raw fact decoding, signature/context validation, legacy adaptation,
semantic projection, and effect/need/offer emission.

## Current State

The worktree is `/home/holmes/poc-10`.

Recent commits already completed related groundwork:

- `4367fcf Carry projection matches on pending queue`
- `34b8aad Simplify pipeline module layout`

Already done:

- `src/core/pipeline/` was folded into `src/core/pipeline.rs`.
- `src/core/pipeline/README.md` was moved to `src/core/pipeline.md`.
- `pending_projection_matches` exists.
- Queued durable projection work now carries matched context.
- Durable offers are append-only.
- Needs are replacement-style while a fact is parked.
- Needs can be reset/removed when projection completes.
- `insert_select` was removed.

Remaining simplification:

- Remove the staged core API:
  - `FactPipeline::Staged`
  - `FactCodec`
  - `DecodedAuthenticator`
  - `Adapter`
  - `SemanticProjector`
  - `project_staged`
- Move the staged logic into each relevant projector.

## Target Model

The target flow should be:

1. Route a raw fact to the matching projector.
2. The projector decodes the fact body.
3. The projector checks whether the required context offers are present.
4. If context is missing, the projector emits needs.
5. The pipeline records those needs and parks the fact.
6. When new offers arrive, the pipeline finds parked facts with matching needs.
7. The pipeline adds matched offers to `pending_projection_matches`.
8. The pipeline queues those facts again as pending projection work.
9. The projector runs again with the matched context already attached.
10. If validation succeeds, the projector emits durable effects.
11. The pipeline commits effects, clears parked needs for completed projection,
    and records any new offers.

The pipeline should not perform a separate initial context search. Context
should be built through projector-emitted needs and offers, then carried on the
pending projection queue.

## Success Criteria

Treat the work as incomplete until every applicable success criterion below is
met or explicitly documented as intentionally deferred.

### Core Pipeline Success Criteria

- `src/core/pipeline.rs` no longer defines or exports staged processing traits
  or helpers:
  - no `FactCodec`,
  - no `DecodedAuthenticator`,
  - no `Adapter`,
  - no `SemanticProjector`,
  - no `project_staged`,
  - no `authenticate_authored` helper that combines staged decode/auth logic.
- `FactPipeline::Staged` is removed. If a route metadata type remains, it
  describes projector routing only.
- Core pipeline code does not know about decode/authenticate/adapt stage names.
- Core pipeline code invokes a projector with:
  - the raw `Fact`,
  - the projection context already attached to pending work,
  - database/runtime services needed to commit effects.
- Core pipeline code is responsible for:
  - enqueueing pending projection work,
  - loading pending projection matches,
  - passing loaded context into projectors,
  - recording effects,
  - recording replacement needs for parked facts,
  - recording append-only offers,
  - matching new offers to parked needs,
  - adding matched offers to `pending_projection_matches`,
  - requeueing facts whose needs were matched,
  - clearing needs after successful projection.
- Core pipeline code is not responsible for:
  - deciding whether a fact is semantically authenticated,
  - adapting fact versions into semantic payloads,
  - interpreting signature-checked offers beyond need/offer matching,
  - performing a pre-projection context search.

### Projector Success Criteria

- Every protocol fact that was previously wired through `project_staged` has an
  explicit `Projector::project` implementation that performs the full local
  flow.
- Each projector-local flow is readable at the call site:
  - decode raw fact body,
  - request missing context as needs,
  - validate present context offers,
  - adapt payload shape if needed,
  - project semantic meaning,
  - emit effects/offers/needs.
- New projector code contains short comments for context-dependent validation.
  Comments should explain:
  - what offer is required,
  - why the fact parks when the offer is missing,
  - what compatibility check is made when the offer is present.
- No projector hides the old staged model behind a new generic helper with a
  different name.
- Repetition is acceptable when it keeps the projector boundary obvious. Only
  extract helpers that are protocol-local and make the individual projector
  easier to read.
- Legacy version adaptation, when needed, happens in the relevant projector or
  in a helper called directly by that projector.
- A projector may use helper functions in sibling `decode.rs`, `adapt.rs`, or
  validation files, but those helpers are plain functions, not core pipeline
  stages.

### Signature Context Success Criteria

- Signature validation is represented to most projectors by a
  signature-checked context offer.
- Projectors that require a signature-checked context offer must handle all
  three cases explicitly:
  - missing offer: emit a need and return a non-error `ProjectionOutput` that
    parks the fact,
  - present compatible offer: continue projection,
  - present incompatible offer: return an error.
- The need emitted for a missing signature-checked offer must be precise enough
  that a later matching offer can be joined back to the same parked fact.
- When the matching offer arrives, pipeline code must add it to
  `pending_projection_matches` for the parked fact before requeueing projection.
- On retry, the projector should read the signature-checked offer from the
  context passed with pending work. It should not perform its own database
  search for context.
- A projector must validate that a present signature-checked offer applies to
  the current fact. The check should include the relevant author/fact/purpose
  fields used by that protocol family.
- Signature context offers should be durable context facts/offers, not replayed
  local intents.
- Local intents must be described wherever mentioned as ephemeral,
  not-replayed intents.

### Need And Offer Success Criteria

- Offers are append-only.
- Needs are replacement-style for a parked projection attempt.
- A projector may replace the current unmet needs for a parked fact by emitting
  the needs that are currently required.
- Successful projection clears the parked needs for that fact.
- Replacing needs must not withdraw durable offers.
- The docs must use "replacement needs" only in this limited sense:
  replacement of the parked fact's current unmet-needs set, not mutation of
  historical offers or completed effects.
- The matching flow is:
  - projector emits needs,
  - pipeline parks those needs,
  - later projector or runtime work emits offers,
  - pipeline matches offers to parked needs,
  - pipeline records matches on pending work,
  - pipeline reruns the projector with matched context.

### Registry And Admission Success Criteria

- The protocol registry routes facts to projectors without exposing staged
  decode/authenticate/adapt metadata.
- Admission checks, where still needed, are protocol-local.
- Admission helpers may decode and validate fact bytes, but they must not
  depend on core `FactCodec` or `DecodedAuthenticator` traits.
- Admission helpers must not make replay-only assumptions about local intents.
- Tests that inspect protocol registry metadata are updated to assert the new
  simpler model.

### Documentation Success Criteria

- `src/core/pipeline.md` describes the new model:
  - route raw facts to projectors,
  - projectors emit effects/needs/offers,
  - pipeline records effects,
  - pipeline parks unmet needs,
  - pipeline carries matched context on pending work,
  - pipeline unparks facts when offers satisfy needs.
- `src/core/pipeline.md` does not describe the active pipeline as
  `route -> decode -> authenticate -> adapt -> project`.
- Any historical discussion of the old staged model is clearly labeled as old
  context or removed.
- `src/core/README.md`, `docs/RULES.md`, tests, and research notes are updated
  so they do not contradict the new model.
- The docs explicitly clarify:
  - ephemeral projection inputs are pending-work/context inputs, not replayed
    durable facts,
  - local intents are ephemeral, not-replayed intents,
  - "due time wakes" means scheduled time-based wakeups that become pending
    projection work when their time arrives,
  - recurring work uses recurring intents and should not require a live-only
    recurring daemon schedule in replay docs unless a real live-only runtime
    behavior remains.

### Test Success Criteria

- The test suite includes realistic coverage for a context-dependent projection
  parking when a required offer is missing.
- The test suite includes realistic coverage for the same projection resuming
  after a matching offer is recorded on pending work.
- Tests verify that matched context is read from pending projection matches, not
  from an initial context search.
- Tests or guardrails verify that old staged pipeline names are removed from
  active core pipeline APIs.
- Registry tests verify projector-only routing or the chosen simplified route
  metadata.
- Documentation layout/cleanliness tests are updated to match the new doc path
  and wording.
- Run at least:
  - `cargo fmt --check`,
  - focused tests changed by the work,
  - `cargo test -q`.

### Completion Success Criteria

- `rg "FactPipeline::Staged|project_staged|FactCodec|DecodedAuthenticator|SemanticProjector|authenticate_authored" src tests docs`
  returns no active references, except any intentionally retained historical
  note that clearly says the staged model was removed.
- `rg "route -> decode -> authenticate -> adapt -> project" src docs tests`
  returns no active description of the current pipeline.
- `git status --short` shows only intentional files before committing.
- The final implementation is committed on the same `/home/holmes/poc-10`
  branch before handoff or review.

## Auth And Signature Context

Do not keep a shared core auth outcome as a pipeline concept.

Auth outcome should be projector-handled in most cases. In almost all cases,
the projector should decide that a fact is authenticated enough to project
based on the presence of a signature-checked context offer.

The intended pattern is:

- If the required signature-checked offer is missing, the projector emits a
  need and projection parks.
- If the offer is present, the projector verifies that the offer applies to
  this fact, author, and purpose, then continues.
- If the offer is present but incompatible, the projector returns an error.
- Admission may still use small protocol-local helpers where needed, but those
  helpers must not recreate a core `decode -> authenticate -> adapt -> project`
  pipeline.

Projector code should make this boundary readable and explicit. New projector
code should have short comments documenting why a fact is parked, what offer is
needed, and what validation is performed after that offer is present.

## Implementation Plan

1. Verify the starting state with `git status --short` in
   `/home/holmes/poc-10`.

2. Remove staged pipeline vocabulary from `src/core/pipeline.rs`.
   Keep only runtime mechanics that the pipeline owns: pending queues, matched
   context, need/offer parking, projector invocation, effect application, and
   commits.

3. Simplify route metadata.
   Replace `FactPipeline::Staged { decode, authenticate, adapt, project }`
   with projector-only routing, or remove the field entirely if the registry
   only needs tag-to-projector mapping.

4. Update `src/protocol/registry.rs` and `src/core/versioning.rs`.
   Registry/versioning code should route by fact tag and projector. It should
   not expose decode/authenticate/adapt as core pipeline stages.

5. Move orchestration into each `project.rs`.
   Each `Projector::project` implementation should explicitly:
   - decode the raw fact body,
   - check required context offers,
   - emit needs when context is missing,
   - validate present offers,
   - adapt legacy/current payloads where needed,
   - project semantic data,
   - emit effects, needs, and offers.

6. Convert protocol helper modules.
   - `decode.rs` should expose plain decode functions, not `FactCodec`.
   - `adapt.rs` should expose plain adapt functions, not `Adapter`.
   - `authenticate.rs` should expose projector/protocol-local validation
     helpers, not `DecodedAuthenticator`.

7. Update admission authentication.
   Replace `authenticate_authored::<Codec, Authenticator>` style calls with
   projector/protocol-local admission helpers. Admission helpers may decode and
   validate facts, but should not reintroduce the old staged model.

8. Update documentation.
   Update at least:
   - `src/core/pipeline.md`
   - `src/core/README.md`
   - `docs/RULES.md`
   - any research docs that still describe
     `route -> decode -> authenticate -> adapt -> project`

9. Update guardrail and behavior tests.
   Add or update realistic tests for:
   - simplified registry/routing metadata,
   - old staged terms not appearing where they should be removed,
   - context-dependent projection parking with needs,
   - resuming projection from matched context carried on the pending queue.

10. Run verification.
    - `cargo fmt --check`
    - focused tests touched by the change
    - `cargo test -q`

11. Commit the completed work on the same `/home/holmes/poc-10` branch before
    handoff or review.

## Readability Priorities

- Prefer explicit projector code over hidden staging machinery.
- Keep comments short and useful.
- Document context-dependent validation where it parks projection.
- Avoid introducing a new generic auth pipeline under a different name.
- Keep `src/core/pipeline.rs` focused on queueing, running, parking,
  unparking, and persistence.
