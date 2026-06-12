# Fact Authenticators

## Status and scope

A **land-first** refactor: make fact authentication a first-class per-family
layer, separate from projection. It is independent of protocol versioning — it
needs no ceiling, adapter, release manifest, or trusted time — and should ship
**before** that work. The protocol-versioning plan (`protocol-versioning.md`)
builds on this layer (its `decode → authenticate → adapt → project` pipeline
reuses these authenticators unchanged), but the split is useful on its own
today.

**Status: staged family conversion landed on main.** Every routed fact family is
registered as `FactPipeline::Staged`; each route declares `decode`,
`authenticate`, `adapt`, and `project` labels; `src/core/projectors.rs` and
`FactPipeline::ProjectorComposed` are gone. Core now exposes first-class route,
decode, authenticate, adapt, project, effects, commit, and optional fact
admission contracts. The remaining work is cleanup and hardening: keep the
guardrails green, ensure sealed/container families prove their boundary in
`authenticate.rs`, keep authored/emitted facts flowing through the runtime
admission self-check, and do not reintroduce `layout.rs`, `create.rs`, or
fact-family `rows.rs` as target shapes.

This note was originally named "fact validators." The design insight is that the
pre-projector layer should not claim full protocol validity. It proves that a
fact's bytes are canonical for a family and cryptographically authentic. The
projector still proves contextual validity: authority, relationships, deletion,
purge, retention, materialization, and normal needs/offers.

## Purpose

Before this change a projector did two jobs at once: it **authenticated and
decoded** the fact, and it **interpreted** the fact in context. RULES already
names these as separate sections in every projector's top-of-file policy:

1. **STRUCTURAL / AUTHENTICATED** — the fact is the right tag, well-formed,
   content-addressed, signed, and carries an intrinsic payload.
2. **CONTEXT** — authority and relationships proven from other facts (signer,
   author, membership, deletion, retention, secrets, time).
3. **MATERIALIZE** — read-model rows and context offers.

The current staged model separates those sections in code. `core::pipeline`
owns the call order, while the fact family owns the role files: `decode.rs`
parses bytes, `authenticate.rs` proves the fact boundary, `adapt.rs` maps the
authenticated source shape to the semantic shape, and `project.rs` proves
context and materializes effects.

This refactor splits section 1 into a first-class **authenticator**
(`authenticate.rs`) that turns raw bytes into an `AuthenticatedFact<T>`, rejects
invalid bytes, or parks on a narrow verifier-key need when the signature public
key is not present in the fact itself. It does **not** perform contextual
authority checks, semantic parking, purge, rows, normal context offers, or IO.
The projector then consumes `AuthenticatedFact<T>` and owns sections 2–3.

Why land it first:

- It makes *"are these bytes canonical and authenticated for this family?"* a
  small, reviewable layer — usually a pure function over bytes, and only
  context-waiting when a fact shape requires an external verifier key.
  Trusted `pure-unit` tests and fuzzing cover the malformed / adversarial /
  wrong-type input space the `con` CLI cannot produce (the CLI only emits
  canonical facts).
- It removes raw-byte parsing from projectors, a clean boundary a guardrail can
  enforce.
- It is the bottom of the `decode → authenticate → adapt → project` pipeline:
  the projector consumes an authenticated/adapted value instead of raw bytes.
  Non-identity adapters and ceilings can land later without changing the
  authenticator contract.

## The contract

A **fact authenticator** for a fact family is a small pre-projector component:

```text
raw fact bytes (+ tag, scope, id, optional authentication context)
  -> Authenticated(AuthenticatedFact<T>)
   | NeedsAuthentication(AuthenticationNeed)
   | Invalid(AuthenticationError)
```

An authenticator **does** (and only):

- decode the fixed layout through the family's `FactCodec` — rejecting wrong tag,
  wrong length, trailing bytes, non-canonical padding, and invalid enum values;
- return `NeedsAuthentication(AuthenticationNeed)` only when the current fact
  boundary needs narrow verifier context before it can be proven authentic;
- recompute and check the fact id against `hash(bytes)`;
- verify the fact's intrinsic cryptographic authenticity when that proof belongs
  to the primary fact boundary — usually a signature over the canonical bytes and
  domain;
- when the verifying public key is not embedded in the fact, emit only the
  narrow authentication need required to find that verifier key, then verify the
  signature when that need is satisfied;
- enforce intrinsic single-fact field rules that need **no other fact** (value
  ranges, canonical forms, internal field consistency).

An authenticator **does not**:

- check the fact's admission scope — scope is unsigned local admission metadata,
  not part of the authenticated bytes, so the scope check is projector
  interpretation. Keeping it there (behind the adapter and the ceiling projector)
  lets the workspace-id shape and the rule itself evolve;
- check semantic authority that requires other facts (signer / author /
  membership / admin / invite / endpoint proofs);
- decide whether the fact is meaningful, unpurged, undeleted, displayable, or
  projectable in the current graph;
- emit normal projector context needs/offers, rows, purge effects, intents, IO,
  or clock reads.

Its output `AuthenticatedFact<T>` is the decoded typed payload plus the source
fact id, scope, and provenance, marked authenticated (id + signature verified).
It is an **in-memory value, not a new signed fact**; it is derived from signed
bytes, not signed itself. The projector consumes `AuthenticatedFact<T>` and
never touches raw primary bytes.

The naming is deliberate. `AuthenticatedFact<T>` does not mean "valid in the
protocol graph." Full contextual validity is only knowable after projection
checks authority, related facts, deletion, purge, retention, and materialization
policy. Calling this value `ValidatedFact<T>` would overstate what the layer
proves.

## Signatures, encryption, and container facts

Not every cryptographic check belongs in the same place.

- **Signed facts with public encrypted fields.** Content messages, reactions, and
  file descriptors carry encrypted payload slots, but their signatures sit
  outside those slots and cover the canonical public envelope, including the
  ciphertext. The authenticator verifies the signature without decrypting the
  user-visible payload. Decryption of message text, reaction text, or file
  metadata remains projector/materialization work because it depends on secret
  context and produces read-model meaning.
- **Facts whose verifier key is external.** The authenticator may park on a
  narrow verifier-key need, then verify the signature once the key is present.
  That key's presence is not authority; authority stays in the projector.
  Verifier key placement is a fact-version choice: a family may embed the public
  key when self-contained verification is worth the bytes, or it may carry a
  compact key reference and rely on `NeedsAuthentication` when key material is
  found through context. Do not make embedded public keys mandatory. The need
  model keeps the authenticator interface stable across schemes with very
  different public-key sizes, including post-quantum signatures.
- **Encrypted carrier facts.** Connection `frame_*` and sealed handshake frames
  are containers. As built, their `authenticate.rs` authenticates only the
  cleartext envelope (decode + id); the AEAD open stays in the **projector**,
  because the opening key is connection/endpoint *context* and a frame that will
  not open is transport noise to drop silently, not a fact to reject as
  inauthentic. The projector opens the container with that context and
  materializes the opened inner facts plus receipts; it must not re-authenticate
  or project the children. The inner facts are admitted back through the normal
  `decode -> authenticate -> adapt -> project` pipeline on their own.
  `NeedsAuthentication` is for an external *verifier key*, not for a
  context-keyed AEAD open whose failure is silent.
- **Signatures inside encryption wrappers.** If a wire wrapper encrypts a
  canonical signed fact, the signature is "inside" the wrapper only while in
  transit. After the wrapper opens, the recovered canonical fact bytes go through
  their owning authenticator. Do not duplicate that inner authentication in the
  carrier.

The rule of thumb: authenticate the current fact boundary, but do not chase
materialization secrets or validate children. Encryption that hides user content
belongs to projection. Encryption whose only job is to recover child fact bytes
belongs to the carrier opener, and those child facts authenticate separately.

## Authentication needs and wakes

There are two wake surfaces, and they must stay distinct:

- **Authentication wake:** an authenticator parked because it needs a verifier
  public key, connection secret, endpoint secret, or equivalent cryptographic
  context for the current fact boundary. When that context appears, core wakes
  authentication/opening for that owner fact. If authentication succeeds,
  projection is scheduled.
- **Projection wake:** a projector emitted normal context needs or time wakes.
  When those match, core wakes projection for an already authenticated fact. The
  authenticator may be re-run as an implementation detail over immutable bytes,
  but the semantic wake belongs to the projector.

An authentication need proves only enough cryptographic material to authenticate
the current fact boundary. It is not an authority proof. The one current user is
`connection::request`: its endpoint signature verifies against the
*initiator's* signing key, which lives in that initiator's `endpoint_shared`, so
the authenticator parks via `NeedsAuthentication` on that `endpoint_shared`,
reads its key, and verifies the signature. Finding that key proves "these bytes
were signed by this key"; the projector still proves "this `endpoint_shared`
binds the sender and sits in a shared workspace."

As built, an authentication need is carried on the *same* standing-need channel
as a projection need. Core's staged helper runs authentication before adaptation
and projection; `NeedsAuthentication` becomes one or more standing needs that
re-wake the same route. The authentication and projection surfaces are distinct
in ownership and meaning even though core schedules both through standing
context.

Purge, deletion, retention, and all materialization effects stay projector-owned.
A purge fact may be authentic forever, but whether a target observes it, removes
rows, retracts sync sharing, or calls `purge_self` is target interpretation.

## Pipeline change

The read pipeline is now explicit in core:

```text
route -> decode -> authenticate -> adapt -> project -> effects -> commit
```

`route.rs` selects a tag route. `decode.rs` names the typed byte parser.
`authenticate.rs` proves content id, fact-boundary cryptography, and intrinsic
single-fact rules, optionally parking on a narrow authentication need.
`adapt.rs` maps authenticated source values to the semantic value projected at
the active head version. `project.rs` proves scope, context, authority,
deletion, retention, and materialization. `effects.rs` packages the replacement
context/time-wake state plus `PipelineEffects`, and the SQL workers commit it.

This is precisely the bottom of the versioning pipeline `authenticate → adapt →
project`, with decode now first-class as well. The current model adapters are
identity adapters, but their file and route labels are real so version splits
have a reviewable conversion point.

### Staged core pipeline

The staged helper is the current routed shape. A per-tag `FactRoute`
runner is:

```text
raw fact bytes
  -> decode
  -> authenticate
  -> identity adapt stub (or real adapter after a version split)
  -> project
  -> effects
  -> commit
```

Core owns the stage boundaries and the wake queues. `AuthenticationNeed` wakes
authentication; projector context needs, offers, and time wakes wake projection
for an already authenticated and adapted fact. The route is still typed inside
the protocol: the protocol route owns the concrete `T`, its `decode`,
`authenticate`, `adapt`, and `project` functions, while core sees only "tag 50
has this decoder, this authenticator, this adapt slot, and this projector."

Projectors call `project_staged::<Codec, Authenticator, Adapter, _>()` for
direct tests, and their registered route function also calls the same core
runner. Context payload facts are loaded by core through matched needs/offers,
but the consuming projector decodes them through the owning typed helper when it
needs fields. They are not re-authenticated by the consumer path: their offer
exists only because the owner already passed its own route. Needs/offers keep
matching on stable role/scope/range coordinates while future typed helpers can
adapt payload shape to the active ceiling.

The initial model families were `content/message` and `auth/workspace`. The
follow-on model lessons now include the sealed connection families:
`connection/request` and `connection/connection` authenticate by opening their
sealed bodies with narrow context needs before projection materializes rows or
intents.

### Model fact lessons

- Every production route now declares `decode`, `authenticate`, `adapt`, and
  `project` labels in `FactRoute.pipeline`, and each route function calls
  `project_staged`.
- `encode.rs` owns canonical bytes. It does not sign, encrypt, read context,
  authenticate, adapt, project, or admit.
- `decode.rs` owns byte parsing and `FactCodec`. It checks tags, lengths,
  canonical padding, and fixed slots; it does not check ids, signatures,
  verifier context, or semantic relationships.
- `authenticate.rs` owns id proof, signature proof, intrinsic single-fact
  rules, and authentication parking. In staged routes it receives the decoded
  source value and does not re-decode.
- `adapt.rs` maps authenticated source values to the active semantic shape. It
  is an identity adapt slot for both model facts, but the physical file and route
  label are present so future version splits have a reviewable conversion point.
- `project.rs` receives semantic values and owns unsigned scope checks, context,
  authority, rows, offers, needs, time wakes, intents, deletion, retention, and
  purge. It does not decode or authenticate primary bytes.
- `author.rs` owns pure construction from explicit inputs: assembly, signing,
  encryption, and calls to `encode.rs`. It must not reference `CommandContext`,
  `Store`, or `Runtime`.
- `commands.rs` owns runtime gathering and command receipts. It gathers the
  authoring snapshot, calls `author.rs`, and does not own projection rows or
  fact byte layout. The runtime admission hook can route emitted facts through
  the same staged authenticator before storage.
- Row shape is separate from fact shape. Core can learn row fields from
  protocol-owned `SchemaSource.row_schemas` declarations without hard-coding
  protocol semantics; projectors still decide when to emit rows.
- `auth/workspace` no longer has a `rows.rs`: its module root declares
  `WORKSPACE_ROW_SCHEMA`, `src/protocol/registry.rs` registers it through
  `SchemaSource.row_schemas`, `project.rs` emits `WORKSPACE_ROW_SCHEMA.row(...)`,
  and `queries.rs` decodes through the schema before applying read semantics.
- `content/message` no longer has a `rows.rs`: its materialized read models are
  typed SQL tables declared in registry `read_models`; `project.rs` owns the
  private row-mutation builders, while `queries.rs` owns result structs and read
  SQL. Typed-table rows should not detour through a per-family row file.
- The remaining sync support files are intentionally named for their role:
  `sync/shared_fact/index.rs` owns the sync contribution/negentropy index.
- Documentation should be readable by following the pipeline. Each converted
  family needs top-of-file docs saying what that role owns, and reviewers should
  be able to line up the route declaration with the role files.

### Write-side twin: command authoring pipeline

Creation is the write-side twin of the read pipeline. CLI/command code gathers
inputs, `author.rs` constructs signed/encrypted typed facts, `encode.rs`
serializes canonical bytes, runtime admission checks those bytes, and projection
interprets the admitted fact. The write pipeline mirrors the read pipeline:

```text
cli args
  -> command run fn
  -> author
  -> encode
  -> authenticate self-check
  -> admit/submit
  -> read pipeline (`decode -> authenticate -> adapt -> project`)
```

The command run fn is the runtime boundary: parse CLI input, load the needed
store/context/key snapshot, enforce blocked-mode and ceiling-selection policy,
and call the ceiling-selected author. It should not handcraft wire bytes.

`author.rs` performs local semantic construction: it signs, encrypts, assembles
the typed fact, and returns the authored value plus scope/timestamp/admission
metadata. `encode.rs` owns canonical bytes. Do not invent a separate signing
input abstraction: signatures and encryption consume canonical bytes produced by
the encoder, while the actual signing/encryption operation stays in `author.rs`.

Before a command reports success or returns a fact id, the write pipeline runs
the real family authenticator over the authored bytes. `Authenticated` admits the
fact; `Invalid` is a synchronous author/encode bug; `NeedsAuthentication` must be
resolved through the same authentication-need machinery (or reported as missing
self-check context), not silently bypassed. For embedded-key signed facts this
means re-verifying the signature just produced, which is the useful round-trip
check that `author.rs`, `encode.rs`, `decode.rs`, and `authenticate.rs` agree on
the canonical form.

## Directory and registry

- The target fact-family role files are:
  - `encode.rs` — typed fact to canonical wire bytes. This is byte definition,
    not semantic construction.
  - `decode.rs` — canonical bytes or `Fact` to typed source value, with tag,
    length, padding, and enum checks, but no id or signature proof.
  - `author.rs` — command/context/keys to an authored typed value; encryption,
    signing, assembly, deterministic nonce use, retention checks, and
    ceiling-selected local construction live here. Non-family intent names such
    as `create_key_wrap` may keep their established command names.
  - `authenticate.rs` — id check + fact-boundary cryptographic proof +
    intrinsic field rules, returning `Authenticated`, `NeedsAuthentication`, or
    `Invalid`. Staged authenticators receive the decoded source value.
  - `adapt.rs` — typed source value to the active semantic value; identity for
    current families, non-identity for version splits.
  - `project.rs` — active semantic value plus context to rows, needs, offers,
    time wakes, intents, emitted facts, and purge.
- `project.rs` drops primary decode + signature and implements
  `SemanticProjector<Semantic>`. It begins at scope + context. Scope stays in
  the projector because it is interpretation.
- **Routing, as built.** Every `FactRoute.pipeline` records first-class
  `decode -> authenticate -> adapt -> project` stages, and every route function
  calls core `project_staged`.
- Foreign context is still read through module-owned typed helpers, never another
  module's raw layout codec — and a projector **never re-verifies a context
  fact's signature**: that fact was authenticated before it could offer the
  context, so its authenticity is guaranteed. The projector decodes it for fields
  and proves relationships only.

## Readability and structure

The authenticator and the re-typed projector must be **highly readable** and follow
the project documentation guidelines (`RULES.md` — *Documentation Style*,
*Projector Style*, *In-Line Documentation*). This is a deliverable, not a nicety:
a split whose structure a reviewer cannot follow is not done.

- Each `authenticate.rs` opens with a **numbered top-of-file policy** listing, in
  order, what it checks — layout / tag, fact id, boundary cryptographic proof
  (signature/domain or container AEAD opening), optional authentication needs,
  then each intrinsic field rule — with matching `// 1.` `// 2.` markers in the
  body (the shape projectors already use). A reviewer reads the header and sees
  exactly what makes bytes authenticated.
- Each re-typed `project.rs` policy now **starts where the projector's own work
  begins** — scope, then context → authority → materialize (a minimal projector
  that only writes rows may start at materialize); its decode and signature moved
  to the authenticator. Security-sensitive context is named in structs / bindings
  (no positional `needs[0]`), authority branches live in path-specific functions,
  and row mutations go through schema-backed helpers or registry typed-table
  schemas.
- The split must be legible to a maintainer asking *"where does authentication
  happen, and where does interpretation happen?"* — authenticators authenticate,
  projectors interpret and validate context; inline comments attach to
  invariants, ownership, and security conditions, and never narrate obvious code.

## Post-conversion hardening plan

This checklist keeps the staged model review-ready. It is not complete unless
**all routed fact families stay staged, the old composed model stays removed,
and every check below passes**.

### 1. Guard the route and file shape

- Every route in `FACT_ROUTES` must remain `FactPipeline::Staged`.
- Every route function must call
  `core::pipeline::project_staged::<Codec, Authenticator, Adapter, _>()`.
- No live code may import `core::projectors`, call `project_authenticated`, or
  implement compatibility-only `Authenticator` / `AuthenticatedProjector`.
- Routed fact families must keep role files named for the pipeline:
  `encode.rs`, `decode.rs`, `authenticate.rs`, `adapt.rs`, `project.rs`, and
  `author.rs` when locally authored.
- Do not reintroduce fact-family `layout.rs`, `create.rs`, or `rows.rs`.
  Non-family support files must be named for their role, such as sync
  `index.rs` or `staging.rs`.

### 2. Keep boundaries readable

For each non-trivial family, reviewers should be able to answer this by opening
one file per role:

1. `encode.rs`: What are the canonical bytes?
2. `decode.rs`: How are bytes parsed and canonical layout rejected?
3. `authenticate.rs`: What proves id, signature/container boundary, intrinsic
   field rules, and narrow authentication needs?
4. `adapt.rs`: What source value becomes the active semantic value?
5. `project.rs`: What scope, context, authority, rows, offers, needs, time
   wakes, emitted facts, intents, deletion, retention, and purge result?
6. `author.rs` / `commands.rs`: What inputs construct facts, where do signing
   and encryption happen, and how do emitted facts reach runtime admission?

Sealed/container families must not decrypt or validate primary fact-boundary
crypto in `project.rs`. If opening is required to know what the fact is,
`authenticate.rs` parks on the needed opener context and returns the opened
authenticated semantic value.

### 3. Keep write admission centralized

The main runtime installs a protocol-owned fact admission hook. That hook routes
stored facts by tag to the same family `Codec` and `DecodedAuthenticator` used
on the read path. It must run for command output, handler output, projection
child facts, emitted ephemeral facts, replay-allowed handler output, and direct
runtime fact submission.

### 4. Required tests and checks

The final change is not review-ready until all of these pass:

- `cargo fmt`
- `cargo test -p topo core::pipeline --lib`
- `cargo test --test poc10_protocol_registry_test`
- `cargo test --test poc10_intent_cleanliness_test`
- `cargo test --test poc10_architecture_boundary_test`
- `cargo test --test documentation_layout_test`
- `cargo test --test typed_row_codecs_todo_doc_test`
- `cargo test`
- `git diff --check`

Add or update tests while converting:

- per-family authenticator pure-unit tests for canonical acceptance and the
  malformed/rejection set;
- tests for `NeedsAuthentication` families proving park-before-context and
  authenticate-after-context;
- projector tests that enter through `Projector::project` or `project_staged`
  over real authored/encoded bytes, not hand-built authenticated values;
- registry tests that assert every route is staged and declares readable
  `decode`, `authenticate`, `adapt`, and `project` labels;
- guardrails that prove no primary decode/signature/id checks remain in
  `project.rs`, no old composed route remains, and no compatibility facade is
  imported.

### 5. Final success criteria

Success means all of the following are true:

- every routed fact family is `FactPipeline::Staged`;
- every routed family has reviewable `decode.rs`, `authenticate.rs`, `adapt.rs`,
  and `project.rs` role files, plus `encode.rs` / `author.rs` where facts are
  locally authored;
- every family route calls `project_staged`;
- no routed family calls `project_authenticated`;
- no protocol code implements or imports compatibility-only `Authenticator` or
  `AuthenticatedProjector`;
- no live code imports `core::projectors`;
- `src/core/projectors.rs` is deleted;
- `FactPipeline::ProjectorComposed` is deleted;
- routed families have no transitional `layout.rs`, `create.rs`, or
  handwritten fact-family `rows.rs`;
- sync support files that are not fact-family role files are named for their
  role, currently `shared_fact/index.rs`;
- every authenticator has credible malformed-input tests, and any
  context-waiting authenticator has parking/authentication tests;
- projector tests exercise the staged path through real bytes;
- docs and guardrails describe only the staged final model;
- the complete required check suite passes.

## Per-family test expectations

Each conversion must bring its tests with it:

- authenticator pure-unit tests accept canonical bytes and reject wrong tag,
  wrong length, trailing bytes, non-canonical padding, invalid enum values, bad
  signature or bad AEAD tag, wrong domain, id mismatch, and out-of-range
  intrinsic fields;
- authenticators that depend on external verifier context prove
  `NeedsAuthentication` before that context exists and authenticate only after
  the correct context is supplied;
- projector tests enter through the staged path (`Projector::project` or
  `project_staged`) over real authored/encoded bytes so decode and
  authentication stay in the test path;
- row tests prove schema-backed row encoding/decoding where the family replaces
  handwritten row helpers;
- guardrails fail if `project.rs` imports a raw primary layout codec, calls
  primary `decode_fact`, calls `verify_fact_id`, verifies signatures, or
  materializes rows outside the staged projector/effects path.

## Documentation and guardrail alignment

Documentation alignment is part of the conversion, not follow-up cleanup:

- `RULES.md` must describe only the final staged target, with any transitional
  allowance removed once the last family is converted.
- `src/core/README.md` and `src/core/pipeline.md` must name
  `core::pipeline` as the source of truth and must not describe
  `core::projectors` as an import path.
- Scope READMEs and family top-of-file docs must let a reviewer line up each
  route's `decode`, `authenticate`, `adapt`, and `project` labels with the
  actual files.
- `poc10_intent_cleanliness_test.rs`, `poc10_protocol_registry_test.rs`,
  `poc10_architecture_boundary_test.rs`, and `documentation_layout_test.rs`
  must enforce the final state: all routes staged, no composed route, no
  compatibility facade, no primary authentication in projectors, and no
  transitional role-file names for converted families.

## Error isolation and purge (change 2)

A separate, behaviour-changing follow-on, not part of the pure refactor above.

Today a projection/authentication error for one fact poisons the whole drain: the
durable batch rolls back every other fact's projection in the transaction, and
the ephemeral path halts the loop — both propagate the error up. That is exactly
why the frame projector swallows undecryptable frames as `Ok(empty)`: to avoid
poisoning the drain. Change 2 fixes the root cause:

- **Per-fact isolation.** A fact whose projection/authentication is rejected
  during preparation drops out and the drain continues. Preparation
  (`prepare_projection_effects`) writes no rows, so isolation needs no rollback —
  core simply skips that fact's commit. Errors from the commit/load steps
  (rusqlite) still propagate, which is correct: they are infrastructure failures,
  and projectors/authenticators are pure (guardrail-enforced), so a *preparation*
  error is always a fact-level rejection, never IO.
- **Classify by re-projecting over an empty context.** To decide purge-vs-keep,
  core re-projects the rejected fact against an empty `ProjectionContext` — a
  pure, side-effect-free probe. The projector authenticates and checks scope
  before any context lookup and *parks* (emits a need, returns `Ok`) when context
  is missing, so:
  - **Fails without context** (re-project errors) → the failure is context-free
    (bad signature/id/intrinsic field, or scope), so the bytes are not admissible
    protocol data: **purge** the fact, the same way beyond-ceiling bytes are
    dropped.
  - **Otherwise** (re-project parks) → the fact authenticates and is well-formed;
    the original rejection came from inconsistent *context*. **Keep** the fact and
    clear only its pending marker so it is not retried. It is evidence: versioning
    needs different adapters and versions to interpret an incorrect fact the same
    way, and purging would destroy the test subject.

Ephemeral inputs have no purge/keep choice: a rejected ephemeral input is simply
dropped (it is never durable). This covers a fact's own preparation; commit-time
admission of a parent's child facts stays atomic with the parent, and
authenticating those children *before* projection is the job of the versioning
admission gate and its staged `FactRoute` runner, where core authenticates by
tag at admission and keeps unsupported but wire-admitted bytes pending.

## Relationship to protocol versioning

This is the prerequisite layer — call it **Phase 0.5**, landing before any of the
versioning phases. The versioning plan's `authenticate → adapt → project`
pipeline reuses these authenticators unchanged; the first route adapter is an
identity stub, and non-identity adapters, the ceiling, the release manifest, and
trusted time come afterward and do not block this landing.
"Decoders/authenticators forever" (a versioning invariant) begins here: once a
family has `decode.rs` and `authenticate.rs`, those components are kept for
every version of the family, so old signed bytes always decode and authenticate
as historical evidence. Full contextual validity remains the ceiling projector's
job after adapting.
