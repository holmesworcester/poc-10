# Fact Authenticators

## Status and scope

A **land-first** refactor: make fact authentication a first-class per-family
layer, separate from projection. It is independent of protocol versioning — it
needs no ceiling, adapter, release manifest, or trusted time — and should ship
**before** that work. The protocol-versioning plan (`protocol-versioning.md`)
builds on this layer (its `decode → authenticate → adapt → project` pipeline
reuses these authenticators unchanged), but the split is useful on its own
today.

**Status: landed through model staged routes.** Change 1: every routed fact
family has an `authenticate.rs`; projectors consume an `AuthenticatedFact` and
verify no signatures; the old `project_typed` / `TypedProjector` path is
removed; the full suite is green and behaviour is unchanged. Change 2 (the
behaviour-changing follow-on — per-fact projection isolation + purge/keep
classification) is described under *Error isolation and purge* below and also
landed. Change 3: `core::pipeline` now exposes first-class route, decode,
authenticate, adapt, project, effects, and commit contracts. Converted facts
declare `decode`, `authenticate`, `adapt`, and `project` as first-class
`FactRoute.pipeline` stages while unconverted facts keep the legacy
projector-composed route shape for fact-by-fact cutover.

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
as a projection need. In converted routes, core's staged helper runs
authentication before adaptation and projection; `NeedsAuthentication` becomes a
standing need that re-wakes the same route. In legacy composed routes, the
family projector still invokes the compatibility authentication helper until
that family is cut over. The two surfaces are distinct in ownership and meaning
even though core schedules both through standing context.

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

The staged helper is the first cutover shape. A converted per-tag `FactRoute`
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

Converted projectors call `project_staged::<Codec, Authenticator, Adapter, _>()`
for direct tests, and their registered route function also calls the same core
runner. Transitional families keep `project_authenticated`, which preserves the
existing behavior while the cutover proceeds fact by fact. Context payload facts
are loaded by core through matched needs/offers, but the consuming projector
decodes them through the owning typed helper when it needs fields. They are not
re-authenticated by the consumer path: their offer exists only because the owner
already passed its own route. Needs/offers keep matching on stable
role/scope/range coordinates while future typed helpers can adapt payload shape
to the active ceiling.

The first implementation substep built two model family shapes before the
fan-out: a signed/encrypted content family (`content/message`) and a
deterministic root auth family (`auth/workspace`). Future model candidates are
an external-verifier authentication-need family, a container frame family, and a
deterministic handler-authored sync/auth family.

### Model fact lessons

- `content/message` and `auth/workspace` are the first production staged
  routes. Each route declares `decode`, `authenticate`, `adapt`, and `project`
  labels in `FactRoute.pipeline`, and the route function calls
  `project_staged`.
- `encode.rs` owns canonical bytes and pure transcript helpers. It does not
  sign, encrypt, read context, authenticate, adapt, project, or admit.
- `decode.rs` owns byte parsing and `FactCodec`. It checks tags, lengths,
  canonical padding, and fixed slots; it does not check ids, signatures,
  verifier context, or semantic relationships.
- `authenticate.rs` owns id proof, signature proof, intrinsic single-fact
  rules, and authentication parking. In staged routes it receives the decoded
  source value and does not re-decode.
- `adapt.rs` maps authenticated source values to the active semantic shape. It
  is identity for both model facts, but the physical file and route label are
  present so future version splits have a reviewable conversion point.
- `project.rs` receives semantic values and owns unsigned scope checks, context,
  authority, rows, offers, needs, time wakes, intents, deletion, retention, and
  purge. It does not decode or authenticate primary bytes.
- `author.rs` owns pure construction from explicit inputs: assembly, signing,
  encryption, and calls to `encode.rs`. It must not reference `CommandContext`,
  `Store`, or `Runtime`.
- `commands.rs` owns runtime gathering and command receipts. It gathers the
  authoring snapshot, calls `author.rs`, runs the authenticate self-check before
  returning facts, and does not own projection rows or fact byte layout.
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
- Documentation should be readable by following the pipeline. Each converted
  family needs top-of-file docs saying what that role owns, and reviewers should
  be able to line up the route declaration with the role files.

### Write-side twin: command authoring pipeline

Creation is the messiest current boundary: CLI/command code, `create.rs`,
`layout.rs`, crypto transcript helpers, final byte encoding, submission, and
projection are often interleaved. The target write pipeline mirrors the read
pipeline:

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
metadata. `encode.rs` owns canonical bytes. Its "transcripts" are the
domain-separated byte strings that cryptography consumes — deterministic nonce
seeds, AEAD associated data, signing bytes, and final serialization. They are
not secret material and not semantic construction. An author may call
`encode.rs` transcript helpers during construction, then the final encode stage
serializes the assembled typed fact.

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
  - `encode.rs` — typed fact to canonical wire bytes, plus transcript byte
    helpers for nonce seeds, AEAD associated data, signing bytes, and final
    serialization. This is byte definition, not semantic construction.
  - `decode.rs` — canonical bytes or `Fact` to typed source value, with tag,
    length, padding, and enum checks, but no id or signature proof.
  - `author.rs` — command/context/keys to an authored typed value; encryption,
    signing, assembly, deterministic nonce use, retention checks, and
    ceiling-selected local construction live here. This replaces fact-family
    `create.rs` in the target shape; non-family intent names such as
    `create_key_wrap` may keep their established command names.
  - `authenticate.rs` — id check + fact-boundary cryptographic proof +
    intrinsic field rules, returning `Authenticated`, `NeedsAuthentication`, or
    `Invalid`. Staged authenticators receive the decoded source value; legacy
    composed authenticators may still decode internally until their route is
    cut over.
  - `adapt.rs` — typed source value to the active semantic value; identity for
    current families, non-identity for version splits.
  - `project.rs` — active semantic value plus context to rows, needs, offers,
    time wakes, intents, emitted facts, and purge.
- `project.rs` drops primary decode + signature; the projector implements
  `AuthenticatedProjector` (binds `let (fact, payload) = authenticated.into_parts()`)
  and begins at scope + context. Scope stays in the projector (interpretation).
- **Routing, as built.** `FactRoute.pipeline` records whether a route is still
  `ProjectorComposed` or has first-class `decode -> authenticate -> adapt ->
  project` stages. `content/message` and `auth/workspace` are staged model
  routes; their route functions call core `project_staged`. Existing
  unconverted families keep the old composed path so the cutover can proceed
  fact by fact without changing their behavior.
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

## Scope — complete in one pass

This is a fact-by-fact cutover with a compatibility requirement. Do not create a
third pattern: converted families use staged route metadata and role files;
unconverted families remain on the existing composed projector path until they
are migrated. The per-family order below is internal sequencing so the tree
compiles and the suite stays green at each conversion.

Per family (order: `auth` → `connection` → `content` → `sync`):

1. Move the policy's section 1 (STRUCTURAL / AUTHENTICATED +
   `verify_signature` + intrinsic field checks) into `authenticate.rs`,
   returning `Authenticated`, `NeedsAuthentication`, or `Invalid`.
2. Re-type the projector body to take an authenticated or semantic value; it now
   begins at section 2 (CONTEXT).
3. Point `Projector::project` at `project_staged::<Codec, Authenticator, Adapter, _>`
   for converted routes, or at `project_authenticated::<Authenticator, _>` for
   transitional routes, so core authenticates before projecting (see *Directory
   and registry*).
4. Add the per-family authenticator pure-unit tests and the boundary guardrail.

**Model cases first — readability checkpoint.** Before propagating the pattern
across every family, build the authenticator + re-typed projector for **a few
especially complex cases** — a signed + encrypted content fact
(`content::message`, where the signature is outside the encrypted text and text
decryption stays in projection), an authority-heavy auth fact
(`auth::endpoint_shared` or `auth::key_wrap`), and a container / frame fact
(`connection::frame_*`, whose opener may need connection context but whose child
facts authenticate separately) — and **review their readability and structure
with the maintainer.** Only after that sign-off, complete the remaining families
to the agreed template. The model cases set the readability bar and shake out the
hard shapes (encrypted payloads, authority proofs, container facts) before mass
production.

Then, in the **same** change, do the cross-cutting *Align docs and rules* work
below. Nothing here depends on the versioning work.

## Tests — all in trusted classes

- **Authenticator pure-unit, per family (the high-value set).** Over crafted
  bytes: accept the canonical fact; reject wrong tag, wrong length, trailing
  bytes, non-canonical padding, invalid enum, **bad signature or bad AEAD tag,
  wrong domain, id mismatch**, and out-of-range intrinsic fields. For any family
  whose cryptographic proof depends on external context, also prove it returns
  `NeedsAuthentication` before that context is available and authenticates only
  after the correct context is supplied. These tests cover the malformed /
  wrong-type space the CLI cannot generate.
- **Fuzz target per authenticator** (the repo's `fuzz-targets`): random or
  mutated bytes never panic and never return `Authenticated` for a
  non-canonical or forged input.
- **Projector tests start from `AuthenticatedFact<T>`** built via the **real**
  authenticator over real bytes — never hand-written — so a projector test
  cannot pass on input authentication would reject.
- **Guardrail (extends the boundary tests):** no `project.rs` imports another
  module's raw layout codec or calls `decode_fact` / `verify_signature` on its
  primary fact; authentication lives only in `authenticate.rs`.

## Align docs and rules

Part of this change — **not** a follow-up — is making every doc and rule describe
the post-refactor reality, so nothing still says "projectors parse or
authenticate their primary fact":

- **`RULES.md`** *(done)* — Projectors / *Projector Style* / *Typed Facts And
  Foreign Context* / *File Ownership* now describe the `authenticate → project`
  model: a projector consumes an `AuthenticatedFact`, starts at scope/context,
  parses no primary bytes, and verifies no signatures (primary or context);
  `authenticate.rs` is a standard fact-family role file.
- **`src/core/README.md`** *(done)* — `pipeline.rs` is the source of truth for
  route/decode/authenticate/adapt/project/effects contracts, and `projectors.rs`
  is documented only as a transitional re-export facade.
- **Boundary / guardrail tests** *(done)* — in `poc10_intent_cleanliness_test.rs`:
  `target_projectors_authenticate_primary_through_core_before_projecting`
  (delegation to `project_authenticated::<super::authenticate::_, _>` + a sibling
  `authenticate.rs` per routed family) and `target_projectors_do_not_verify_signatures`
  (no `verify_signature` in any `project.rs`); `STANDARD_FAMILY_FILES` includes
  `authenticate.rs`; the policy-narrative guardrail accepts a materialize-only
  projector.
- **`protocol-versioning.md`** *(done)* — its `authenticate.rs` references point
  here as the authority and name the staged `FactRoute` runner as the next
  versioning-prep step.
- Any scope README or comment that still describes the projector-does-validation
  model.

## Success criteria (done when)

Complete — in one pass — when **all** of the following hold:

- Every routed fact family has an `authenticate.rs` whose authenticator returns
  `Authenticated(AuthenticatedFact<T>)`, `NeedsAuthentication(AuthenticationNeed)`,
  or `Invalid(AuthenticationError)` and does only decode + id-check + intrinsic
  field rules + boundary cryptographic proof plus narrow verifier/opener context
  lookup (no semantic context, authority, rows, offers, purge, IO, or clock).
- No `project.rs` decodes raw primary bytes, checks the fact id, or calls
  `verify_signature` at all — primary *or* context (a context fact's authenticity
  is guaranteed upstream); every projector implements `AuthenticatedProjector`
  over an `AuthenticatedFact<T>`. The boundary guardrails enforce this and pass.
- Every routed fact family has an `authenticate.rs` and delegates to it via
  `project_authenticated`; a guardrail fails if a routed family lacks either.
  The next route-runner change replaces that per-projector delegation with a
  core-owned `FactRoute` that carries the authenticator, identity adapt slot, and
  projector for the tag.
- Authenticator pure-unit tests (accept canonical; reject the full malformed set:
  wrong tag / length / trailing / padding / enum, bad signature, wrong domain, id
  mismatch, out-of-range fields; park then authenticate for external verifier
  keys) exist for every family; a fuzz target per authenticator exists; projector
  tests build their inputs through the real authenticator. *(Outstanding: only
  `auth::endpoint_shared` carries the per-family authenticator unit set today,
  and the repo has no fuzz harness yet — these are the remaining follow-on tasks
  for change 1.)*
- `RULES.md`, the boundary tests, and the affected docs are aligned (above) — no
  doc or rule still says projectors parse/authenticate primary facts.
- **Readability bar met.** Every `authenticate.rs` and re-typed `project.rs` follows
  the guidelines above — numbered policy header; RULES *Documentation* /
  *Projector Style*; comments on invariants, not obvious code.
- **Model cases reviewed.** The authenticator + projector for the complex exemplars
  were built and their readability / structure **reviewed and signed off with the
  maintainer** before the remaining families were completed.
- **Behaviour is unchanged.** This is a pure refactor: primary parsing and
  authentication relocate, but the accept / reject / project outcome for every
  fact is identical. The full `cargo build` and test suite are green.

Hand-off note: this is a **single deliverable with one mid-way checkpoint** —
build the model cases, get the readability sign-off, then complete the entire
split *plus* the doc/rule alignment together, not a subset.

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
