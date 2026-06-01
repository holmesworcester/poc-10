# Fact Authenticators

## Status and scope

A **land-first** refactor: make fact authentication a first-class per-family
layer, separate from projection. It is independent of protocol versioning — it
needs no ceiling, lens, release manifest, or trusted time — and should ship
**before** that work. The protocol-versioning plan (`protocol-versioning.md`)
builds on this layer (its `authenticate → lens → project` pipeline reuses these
authenticators unchanged), but the split is useful on its own today.

**Status: landed (changes 1 and 2).** Change 1: every routed fact family has an
`authenticate.rs`; projectors consume an `AuthenticatedFact` and verify no
signatures; the old `project_typed` / `TypedProjector` path is removed; the full
suite is green and behaviour is unchanged. Change 2 (the behaviour-changing
follow-on — per-fact projection isolation + purge/keep classification) is
described under *Error isolation and purge* below and also landed. Only the
admission-time `AuthenticatorRoute` dispatch table (authenticate-by-tag at
admission, for drop-at-ceiling) defers to the versioning admission gate.

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

But they are not separated in *code*: `core::projectors::project_typed::<Codec,_>`
decodes via the family `FactCodec`, then the `TypedProjector::project_typed` runs
`layout::verify_signature(...)`, the structural checks, **and** the context /
materialize logic in one place (see `content/message/project.rs`).

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
- It is the bottom of the eventual `authenticate → lens → project` pipeline, but
  it stands alone: the projector consumes an authenticated fact instead of raw
  bytes. Lenses and ceilings come later and do not block this.

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
  interpretation. Keeping it there (behind the lens and the ceiling projector)
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
  authenticate/project pipeline on their own. (Decode is already
  separated from projectors via `FactCodec`, so a carrier needs no opener
  relocation; `NeedsAuthentication` is for an external *verifier key*, not for a
  context-keyed AEAD open whose failure is silent.)
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
`connection::connection_request`: its endpoint signature verifies against the
*initiator's* signing key, which lives in that initiator's `endpoint_shared`, so
the authenticator parks via `NeedsAuthentication` on that `endpoint_shared`,
reads its key, and verifies the signature. Finding that key proves "these bytes
were signed by this key"; the projector still proves "this `endpoint_shared`
binds the sender and sits in a shared workspace."

As built, an authentication need is carried on the *same* standing-need channel
as a projection need (core runs the authenticator inside the projection call via
`project_authenticated`, and `NeedsAuthentication` becomes a standing need that
re-wakes the same path). The two surfaces are distinct in ownership and meaning;
a separate authentication-scheduling surface — core authenticating by tag at
*admission* — lands with the versioning admission gate, not here.

Purge, deletion, retention, and all materialization effects stay projector-owned.
A purge fact may be authentic forever, but whether a target observes it, removes
rows, retracts sync sharing, or calls `purge_self` is target interpretation.

## Pipeline change

- **Before:** `core` → `RouterProjector` → `project_typed::<Codec,_>` (decode) →
  `TypedProjector::project_typed` (verify_signature + structural + context +
  materialize). (Both `project_typed` and `TypedProjector` are now removed.)
- **After:** `core` → tag route → `Projector::project` →
  `project_authenticated::<Authenticator,_>` → **authenticator** (decode + id +
  boundary signature + intrinsic field rules, optionally parked on a verifier-key
  need) → `AuthenticatedFact<T>` → `AuthenticatedProjector::project_authenticated`
  (scope + context + materialize). `FactCodec` stays (the authenticator decodes
  through it); `verify_fact_id` is the shared id check.

This is precisely the bottom of the versioning pipeline `authenticate → lens →
project`. There is **no lens** in this landing: the projector consumes the
authenticated fact directly, at head. Lenses and the ceiling are added later,
between authenticate and project, without changing the authenticators.

## Directory and registry

- Each fact family gains `authenticate.rs`, owning the `Authenticator`. It reuses
  the family's existing `layout.rs` / `FactCodec` decoder and `verify_signature`.
- `project.rs` drops primary decode + signature; the projector implements
  `AuthenticatedProjector` (binds `let (fact, payload) = authenticated.into_parts()`)
  and begins at scope + context. Scope stays in the projector (interpretation).
- **Routing, as built.** Authentication composes *into* the projector path: the
  family's `Projector::project` delegates to
  `project_authenticated::<Authenticator,_>`, which runs the authenticator then
  the projector. There is no separate runtime `tag → authenticator` table yet;
  completeness ("every routed family has an `authenticate.rs` and delegates to
  it") is enforced by a guardrail. A standalone `AuthenticatorRoute` dispatch
  table — core authenticating by tag at *admission*, independent of projection —
  is the right home for drop-at-ceiling and lands with the versioning admission
  gate, not here.
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
  and rows go through module-owned helpers.
- The split must be legible to a maintainer asking *"where does authentication
  happen, and where does interpretation happen?"* — authenticators authenticate,
  projectors interpret and validate context; inline comments attach to
  invariants, ownership, and security conditions, and never narrate obvious code.

## Scope — complete in one pass

This is **one cohesive change covering every routed fact family** — finish it in
one go. Do **not** land a partial split (some families authenticated, others still
parsing in the projector): that leaves two contradictory patterns in the tree.
The per-family order below is **internal sequencing** so the tree compiles and
the suite stays green at each commit — not a licence to stop early.

Per family (order: `auth` → `connection` → `content` → `sync`):

1. Move the policy's section 1 (STRUCTURAL / AUTHENTICATED +
   `verify_signature` + intrinsic field checks) out of `project_typed` into
   `authenticate.rs`, returning `Authenticated`, `NeedsAuthentication`, or
   `Invalid`.
2. Re-type the projector's `project_typed` to take `AuthenticatedFact<T>`; it now
   begins at section 2 (CONTEXT).
3. Point `Projector::project` at `project_authenticated::<Authenticator, _>` so
   core authenticates before projecting (no separate route table — see *Directory
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
- **`src/core/README.md`** *(done)* — `projectors.rs` description names the
  `Authenticator` / `AuthenticatedProjector` layer.
- **Boundary / guardrail tests** *(done)* — in `poc10_intent_cleanliness_test.rs`:
  `target_projectors_authenticate_primary_through_core_before_projecting`
  (delegation to `project_authenticated::<super::authenticate::_, _>` + a sibling
  `authenticate.rs` per routed family) and `target_projectors_do_not_verify_signatures`
  (no `verify_signature` in any `project.rs`); `STANDARD_FAMILY_FILES` includes
  `authenticate.rs`; the policy-narrative guardrail accepts a materialize-only
  projector.
- **`protocol-versioning.md`** *(pending)* — its `authenticate.rs` references
  point here as the authority; reconcile when that doc next lands on `main`.
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
  `project_authenticated`; a guardrail fails if a routed family lacks either. (A
  runtime `AuthenticatorRoute` dispatch table is deferred to the versioning
  admission gate.)
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
    needs different lenses and versions to interpret an incorrect fact the same
    way, and purging would destroy the test subject.

Ephemeral inputs have no purge/keep choice: a rejected ephemeral input is simply
dropped (it is never durable). This covers a fact's own preparation; commit-time
admission of a parent's child facts stays atomic with the parent, and
authenticating those children *before* projection is the job of the versioning
admission gate and its `AuthenticatorRoute` dispatch table, where core
authenticates by tag at admission and drops beyond-ceiling bytes.

## Relationship to protocol versioning

This is the prerequisite layer — call it **Phase 0.5**, landing before any of the
versioning phases. The versioning plan's `authenticate → lens → project`
pipeline reuses these authenticators unchanged; lenses, the ceiling, the release
manifest, and trusted time come afterward and do not block this landing.
"Authenticators forever" (a versioning invariant) begins here: once a family has
an `authenticate.rs`, that authenticator is kept for every version of the family,
so old signed bytes always authenticate as historical evidence. Full contextual
validity remains the ceiling projector's job after lensing.
