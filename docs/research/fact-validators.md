# Fact Authenticators

## Status and scope

A **land-first** refactor: make fact authentication a first-class per-family
layer, separate from projection. It is independent of protocol versioning — it
needs no ceiling, lens, release manifest, or trusted time — and should ship
**before** that work. The protocol-versioning plan (`protocol-versioning.md`)
builds on this layer (its `authenticate → lens → project` pipeline reuses these
authenticators unchanged), but the split is useful on its own today. Proposed;
not yet in code.

This note was originally named "fact validators." The design insight is that the
pre-projector layer should not claim full protocol validity. It proves that a
fact's bytes are canonical for a family and cryptographically authentic. The
projector still proves contextual validity: authority, relationships, deletion,
purge, retention, materialization, and normal needs/offers.

## Purpose

Today a projector does two jobs at once: it **authenticates and decodes** the
fact, and it **interprets** the fact in context. RULES already names these as
separate sections in every projector's top-of-file policy:

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
- **Encrypted carrier facts.** Connection `frame_*` and sealed handshake frames
  are containers. Their outer bytes are authenticated/opened by AEAD using
  connection or endpoint context, and opening yields inner canonical fact bytes.
  The outer carrier does not prove the inner facts' semantic validity. The inner
  facts are admitted back through the normal authenticate/project pipeline.
  Therefore a frame authenticator/opener may need connection or endpoint key
  context to open the container, but it must not validate or project the children.
  The frame projector materializes the opened children as facts and receipts.
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
or open the current fact boundary. It is not an authority proof. For example,
finding a signer public key lets the authenticator prove "these bytes were
signed by this key." The projector still proves "this key was an admitted
endpoint for this workspace and author at this point in the context graph."

Purge, deletion, retention, and all materialization effects stay projector-owned.
A purge fact may be authentic forever, but whether a target observes it, removes
rows, retracts sync sharing, or calls `purge_self` is target interpretation.

## Pipeline change

- **Today:** `core` → `RouterProjector` → `project_typed::<Codec,_>` (decode) →
  `TypedProjector::project_typed` (verify_signature + structural + context +
  materialize).
- **After:** `core` → tag route → **authenticator** (decode + id + intrinsic +
  boundary cryptographic proof, optionally parked on verifier-key or opener
  context) →
  `AuthenticatedFact<T>` → **projector**
  (`project_typed(AuthenticatedFact<T>, context)` doing context + materialize only).

This is precisely the bottom of the versioning pipeline `authenticate → lens →
project`. There is **no lens** in this landing: the projector consumes the
authenticated fact directly, at head. Lenses and the ceiling are added later,
between authenticate and project, without changing the authenticators.

## Directory and registry

- Each fact family gains `authenticate.rs`, owning the `Authenticator`. It reuses
  the family's existing `layout.rs` / `FactCodec` decoder and
  `verify_signature`.
- `project.rs` loses its STRUCTURAL section; its `project_typed` is re-typed to
  start from `AuthenticatedFact<T>` (section 2 onward).
- The registry maps `tag → authenticator` (an `AuthenticatorRoute`, parallel to
  `FactRoute`); core runs authentication before the projector, replacing the
  decode step inside `project_typed`.
- Foreign context is still read through module-owned typed helpers, never another
  module's raw layout codec — unchanged by this refactor.

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
- Each re-typed `project.rs` policy now **starts at the CONTEXT section** (its
  STRUCTURAL section moved to the authenticator) and reads as context → authority →
  materialize only: security-sensitive context named in structs / bindings (no
  positional `needs[0]`), authority branches in path-specific functions, rows via
  module-owned helpers.
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
3. Register the `AuthenticatorRoute` so core authenticates before projection.
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

- **`RULES.md`** — update "Projectors do protocol validation, not IO" and the
  *Projector Style* / *Typed Facts* sections: primary fact authentication now
  lives in `authenticate.rs`; a projector consumes an `AuthenticatedFact<T>` and
  its policy starts at the CONTEXT section (no primary STRUCTURAL /
  `verify_signature` / `decode_fact` step). Add `authenticate.rs` to the
  standard fact-family role files and add the "projectors do not parse raw
  primary bytes" boundary rule.
- **Boundary / guardrail tests** (`documentation_layout_test.rs` and the
  architecture guardrails) — enforce the new file shape (`authenticate.rs`
  present per routed family) and the no-raw-primary-bytes-in-projectors rule.
- **`protocol-versioning.md`** — its Phase 3 / Phase 4 `authenticate.rs` descriptions
  point here as the authority (already cross-referenced); keep them consistent.
- Any scope README or comment that still describes the projector-does-validation
  model.

## Success criteria (done when)

Complete — in one pass — when **all** of the following hold:

- Every routed fact family has an `authenticate.rs` whose authenticator returns
  `Authenticated(AuthenticatedFact<T>)`, `NeedsAuthentication(AuthenticationNeed)`,
  or `Invalid(AuthenticationError)` and does only decode + id-check + intrinsic
  field rules + boundary cryptographic proof plus narrow verifier/opener context
  lookup (no semantic context, authority, rows, offers, purge, IO, or clock).
- No `project.rs` decodes raw bytes, calls `FactCodec::decode_fact` /
  `verify_signature`, or checks the fact id on its primary fact; every
  `project_typed` takes an `AuthenticatedFact<T>`. The boundary guardrail
  enforces this and passes.
- Every routed fact tag has a registered `AuthenticatorRoute`; a registry
  completeness test fails if a routed tag lacks one.
- Authenticator pure-unit tests (accept canonical; reject the full malformed set:
  wrong tag / length / trailing / padding / enum, bad signature, wrong domain, id
  mismatch, out-of-range fields; park then authenticate for external verifier
  keys) exist for every family and pass; a fuzz target per authenticator exists;
  projector tests build their inputs through the real authenticator.
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

## Relationship to protocol versioning

This is the prerequisite layer — call it **Phase 0.5**, landing before any of the
versioning phases. The versioning plan's `authenticate → lens → project`
pipeline reuses these authenticators unchanged; lenses, the ceiling, the release
manifest, and trusted time come afterward and do not block this landing.
"Authenticators forever" (a versioning invariant) begins here: once a family has
an `authenticate.rs`, that authenticator is kept for every version of the family,
so old signed bytes always authenticate as historical evidence. Full contextual
validity remains the ceiling projector's job after lensing.
