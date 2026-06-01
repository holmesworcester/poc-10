# Fact Validators

## Status and scope

A **land-first** refactor: make fact validation a first-class per-family layer,
separate from projection. It is independent of protocol versioning — it needs no
ceiling, lens, release manifest, or trusted time — and should ship **before**
that work. The protocol-versioning plan (`protocol-versioning.md`) builds on this
layer (its `validate → lens → project` pipeline reuses these validators
unchanged), but the split is useful on its own today. Proposed; not yet in code.

## Purpose

Today a projector does two jobs at once: it **authenticates and decodes** the
fact, and it **interprets** the fact in context. RULES already names these as
separate sections in every projector's top-of-file policy:

1. **STRUCTURAL** — the fact is the right tag, well-formed, signed, and carries a
   valid payload.
2. **CONTEXT** — authority and relationships proven from other facts (signer,
   author, membership, deletion, retention, secrets, time).
3. **MATERIALIZE** — read-model rows and context offers.

But they are not separated in *code*: `core::projectors::project_typed::<Codec,_>`
decodes via the family `FactCodec`, then the `TypedProjector::project_typed` runs
`layout::verify_signature(...)`, the structural checks, **and** the context /
materialize logic in one place (see `content/message/project.rs`).

This refactor splits section 1 into a first-class **validator** (`validate.rs`)
that turns raw bytes into a typed, authenticated `ValidatedFact<T>` (or an
`Invalid`), doing **no** context, authority-needing-context, parking, or IO. The
projector then consumes `ValidatedFact<T>` and owns only sections 2–3.

Why land it first:

- It makes *"is this fact authentic and well-formed?"* a **pure function over
  bytes** — provable by trusted `pure-unit` tests and fuzzing, which is exactly
  the malformed / adversarial / wrong-type input space the `con` CLI cannot
  produce (the CLI only emits canonical facts).
- It removes raw-byte parsing from projectors, a clean boundary a guardrail can
  enforce.
- It is the bottom of the eventual `validate → lens → project` pipeline, but it
  stands alone: the projector simply consumes a validated fact instead of raw
  bytes. Lenses and ceilings come later and do not block this.

## The contract

A **validator** for a fact family is a pure function:

```text
raw fact bytes (+ tag, scope, id) -> Valid(ValidatedFact<T>) | Invalid(ValidationError)
```

A validator **does** (and only):

- decode the fixed layout through the family's `FactCodec` — rejecting wrong tag,
  wrong length, trailing bytes, non-canonical padding, and invalid enum values;
- recompute and check the fact id against `hash(bytes)`;
- verify the signature over the fact's bytes and domain (the `verify_signature`
  step projectors run today);
- enforce intrinsic single-fact field rules that need **no other fact** (value
  ranges, canonical forms, internal field consistency).

A validator **does not**:

- read or match context, or look at any other fact;
- check authority that requires other facts (signer / author / membership /
  admin / invite / endpoint proofs);
- park, purge, mutate rows, emit needs / offers / intents, perform IO, or read
  the clock.

Its output `ValidatedFact<T>` is the decoded typed payload plus the fact id,
marked authenticated (id + signature verified). It is an **in-memory value, not
a new signed fact**; it carries provenance (the source fact id), because it is
derived from signed bytes, not signed itself. The projector consumes
`ValidatedFact<T>` and never touches raw bytes.

## Pipeline change

- **Today:** `core` → `RouterProjector` → `project_typed::<Codec,_>` (decode) →
  `TypedProjector::project_typed` (verify_signature + structural + context +
  materialize).
- **After:** `core` → tag route → **validator** (decode + id + signature +
  intrinsic) → `ValidatedFact<T>` → **projector**
  (`project_typed(ValidatedFact<T>, context)` doing context + materialize only).

This is precisely the bottom of the versioning pipeline `validate → lens →
project`. There is **no lens** in this landing: the projector consumes the
validated fact directly, at head. Lenses and the ceiling are added later, between
validate and project, without changing the validators.

## Directory and registry

- Each fact family gains `validate.rs`, owning the `Validator`. It reuses the
  family's existing `layout.rs` / `FactCodec` decoder and `verify_signature`.
- `project.rs` loses its STRUCTURAL section; its `project_typed` is re-typed to
  start from `ValidatedFact<T>` (section 2 onward).
- The registry maps `tag → validator` (a `ValidatorRoute`, parallel to
  `FactRoute`); core runs the validator before the projector, replacing the
  decode step inside `project_typed`.
- Foreign context is still read through module-owned typed helpers, never another
  module's raw layout codec — unchanged by this refactor.

## Scope — complete in one pass

This is **one cohesive change covering every routed fact family** — finish it in
one go. Do **not** land a partial split (some families validated, others still
parsing in the projector): that leaves two contradictory patterns in the tree.
The per-family order below is **internal sequencing** so the tree compiles and
the suite stays green at each commit — not a licence to stop early.

Per family (order: `auth` → `connection` → `content` → `sync`):

1. Move the policy's section 1 (STRUCTURAL + `verify_signature` + intrinsic field
   checks) out of `project_typed` into `validate.rs`, returning `Valid` /
   `Invalid`.
2. Re-type the projector's `project_typed` to take `ValidatedFact<T>`; it now
   begins at section 2 (CONTEXT).
3. Register the `ValidatorRoute` so core runs the validator before projection.
4. Add the per-family validator pure-unit tests and the boundary guardrail.

Then, in the **same** change, do the cross-cutting *Align docs and rules* work
below. Nothing here depends on the versioning work.

## Tests — all in trusted classes

- **Validator pure-unit, per family (the high-value set).** Over crafted bytes:
  accept the canonical fact; reject wrong tag, wrong length, trailing bytes,
  non-canonical padding, invalid enum, **bad signature, wrong domain, id
  mismatch**, and out-of-range intrinsic fields. Pure functions over bytes —
  trustworthy without the binary, and covering the malformed / wrong-type space
  the CLI cannot generate.
- **Fuzz target per validator** (the repo's `fuzz-targets`): random or mutated
  bytes never panic and never return `Valid` for a non-canonical or forged input.
- **Projector tests start from `ValidatedFact<T>`** built via the **real**
  validator over real bytes — never hand-written — so a projector test cannot
  pass on input a validator would reject.
- **Guardrail (extends the boundary tests):** no `project.rs` imports another
  module's raw layout codec or calls `decode_fact` / `verify_signature` on its
  primary fact; validation lives only in `validate.rs`.

## Align docs and rules

Part of this change — **not** a follow-up — is making every doc and rule describe
the post-refactor reality, so nothing still says "projectors validate":

- **`RULES.md`** — update "Projectors do protocol validation, not IO" and the
  *Projector Style* / *Typed Facts* sections: validation now lives in
  `validate.rs`; a projector consumes a `ValidatedFact<T>` and its policy starts
  at the CONTEXT section (no STRUCTURAL / `verify_signature` / `decode_fact`
  step). Add `validate.rs` to the standard fact-family role files and add the
  "projectors do not parse raw bytes" boundary rule.
- **Boundary / guardrail tests** (`documentation_layout_test.rs` and the
  architecture guardrails) — enforce the new file shape (`validate.rs` present
  per routed family) and the no-raw-bytes-in-projectors rule.
- **`protocol-versioning.md`** — its Phase 3 / Phase 4 `validate.rs` descriptions
  point here as the authority (already cross-referenced); keep them consistent.
- Any scope README or comment that still describes the projector-does-validation
  model.

## Success criteria (done when)

Complete — in one pass — when **all** of the following hold:

- Every routed fact family has a `validate.rs` whose validator returns
  `Valid(ValidatedFact<T>) | Invalid(ValidationError)` and does only decode +
  id-check + signature/domain + intrinsic field rules (no context, authority,
  parking, IO, or clock).
- No `project.rs` decodes raw bytes, calls `FactCodec::decode_fact` /
  `verify_signature`, or checks the fact id on its primary fact; every
  `project_typed` takes a `ValidatedFact<T>`. The boundary guardrail enforces this
  and passes.
- Every routed fact tag has a registered `ValidatorRoute`; a registry
  completeness test fails if a routed tag lacks one.
- Validator pure-unit tests (accept canonical; reject the full malformed set:
  wrong tag / length / trailing / padding / enum, bad signature, wrong domain, id
  mismatch, out-of-range fields) exist for every family and pass; a fuzz target
  per validator exists; projector tests build their inputs through the real
  validator.
- `RULES.md`, the boundary tests, and the affected docs are aligned (above) — no
  doc or rule still says projectors validate.
- **Behaviour is unchanged.** This is a pure refactor: validation relocates, but
  the accept / reject / project outcome for every fact is identical. The full
  `cargo build` and test suite are green.

Hand-off note: this is a **single deliverable**. An agent assigned it should land
the entire split *plus* the doc/rule alignment together, not a subset.

## Relationship to protocol versioning

This is the prerequisite layer — call it **Phase 0.5**, landing before any of the
versioning phases. The versioning plan's `validate → lens → project` pipeline
reuses these validators unchanged; lenses, the ceiling, the release manifest, and
trusted time come afterward and do not block this landing. "Validators forever"
(a versioning invariant) begins here: once a family has a `validate.rs`, that
validator is kept for every version of the family, so old signed bytes always
authenticate as historical evidence.
