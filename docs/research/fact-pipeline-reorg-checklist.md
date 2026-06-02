# Fact pipeline reorg — migration checklist

Durable, carried-over task list for the fact-family role-file reorg + staged
pipeline. Keep this updated as the source of truth so we never lose track
mid-stream. Companion design docs: `fact-validators.md`, `protocol-versioning.md`.

## Target pipeline shape

```
READ:   Fact bytes → decode → authenticate → adapt → project → effects
WRITE:  cli → command → author → encode → authenticate(self-check) → admit → (READ)
```

- `authenticate.rs` is the single definition of "valid bytes," used as the read
  pipeline's entry gate AND the write pipeline's exit self-check.
- Write self-check accepts `Authenticated | NeedsAuthentication`, rejects only
  `Invalid` (fail fast & loud at author time, before admission — otherwise a bad
  authored fact is admitted then silently purged on the projection drain). Sig IS
  checked for embedded-key families (catches encode/sign transcript drift);
  context-verifier families naturally park (NeedsAuthentication).

## Role files (strict, per family)

- `encode.rs` — typed → bytes + ALL canonical byte transcripts (signing_bytes,
  AEAD associated_data, nonce-input, plaintext-slot pad). Pure.
- `decode.rs` — bytes/Fact → typed (tag/len/padding/enum); the `FactCodec`;
  slot→text recover. No id, no signature.
- `author.rs` — pure construction from an explicit snapshot/inputs+keys. Derives
  crypto material via encode transcripts, signs/encrypts, assembles, encodes.
  **MUST NOT reference `CommandContext` / `Store` / `Runtime`.**
- `commands.rs` — intent handlers / the ONLY family file that reads the runtime;
  gathers the snapshot, calls `author`, ends with the `authenticate` self-check.
- `authenticate.rs` — decode + id + crypto verify + intrinsic → Authenticated /
  NeedsAuthentication / Invalid. Kept forever per version.
- `adapt.rs` — typed source → active semantic value; identity now (physical file
  only when non-identity / replay-projected family).
- `project.rs` — semantic value + context → effects (rows/needs/offers/wakes/
  intents/emitted facts/purge). Owns projection/retention support.
- Supporting (unchanged role): `fact.rs` (typed value + wire/schema constants),
  `rows.rs`/`queries.rs` (shared at head), `cli.rs` (only when input surface
  changes).

**Doc style (apply across the fan-out):** each file's `//!` doc says, narratively
and for a human reader, *what the file is for and does* — not defensive
"does not / must not" jargon aimed at an LLM. The "what it does NOT do" boundaries
live once in `docs/RULES.md` (it now has a `## CLI` section alongside `## Commands`).
Confirmed on `content/message` cli.rs + commands.rs; project.rs approved as-is.

## Phase 0 — Core pipeline (additive, behavior-preserving)  ✅ DONE

- [x] `Adapter` trait (`type Source; type Semantic; fn adapt`) + `IdentityAdapter<T>` in `core/projectors.rs`.
- [x] `project_adapted::<A, Ad, P>` = authenticate → adapt → project (identity-typed constraint `Source==Semantic==A::Authenticated` for now; `NeedsAuthentication`→need, `Invalid`→Err).
- [x] write self-check `authenticate_authored::<A>(fact) -> Result<(), String>` (accept Authenticated|NeedsAuthentication, reject Invalid).
- [x] kept `project_authenticated` + `AuthenticatedProjector` for un-migrated families (the 42 stay green).

## Phase 1 — Model families (strict shape; behavior-preserving; green)

Per family: create encode/decode/author/(commands)/adapt; rewire authenticate
(use decode, verify via encode transcript); update project (project_adapted +
absorb projection support); update fact.rs (schema consts); update manifest
(mod list + re-exports keep `decode_fact_payload`/`Codec`/`TYPE_*` stable);
remove layout.rs + create.rs; update cross-refs (registry/cli/tests/siblings);
wire write self-check at authoring sites.

- [x] `content/message` — canonical, DONE & behavior-preserving (44 message tests green). create.rs was a 6-role grab-bag → encode (encode_fact, signing_bytes, associated_data, deterministic_nonce, pad_plaintext) / decode (decode_fact, recover_text, Codec, decode_fact_payload) / author (MessageAuthoringSnapshot+build, validates+self-checks) / commands (send/generate/prepare-gather, ContentMessageVault) / project (retention support). `message_row_delete` → **rows.rs** (it's the keyed-delete payload builder, the counterpart of `content_message_row`→TableInsert; project emits `RowMutation::DeleteWhere`, core `commit_effects::delete_where_in_tx` executes). Manifest keeps re-exporting `decode_fact_payload`/`Codec`/`TYPE_CONTENT_MESSAGE` so siblings + connection_frame are untouched. fact.rs holds the wire/schema consts.
- [ ] `connection/connection_request` — NeedsAuthentication; create.rs=signing utils→encode; real `create()` in commands.rs→author; `connect()` stays command.
- [ ] `connection/frame_small` — carrier; create.rs `fact_from_wire`→author, `project_observed_frame`→project.
- [ ] `auth/key_wrap` — handler-authored + encrypted; encrypt-input helpers (deterministic_nonce/associated_data/wrap_info)→encode; clean author/commands split; decode is `decode_key_wrap` (manifest Codec).

## Phase 2 — Guardrails

Transition-aware updates DONE (accept new role files alongside old; layout.rs
still allowed for the 42 un-migrated families). In `poc10_intent_cleanliness_test.rs`:
- [x] `STANDARD_FAMILY_FILES` += encode/decode/author/adapt (size 10→14).
- [x] family marker `layout.rs` → `(layout.rs || decode.rs)` in the 3 classification guardrails (scope-helper, registered-modules, single-flat-shape).
- [x] route registration check uses `=> {scope}::{family}::` (contains); route **count** uses `{scope}::{family}::project::` (1 per family — the old `=> ...layout::` over/under-counted: connection families have envelope routes too).
- [x] `target_projectors_authenticate_primary_*` accepts `project_adapted::<` + `super::adapt::` + `super::authenticate::` (multi-line) OR the old `project_authenticated::<super::authenticate::`.
- [x] `target_row_layouts_do_not_emit_context_or_intents` bans `RowMutation` (the effect wrapper) instead of `TableDelete` — rows.rs builds insert AND keyed-delete payloads, project emits the RowMutation.
- [x] all 55 intent-cleanliness guardrails green.
- [x] `target_authors_do_not_read_the_runtime` — author.rs may not contain `CommandContext`/`Store`/`Runtime` (enforces author⊥commands). **Landed before the fan-out** so parallel agents can't drift.
- [x] `target_decoders_do_not_check_id_or_signatures` — decode.rs may not contain `verify_fact_id`/`verify_signature`/`ed25519_verify`/`ed25519_sign` (id/sig belong in authenticate.rs). **Landed before the fan-out.**
- Note: these substring guardrails double as narrative-doc enforcers — a defensive doc that *names* the banned type to say "does not use X" trips them, so file docs stay "what it does." RULES.md now states both boundaries (Commands section).
- [ ] (optional later) guardrail that `encode.rs` owns the transcripts.
- [ ] verify `tests/documentation_layout_test.rs` (updated by agent doc commits — re-run after model work).

**Doc-style convention is now enforced + documented:** narrative file docs (what the file does); the "does not do" boundaries live in `docs/RULES.md` (`## CLI`, `## Commands` author⊥commands + decode⊥authenticate). The numbered `// 1./2./3.` projector body markers are retired (they referenced a numbered top-level doc that is now narrative); `target_projectors_document_policy_narratives` no longer requires them.

## Phase 3 — Fan out remaining 39 families (workflow; after models reviewed)

Apply the strict shape per family, behavior-preserving, green. Known needs-care
(from the reorg sweep, run 2026-06-02):
- [ ] `auth/endpoint_shared` — extract `DEVICE_NAME_OFFSET = 138` named const before split.
- [ ] `connection/bootstrap_request` — `encode/decode_optional_addr` (SocketAddr) placement; signing transcript→encode; `validate_invite_signature`→project (it's policy, not decode).
- [ ] `sync/range_request` — `decode_fact` calls `encode_fact` to check range bounds; extract a shared `validate_range_bounds`.
- [ ] `connection/fact_receipt`, `connection/frame_bundle` — create.rs is NOT authoring (normalization / transport shim / projector delegation); redistribute to encode/project, do NOT blind-rename to author.rs.
- [ ] `auth/invite` commands.rs (835 lines) — split construction handlers vs invite-link parse/format codecs.
- [ ] 11 families have no create.rs (handler-authored): author lives in their handler/commands path.

## Phase 4 — Core route runner (versioning-era; after models blessed)

- [ ] `FactRoute` carries decoder/authenticator/adapter/projector (+ author for write).
- [ ] `RouterAuthenticator` + staged read runner (core authenticates by tag, then adapt, then project).
- [ ] core command-pipeline runner + ceiling-selected `author` dispatch (versioning §5).
- [ ] purge classifier reads the auth verdict directly; delete `durable_fact_fails_without_context` (empty-context probe) in `project_pending_facts.rs`.
- [ ] context provision: decode→adapt without re-verify; keep consumer-side (Design B) until non-identity adapters justify core-provisioned type-erased payloads (Design A).

## Phase 5 — Docs

- [ ] `fact-validators.md` / `protocol-versioning.md` — write pipeline + authenticate self-check + strict role definitions + author⊥commands guardrail.
- [ ] `src/core/pipeline/README.md` — authentication + adapt + the write pipeline as core stages.

## Sweep findings to honor (validation runs, 2026-06-02)

- Decode is pure bytes→typed in ALL 43 families (carriers included; AEAD-open is a
  projector+context op, not decode). Only `connection_request`'s VERIFY is
  context-dependent (NeedsAuthentication on `endpoint_shared`).
- Context payloads = decode→adapt, never re-verified (already today's behavior).
- Replay/ephemeral safe: replay re-runs full authenticate; ephemeral authenticate
  before use; identity adapt adds no new decode.
- encode/decode split: 40/43 clean; author: 28 clean, 11 no-create, 4 needs-care.
