# Fact pipeline reorg — migration checklist

Durable, carried-over task list for the fact-family role-file reorg + staged
pipeline. Keep this updated as the source of truth so we never lose track
mid-stream. Companion design docs: `fact-validators.md`, `protocol-versioning.md`.

## Target pipeline shape

```
READ:   Fact bytes → decode → authenticate → adapt → project → effects
WRITE:  cli → command → author → encode → authenticate(self-check) → admit → (READ)
```

- Core owns the stage boundaries. Protocol/family code declares the typed
  functions for each stage, and the core route/write runners call them in order.
  Projectors must not hide primary decode/authentication/adaptation behind
  `project_authenticated` or `project_adapted` once the staged runner lands.
- `authenticate.rs` is the single definition of "valid bytes," used as the read
  pipeline's entry gate AND the write pipeline's exit self-check.
- Write self-check accepts `Authenticated | NeedsAuthentication`, rejects only
  `Invalid` (fail fast & loud at author time, before admission — otherwise a bad
  authored fact is admitted then silently purged on the projection drain). Sig IS
  checked for embedded-key families (catches encode/sign transcript drift);
  context-verifier families naturally park (NeedsAuthentication).
- Row materialization is downstream of projection. Projectors decide when to
  emit rows, but row shape is declared schema metadata and exposed through
  generated helpers, not handwritten per-family byte packing.

## Role files (strict, per family)

- `encode.rs` — typed → canonical fact bytes. Layout only unless a transcript
  helper cannot yet be expressed by shared core/schema transcript machinery.
  When transcript helpers remain here temporarily, they are pure byte builders
  called by both `author.rs` and `authenticate.rs`; they do not sign, encrypt,
  read context, or admit facts.
- `decode.rs` — bytes/Fact → typed source value (tag/len/padding/enum); the
  `FactCodec`; slot→text recover. No id, no signature, no verifier lookup, no
  semantic context.
- `author.rs` — pure construction from an explicit snapshot/inputs+keys. Derives
  crypto material via shared transcript helpers, signs/encrypts, assembles, and
  calls encode. It owns creation policy, not runtime gathering.
  **MUST NOT reference `CommandContext` / `Store` / `Runtime`.**
- `commands.rs` — intent handlers / the ONLY family file that reads the runtime;
  gathers the snapshot, calls `author`, ends with the `authenticate` self-check.
- `authenticate.rs` — decode + id + crypto verify + intrinsic → Authenticated /
  NeedsAuthentication / Invalid. Kept forever per version. In the staged
  runner, `authenticate.rs` receives the decoded source value and does not
  re-decode.
- `adapt.rs` — authenticated source value → active semantic value; identity now
  (physical file only when non-identity / replay-projected family). No raw
  bytes, context, authority, parking, rows, or IO.
- `project.rs` — semantic value + context → effects (rows/needs/offers/wakes/
  intents/emitted facts/purge). Owns scope, context, authority, relationships,
  materialization, retention, deletion, and purge. No primary decode,
  authentication, or adaptation.
- Supporting (unchanged role): `fact.rs` (typed value + wire/schema constants),
  `queries.rs` (shared at head), `cli.rs` (only when input surface changes).
  Handwritten `rows.rs` is transitional: the target is schema-declared row
  tables with generated constructors, decoders, key-prefix helpers, and delete
  selectors.

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
- [x] optional staged read runner (`project_staged::<Codec, Authenticator, Adapter, Projector>`) and
  `FactRoute.pipeline` metadata. Converted families can expose decode/authenticate/adapt/project
  as first-class route stages while unconverted families stay projector-composed.
- [x] optional schema-backed opaque row declarations on `SchemaSource`. Store allowlists row tables
  declared by `row_schemas`, and `core::row_schema` provides named-field encode/decode helpers for
  generated row constructors.

## Phase 1 — Model families (strict shape; behavior-preserving; green)

Per family: create encode/decode/author/(commands)/adapt; rewire authenticate
(use decode, verify via encode transcript); update project (project_adapted +
absorb projection support); update fact.rs (schema consts); update manifest
(mod list + re-exports keep `decode_fact_payload`/`Codec`/`TYPE_*` stable);
remove layout.rs + create.rs; update cross-refs (registry/cli/tests/siblings);
wire write self-check at authoring sites.

- [x] `content/message` — canonical, DONE & behavior-preserving (44 message tests green). create.rs was a 6-role grab-bag → encode (encode_fact, signing_bytes, associated_data, deterministic_nonce, pad_plaintext) / decode (decode_fact, recover_text, Codec, decode_fact_payload) / author (MessageAuthoringSnapshot+build, validates+self-checks) / commands (send/generate/prepare-gather, ContentMessageVault) / project (retention support). `message_row_delete` → **rows.rs** (it's the keyed-delete payload builder, the counterpart of `content_message_row`→TableInsert; project emits `RowMutation::DeleteWhere`, core `commit_effects::delete_where_in_tx` executes). Manifest keeps re-exporting `decode_fact_payload`/`Codec`/`TYPE_CONTENT_MESSAGE` so siblings + connection_frame are untouched. fact.rs holds the wire/schema consts.
- [ ] handshake families (`connection_request`/`response`, `bootstrap_request`/`response`) — see **"Connection handshakes — carrier + plaintext transport"** below (in progress).
- [ ] `connection/frame_small` — carrier; folds into the stage-3 carrier collapse below.
- [ ] `auth/key_wrap` — handler-authored + encrypted; encrypt-input helpers (deterministic_nonce/associated_data/wrap_info)→encode; clean author/commands split; decode is `decode_key_wrap` (manifest Codec).

### Model fact lessons

- `content/message` is the first production staged route. Its route declares
  `decode::Codec`, `authenticate::ContentMessageAuthenticator`,
  `adapt::ContentMessageAdapter`, and `project::ContentMessageProjector` in
  `FactRoute.pipeline`; `Projector::project` calls `project_staged`.
- Staged authentication receives the decoded `ContentMessageFact`, then does id
  proof and signature proof. The legacy `Authenticator` implementation remains
  as a compatibility wrapper while other families migrate.
- The projector implements `SemanticProjector<ContentMessageFact>` and delegates
  to its existing reviewed `AuthenticatedProjector` body. This keeps behavior
  stable while making the staged route visible.
- Core model tests cover a context-free fact and a fact that returns
  `NeedsAuthentication`. The lesson: authentication parking must happen before
  adapt/project, and a parked authenticator emits only the authentication need.
- Schema-backed rows are modeled separately from facts. The store test proves a
  row table declared through `row_schemas` is allowlisted and still committed
  through opaque `TableRow` storage. The lesson: core can learn row fields from
  protocol-owned schema declarations without hard-coding protocol semantics.
- Documentation should be narrative and reviewer-facing. Each role file says
  what it does; negative boundaries live once in `docs/RULES.md` and the
  guardrails. Avoid defensive "this file does not..." prose in every module.

## Connection handshakes — carrier + plaintext transport

The four handshake families (`connection_request`/`response`, `bootstrap_request`/`response`)
get the standard role-file shape, with one structural fix: **sealing/opening is transport, not
a family concern.** Today each family carries a `transit.rs` (per-family seal/open) — a rules
violation (not a standard role file). It is deleted; its crypto relocates to a shared connection
transport module.

### The model (datalog / carrier)

A handshake fact is **plaintext + durable, like every other fact** (`content_message`). The
sealed bytes are pure **transport**, exactly how an established connection frame works: a
`content_message` isn't "a sealed fact" — the frame layer seals it onto the wire and opens it on
arrival. So:

- `connection_request` / `connection_response` (and the bootstrap pair) stay **durable plaintext
  facts** with their current tags, admission, and projections. The initiator stores its request;
  the peer holds its received copy; symmetric for the response. No sealed-fact, no ephemeral wire
  input, no "outbound isn't a fact" — **behaviour = today**; the whole change is factoring.
- A **carrier** is one concept: an ephemeral encrypted wire fact (+ a `connection_frame_observation`
  for origin/received-at) whose projection pulls an **open-key from context**, decrypts, and
  **admits the recovered plaintext fact(s) durably** (+ a `fact_receipt`). A failed open just
  **drops** (no fact — like a corrupt frame; garbage never becomes a fact, so no admit-then-purge),
  while a *valid* fact that isn't yet actionable (membership still syncing) **parks durably**.
  Carriers differ ONLY in the open-key source — full-range `auth_local_endpoint` (handshakes:
  pre-connection; "a node has exactly one local endpoint, so a full-range need
  `[0;32]..=[0xff;32]` matches without knowing the recipient before opening") vs the connection
  secret from `connection_response` context (established frames: keyed by connection id) — plus
  wire framing/payload count. Everything else is shared: `observed_frame_effect`,
  `connection_frame_observation`, the ephemeral pipeline, `admit_received_fact_bytes`, the
  `connection_fact_receipt_for_path` builder, and egress (`send_network_frame`).
- `connection_response ⋈ connection_request` (and the bootstrap analog) is a **normal plaintext
  context join** against a fact you hold — `connection_request_need` + decode, UNCHANGED. (The
  response must join the request to recompute the handshake transcript / derive the connection
  secret; that join is intrinsic to a request/response handshake, not a misplacement.) The
  responder's own self-authored response branch trusts its construction; only the received branch
  joins.

### Egress == frame egress (hard constraint)

All outbound — established frames AND handshakes — goes through `send_network_frame`: seal
(transport) → emit `send_network_frame_intent(SendNetworkFrame { routing_key, frame })` as a
`local_intent`, and the `send_network_frame` handler is the **sole** `network::send` boundary
(exactly as `send_facts_on_connection` does for frames). The four bespoke
`send_{bootstrap,connection}_{request,response}` handlers lose their direct `network::send` — they
seal then emit `send_network_frame`. `maintain_connections` stays the retransmit driver (re-queues
the send each tick while a request is unanswered). `send_network_frame::resolve_target` resolves
the peer addr from `observed_endpoint_address(peer_endpoint)` (works pre-connection; today it
decodes the connection + request facts).

### Per-family file plan (mirror `content/message`)

- `fact.rs` — the plaintext typed value (unchanged) + wire/schema consts.
- `encode.rs` — `encode_fact` (plaintext bytes) + the signing/handshake transcripts (the
  `*_signing_transcript` / `sign_*` from `create.rs`; the DH key schedule for responses).
- `decode.rs` — `decode_fact` + `Codec` (`FactCodec`) + `decode_fact_payload`. Pure.
- `authenticate.rs` — decode + id + crypto + intrinsic. connection_request: endpoint signature,
  parks on `auth_endpoint_shared` (the verifier key is the initiator's `endpoint_shared` signing
  key, not embedded). connection_response: NO inner signature — DH-only — so decode + id + field
  rules. Already operates on the plaintext today; keep, fix imports.
- `adapt.rs` — `IdentityAdapter<…Fact>`.
- `author.rs` — pure construction of the plaintext fact (build + sign / run the DH schedule). NO
  sealing (that's transport).
- `project.rs` — the current branches (request: local-outbound / received; response:
  local-responder / received), switched to `project_adapted`. Keeps the `connection_request_need`
  join, the row writes, and the `create_*_response` intent.
- `commands.rs` (requests only) — runtime gathering for `connect` / `create`.
- Supporting kept for this migration step: `rows.rs` / `queries.rs` (the outbound request row +
  `pending_*_requests` for `maintain_connections`); responses use the shared
  `bootstrap_response::rows` (connection row + `answered_request_ids`). Treat those row modules as
  temporary facades over the future schema-backed generated row helpers, not the desired end state.
- **Deleted:** `transit.rs` (→ transport module), `layout.rs` (→ encode + decode), `create.rs`
  (→ encode/author; the DH schedule stays callable by author + the received-branch projector).

### Transport module

`transit.rs`'s `seal_*` / `open_*` relocate to a shared connection transport sibling (a
`handshake_wire` module — the handshake analog of `connection_frame_wire`). Seal =
`x25519_xchacha20poly1305_encrypt(sender_ephemeral_priv, recipient_endpoint_pub, PURPOSE, header
AAD, nonce, plaintext_bytes)`; open = `…_decrypt(local_endpoint.secret, sender_ephemeral_pub, …)`.
The send path calls `seal_*`; the carrier projector calls `open_*`.

### Build order (staged)

1. **Membership pair** (`connection_request` + `connection_response`) together — inseparable (the
   response decodes the request's plaintext via the join). Role-file reorg keeping plaintext,
   relocate the two `transit.rs` into the transport module + delete them, unify egress to
   `send_network_frame`. `SealedHandshakeFrameProjector` stays (its membership arms now call the
   relocated `open_*`). GREEN: `cli_membership_connect_reconnects_known_peer_without_invite` + full
   suite.
2. **Bootstrap pair** (`bootstrap_request` + `bootstrap_response`) the same way.
3. **Carrier collapse** — fold `project_observed_frame` (established) + `SealedHandshakeFrameProjector`
   (handshake) into ONE carrier projector: read the observation, get the open-key from context
   (pluggable: endpoint key vs connection secret), `admit_received_fact_bytes`. Delete the dead
   bespoke projector. The frame-family reorg (`frame_small` / `file_slice` / `bundle`) folds in here
   — they are the same carrier.

**Survives untouched** (until stage 3): the established-frame path (`frame_small` / `file_slice` /
`bundle`, `project_observed_frame`, `wire_from_frame_fact`, `admit_received_fact_bytes`),
`frame_observation`, `fact_receipt`, `observed_endpoint_address`, the shared connection row
(`bootstrap_response::rows`).

### Code facts to honor

- connection_request carries an endpoint signature (verified against the initiator's
  `endpoint_shared` signing key — authenticate parks on `auth_endpoint_shared`). connection_response
  has NO inner signature; authenticity = the DH handshake, validated in `project` by recomputing
  `handshake_hash` + `connection_secret` against the joined request.
- The connection row is keyed by connection_id = response fact id. `answered_request_ids` (over
  `bootstrap_response::rows`) is the cross-family join `maintain_connections` uses to stop
  re-sending an answered request.
- `fact_receipt` (`RECEIVE_PATH_CONNECTION_{REQUEST,RESPONSE,FRAME}`) and its builder are shared
  across handshakes + established frames — do not narrow them.
- The ephemeral pipeline is the one projection drain with a lifecycle flag, not a separate path:
  `core/pipeline/project_pending_facts.rs` `enum ProjectionSource { Durable, Ephemeral }`; ephemeral
  inputs load from `ephemeral_projection_inputs`, project once, delete, and may not leave durable
  offers/time-wakes (`validate_ephemeral_projection`). Carriers are ephemeral; the plaintext facts
  they admit are durable.

## Phase 2 — Guardrails

Transition-aware updates DONE (accept new role files alongside old; layout.rs
still allowed for the 42 un-migrated families). In `poc10_intent_cleanliness_test.rs`:
- [x] `STANDARD_FAMILY_FILES` += encode/decode/author/adapt (size 10→14).
- [x] family marker `layout.rs` → `(layout.rs || decode.rs)` in the 3 classification guardrails (scope-helper, registered-modules, single-flat-shape).
- [x] route registration check uses `=> {scope}::{family}::` (contains); route **count** uses `{scope}::{family}::project::` (1 per family — the old `=> ...layout::` over/under-counted: connection families have envelope routes too).
- [x] `target_projectors_authenticate_primary_*` accepts `project_adapted::<` + `super::adapt::` + `super::authenticate::` (multi-line) OR the old `project_authenticated::<super::authenticate::`.
- [x] `target_row_layouts_do_not_emit_context_or_intents` bans `RowMutation` (the effect wrapper) instead of `TableDelete` — while handwritten rows remain, rows.rs builds insert AND keyed-delete payloads, project emits the RowMutation.
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

## Phase 4 — First-class core pipeline runners (versioning-era; after models blessed)

- [ ] `FactRoute` carries decoder/authenticator/adapter/projector with explicit
  labels (`tag`, `intro_version`, `replayed`, `decode`, `authenticate`,
  `adapt`, `project`). Core routes by tag, decodes, authenticates, adapts, then
  projects.
- [ ] Replace projector-local `project_authenticated` / `project_adapted`
  composition with the staged read runner. Projectors receive semantic values
  that have already passed decode/authenticate/adapt.
- [ ] Core command-pipeline runner + ceiling-selected `author` dispatch
  (versioning §5): command gathers runtime state, author builds typed source,
  encode serializes, authenticate self-checks, admit feeds the read pipeline.
- [ ] Generated row route metadata: row schemas declare table names, key/value
  fields, stable order, primitive types, key-prefix helpers, and delete
  selectors; generated helpers replace handwritten `rows.rs` byte packing.
- [ ] purge classifier reads the auth verdict directly; delete `durable_fact_fails_without_context` (empty-context probe) in `project_pending_facts.rs`.
- [ ] context provision: decode→adapt without re-verify; keep consumer-side (Design B) until non-identity adapters justify core-provisioned type-erased payloads (Design A).

## Phase 5 — Docs

- [ ] `fact-validators.md` / `protocol-versioning.md` — write pipeline + authenticate self-check + strict role definitions + author⊥commands guardrail.
- [ ] `src/core/pipeline/README.md` — authentication + adapt + the write pipeline as core stages.

## Sweep findings to honor (validation runs, 2026-06-02)

- Decode is pure bytes→typed in ALL 43 families (carriers included; AEAD-open is a
  transport+context op, not decode).
- Context payloads = decode→adapt, never re-verified (already today's behavior).
- Replay/ephemeral safe: replay re-runs full authenticate; ephemeral authenticate
  before use; identity adapt adds no new decode.
- encode/decode split: 40/43 clean; author: 28 clean, 11 no-create, 4 needs-care.
