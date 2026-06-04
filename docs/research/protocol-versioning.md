# Protocol Versioning

Single authoritative note: the model and phased implementation plan (Part I), then the exhaustive test matrix (Part II). Builds on the landed replay runtime and fact-authenticator split.

## Status and scope

This is the authoritative, consolidated plan for protocol versioning in poc-10.
It starts from two landed prerequisites: the replay runtime
(`poc10-replay-intent-shape.md`) and the **fact-authenticator split**
(`fact-validators.md`) — the bottom of the `authenticate → adapt → project`
pipeline, landed before any ceiling/adapter work. Its exhaustive test matrix lives
in Part II below.

Most machinery described here is unbuilt today. What already exists, and what
the plan reuses:

- Tag-routed facts: `FactRoute { tag, projector, replayed }` and the
  `projector_routes!` table in `src/protocol/registry.rs`; dispatch in
  `core::projectors::RouterProjector`.
- Per-family authenticators: each routed family has `authenticate.rs`.
  Converted families route through a core-managed staged `FactRoute` runner;
  unconverted families still compose authentication into projection with
  `project_authenticated::<Authenticator, _>`.
- Replay runtime: `replay`, `state-summary`, `replay-check`,
  `intent-registry`, and `recurring-intents` are in `src`.
- Container frame facts: `connection::{frame_small,frame_bundle,frame_file_slice}`
  (tags 168–170), produced from wire bytes by
  `connection_frame.rs::frame_fact_from_wire`.
- The `TRNS` AEAD frame layout (`connection_frame_wire.rs`) and the sealed
  bootstrap request (`bootstrap_request/layout.rs`, `TYPE_SEALED_CONNECTION_REQUEST`).
- Connection close / retirement facts; purge-as-context
  (`content/purge/project.rs`); length-framed socket transport with heartbeats
  in `core/network.rs`.

What does **not** exist yet: a protocol version / ceiling, any version gating on
routes, a release manifest, trusted time, scope-owned ceiling adapters,
`intro_version` on routes/handlers/commands, derived context payloads through
`decode -> adapt`, and the pending admission state for wire-admitted bytes that
cannot yet become active facts. A core-managed staged `FactRoute` runner is
available for converted facts; unconverted facts still use projector-composed
routes.

## 1. Summary — the model in one breath

- **One substance: facts.** Everything protocol-meaningful is a fact — content,
  auth, connection frames, sync messages, the sealed handshake. Encryption is
  not a layer outside facts: a frame is a **container fact** whose payload is a
  cleartext key hint plus AEAD ciphertext. Opening authenticates the carrier
  boundary, and projection emits recovered inner fact bytes that re-enter the
  normal pipeline by their own tags. The only non-fact layer is core's TCP
  framing (length prefix + heartbeat), which is protocol-neutral substrate.
- **One versioning knob: the fact tag.** An incompatible durable fact shape is a
  new tag, kept-forever decoder/authenticator functions, a scope-owned adapt edge toward
  the active ceiling model, and a sibling `_vN/` directory. No internal version
  bytes for routed facts. The `TRNS` magic is a socket-level recognizer for the
  framing substrate, not a fact-versioning device.
- **One coordination number: the protocol version, defined as a named bundle of
  tag-versions.** `protocol 7 = protocol 6 + {message:2, file:3}`. It is
  platform-neutral. Per-platform semver maps onto it through a fleet-wide
  signed manifest. The **ceiling** is the minimum protocol version supported by
  every still-usable release, across all platforms. Because durable-fact support
  is left-anchored at `[1, head]` (authenticators-forever), `min(supported_protocol
  .end())` is exactly the ceiling; the version-range *intersection* concern
  applies only to transport carriers, which have a moving floor.
- **Two uniformity invariants:**
  - *Visibility* (emission): any shared action emitted under the ceiling is
    admissible by every supported client.
  - *Rendering* (reading): the surfaced meaning of shared facts is a function of
    `(retained facts, protocol version)` — identical across every supported
    client and platform. Clients render **at the ceiling, not their head**; only
    presentation chrome is platform-local.
- **Decoders/authenticators forever; transport lives in `[floor, head]`.** Old fact
  decoders and authenticators are kept forever because retained signed history must
  always authenticate as historical evidence. Old transport formats are kept only
  while some still-usable release speaks them; once every speaker has expired
  (**sub-floor**) — or a format is unsafe — the format is dropped. **Expired /
  sub-floor peers are out**: no recovery responder. Updating is the
  app-store/updater's job; local data is safe regardless because it replays after
  update.
- **Replay authenticates, adapts, then projects.** Wipe and replay rebuilds
  derived state from retained facts by routing bytes to their historical
  authenticator, translating typed authenticated facts through the scope-owned
  adapt chain to the active ceiling semantic type, and running the ceiling
  projector. Core owns these route stages; the protocol route owns the concrete
  typed fact and semantic values for that tag.
- **Pending before active.** Bytes that make it through transport/frame opening
  from an authenticated sync peer can be retained as **pending** when the local
  runtime cannot yet authenticate, decrypt, or ceiling-admit them. Pending bytes
  are syncable evidence, not active semantic facts: no projection, read rows,
  authority, purge effect, or local creation follows from them until they
  re-enter admission and become active.

Invariants stated precisely:

1. **Visibility.** If trusted clients create a fact whose tag is ceiling-active,
   every still-usable release can admit, project, display, and transport it.
2. **Rendering uniformity.** Two supported clients at the same protocol version,
   given the same retained facts, produce the same surfaced meaning (read-model
   row content), independent of release or platform.
3. **Ceiling monotonicity.** The ceiling never decreases: a production release
   must support every ceiling-active capability (the no-regression gate), and
   expiry only removes constraints.
4. **Replay determinism.** Given the same retained facts, trusted time, and
   active ceiling, replay produces the same state regardless of admission order,
   and recreates only facts that are deterministic functions of retained facts.
5. **Keep-forever decoders/authenticators, floor-bounded transport.** No retained fact
   ever loses the decoder/authenticator for its original signed bytes. No
   transport format is answered below the floor.
6. **Safety floor.** A fact version or transport format is removed before
   natural expiry only when it is unsafe.

### Why the invariants hold

The visibility invariant follows from four properties of the release train, not
from any runtime consensus about who is upgraded.

1. **The blocker is known at build time.** A release that introduces capability
   C is built after the newest release that lacks C — the blocker — so C's
   release embeds the blocker's identity and `expires_at` in its manifest (the
   monotonic-train assumption, enforced by the no-regression gate, invariant 3).
2. **Emit is time-gated.** A capable release withholds C in production until its
   trusted time passes the blocker's `expires_at` plus a skew margin `M`.
3. **Expiry is self-enforced.** The blocker independently blocks its own shared
   production once its trusted time passes its `expires_at`.
4. **Trusted time is a monotonic lower bound on real time.** So when a capable
   client believes the blocker expired, real time truly has passed `expires_at`;
   the blocker reaches the same belief once its own trusted time catches up.

The only window in which a capable client emits C while a blocker still reads is
where the capable client's trusted time has passed the deadline but the blocker's
has not. The "skew" here is **not wall-clock skew**: trusted time is a monotonic
max of *signed* observations and never overstates real time, so a device can only
be *behind*, never ahead. What separates two actively-refreshing devices is lag
in the **signed-observation stream** — bounded by the staleness window `S` (the
longest a participating device may go without refreshing) plus the propagation
delay `P` of a signed time/expiry observation reaching a device's sources.

Two rules close the window, and they are **sized against each other**, not chosen
independently:

- **Skew margin `M`.** A capable client advances the ceiling only at
  `trusted_time > expires_at + M`. Because trusted time lower-bounds real time,
  this guarantees real time is genuinely past `expires_at` by more than `M`
  before C is ever emitted in production.
- **Staleness block `S`.** A still-usable release that has not ingested
  a fresh signed observation within `S` stops its own shared production until it
  refreshes. So any blocker that is *still participating* necessarily refreshed
  within the last `S`.

Choose **`M ≥ S + P`** (with headroom). Then at the instant a capable client
raises the ceiling — its `trusted_time > expires_at + M`, so real time is also
`> expires_at + M` — any blocker still doing shared production refreshed within
`S`, and the freshest observation it could pull attests a trusted time of at
least `(expires_at + M) − S − P`, which by the choice of `M` is `> expires_at`.
That is past the blocker's own `expires_at`, so it has already self-disabled
(property 3) — the danger window is empty. A blocker that *cannot* obtain fresh
signed time does not guess it is pre-expiry; it enters blocked mode under the `S`
rule and stops participating, which is the safe direction.

The argument is **per-device**, with no appeal to devices staying in lockstep. A
fresh install whose embedded time is stale computes a low (conservative) ceiling
and/or enters blocked mode until it refreshes — never an over-optimistic ceiling
that would emit C too early. A device that cannot refresh simply stays behind and
conservative, independent of what any other device holds; safety never relies on
a fleet-wide signed-time stream advancing *together*. The single residual
assumption is that `S + P` stays within the chosen `M`; the separate case where
`expires_at` itself is moved is the grace-window caveat below.

Security-deprecation is the deliberate exception: a `must_update` canary removes
a release from the still-usable set early, so the invariant stops protecting that
release's users — which is the point of emergency deprecation, and why "supported
client" means "still-usable release," not "any running client." Grace windows
refine property 1: extending a blocker's `expires_at` is safe only if every
capable producer learns the extension before the original deadline, so distribute
extensions with margin and have producers treat the latest signed `expires_at`
they have observed as authoritative.

## 2. Implementation plan

The plan is phased so each phase establishes one invariant and can be tested in
isolation. Core stays protocol-neutral throughout: it routes facts by tag,
filters routes by the ceiling, wipes and replays, and stores signed
release/time observations as local facts. Scope modules own the version
decisions.

### Phase 0 — Replay runtime (landed prerequisite)

`poc10-replay-intent-shape.md` has landed: the wipe-and-replay entry point,
`HandlerRoute.runs_during_replay`, recurring intents, the projection/work
fixpoint, and the network/purge barrier. Versioning rides on top of this
runtime.

### Phase 1 — Version space, manifest, trusted time

- **Protocol version** is a single monotonic `u32`. A **capability** is the set
  of fact tags (and their projectors/constructors) introduced at one version.
- **Release manifest.** Provider-signed, one entry per shipped release, fleet-wide:

  ```rust
  pub struct ReleaseManifestEntry {
      pub release_id: ReleaseId,
      pub platform: Platform,                       // Desktop | Mobile | ...
      pub supported_protocol: RangeInclusive<u32>,  // contiguous create/admit/project/display/transport range
      pub warn_after: TrustedTime,                  // user-facing update prompt; no protocol effect
      pub expires_at: TrustedTime,                  // shared production blocks past this; ceiling transition for a blocker
      pub signature: ProviderSignature,
  }
  ```

  A build embeds every entry it knows at build time (always including older
  releases it must wait for). Later entries and `expires_at` extensions arrive
  as signed registry facts; clients persist the **monotonic union**. Store these
  as durable local facts.
- **Trusted time.** Persist the greatest time learned from embedded metadata,
  signed registry facts, or signed canaries (monotonic max; a lower bound on
  real time). Define a rollback tolerance, a skew margin `M`, and a staleness
  window `S`.
- **`must_update` canary.** Signed, monotonic, persisted; marks a release
  security-deprecated before `expires_at`. Delivered out of band from the
  provider and also gossiped as a signed fact for offline catch-up.
- **Ceiling function.** `ceiling = min` over still-usable releases (not past
  `expires_at`, not security-deprecated), across all platforms, of
  `supported_protocol.end()`, evaluated at `trusted_time`. A capability advances
  to ceiling-active only at `trusted_time > blocker.expires_at + M`. If trusted
  time rolls back beyond tolerance, or has not refreshed within `S`, enter
  **blocked mode** (shared production withheld; local reads and replay
  continue).
- **Permission ceiling vs. write activation (decision, 2026-06-04).** The
  ceiling is a *permission* upper bound, never a write trigger: it bounds what a
  node *may* emit and never forces it to begin emitting a newer shape. The actual
  write-version is the highest bucket that is both `<= ceiling` and has an
  `author`/`encode` path compiled into the build — i.e.
  `min(ceiling, highest-authored-version-in-this-build)`. Writing below the
  ceiling is always safe (older still-usable peers can read it; adapters bridge
  it on replay), so a build may deliberately sit below the ceiling. The **read
  side ships ahead** — `decode`/`authenticate`/`adapt`/`project` land in an
  earlier release so the node ingests the new shape from non-stalled peers the
  moment the ceiling allows — while the **write side is gated on the deploy**
  that ships the family's `author`/`encode`. Emission therefore begins at a
  release/upgrade (a discrete, locally-controlled event), while the ceiling still
  guarantees no node ever emits a fact an older still-usable peer cannot read.
  Net: a deprecation-driven ceiling rise *grants permission*; shipping the author
  path is the *trigger* (`ceiling-cleared AND release-opted-in`). Chosen
  implementation: gate purely by **what the build compiles in** (withhold
  `author`/`encode` until the release that should begin emitting), not a separate
  manifest opt-in flag.

### Phase 1b — Observability surface (so the machinery is black-box-testable)

The versioning machinery is in-process, so without CLI handles it can only be
exercised by mocked, suspect handler-unit tests. These read-only `con` commands
make it black-box-observable. Each queries the **real durable store** and reports
status only — never plaintext — so it is an observability affordance, not a
backdoor:

- `manifest-ingest <signed-entry>` / `time-observe <signed-obs>` — feed a signed
  manifest entry or a trusted-time / canary observation (the only inputs to the
  ceiling).
- `ceiling` — dump the computed protocol-version ceiling, the still-usable
  release set, and each capability's ceiling-active status at the current
  trusted time.
- `fact-status <id>` / `purge-audit <id>` — report whether a fact id, **and any
  row, index, or material derived from it**, is present anywhere in durable
  storage. This is what makes purge-completeness and forward secrecy black-box:
  create → purge → assert `purge-audit` reports gone in **every** location.
- the replay surface from `poc10-replay-intent-shape.md` (`replay`,
  `state-summary`, `replay-check`).

With these, the manifest/ceiling/pending/purge invariants — and the bulk
of the handler-unit triage's `A`/`BX-M` buckets — are proven black-box instead
of by fabricated in-process state.

**Purge-completeness and forward secrecy are black-box via `purge-audit`.** The
audit must scan every table/index/blob (fact log, derived row tables, sync
shareable/negentropy tables), not just the fact-log entry — so a purge that drops
the fact but leaves a derived secret fails the audit. Forward secrecy is then:
the whole retiring secret set is `purge-audit`-gone **and** no surviving
`key_wrap` or path-node targets the retired coordinate (the "healing must not
resurrect the removed root" rule), both presence-checkable. The only residue
outside this is crypto-primitive soundness (the remaining material is
cryptographically insufficient, not merely absent), which is out of scope —
trusted to the AEAD/DH primitive, not to poc-10.

### Phase 2 — Staged routes, then route gating

The first implementation step in this phase is the staged `FactRoute` runner. It
should land before real adapters, manifests, trusted time, or ceiling filtering:
current behavior is preserved by registering an identity adapt slot for every
existing family. That gives core ownership of the `authenticate -> adapt ->
project` pipeline now, so later versioning work fills in non-identity adapt edges
and ceiling filters instead of moving the projector boundary again.

Before the broad fan-out, build model family examples for the target file shape
and review them. The examples should cover the main family styles — a
signed/encrypted content fact, a fact with an external verifier-key
`AuthenticationNeed`, a container frame fact, and a deterministic
handler-authored sync/auth fact. Each model should include the target files
(`encode.rs`, `decode.rs`, `author.rs` when the family locally authors facts,
`authenticate.rs`, identity `adapt.rs`, and `project.rs`), top-of-file policies,
route declarations, and focused tests. Once those examples settle, migrate the
remaining families mechanically.

- `FactRoute` becomes the core-owned staged pipeline for one tag: `tag`,
  `intro_version: u32`, `replayed`, decoder, authenticator, adapt path, author
  entry when local creation exists, and projector.
- Core runs `authenticate -> adapt -> project` as three labelled stages.
  `AuthenticationNeed` parks/wakes the authentication stage; projector
  context/time needs park/wake the projection stage for an already authenticated
  and adapted fact. A future adapt need would park/wake the adapt stage, but the
  identity adapt stub has no needs.
- Core also grows the write-side twin for commands: `cli -> command -> author ->
  encode -> authenticate self-check -> admit`. This is where blocked-mode,
  ceiling-selected author dispatch, local above-ceiling refusal, returned fact
  ids, and the handoff into the read pipeline belong.
- `registry::protocol_projector()` builds a **ceiling-filtered** route runner
  containing only routes with `intro_version <= ceiling`, recomputed when
  trusted time or the manifest changes.
- The route is typed inside protocol-owned functions and opaque to core. Core can
  know that tag 50 uses a particular decoder, authenticator, adapt path, author,
  and projector without importing `ContentMessageFact`; the route-owned stage
  functions enforce that the decoded type, authenticated type, adapted semantic
  type, author output, and projector agree.
- `HandlerRoute` gains `intro_version`; `runs_during_replay` is already present.
- `CliCommand` registration becomes a stable name mapped to a **version-tagged
  list** of run fns: `name -> [(intro 0, run_v1), (intro 7, run_v2)]`. The
  dispatcher runs the highest entry with `intro_version <= ceiling`. "Absent ⇒
  reuse previous" falls out: you simply do not add an entry when the surface is
  unchanged.
- Guardrail: every route (fact, handler, command) declares `intro_version`
  explicitly; a registry completeness test fails if one is omitted.
- Carry-over TODO for the model-family pass: split the representative families
  far enough to prove both pipelines. For each model, show command input
  gathering, `author.rs` construction, `encode.rs` transcript/final-encode
  helpers, the authenticate self-check before admission, and the read-side
  `decode -> authenticate -> adapt -> project` route.

### Phase 3 — Admission, pending, and unsupported input

- **Pending, not active truth.** Production clients locally create only
  ceiling-active fact tags. Received bytes that make it through the
  connection/frame/opening boundary from an authenticated sync peer may be
  retained as **pending** when the tag is unknown to this binary, above the local
  ceiling, or missing authentication/decryption context. Pending bytes are not
  active protocol truth: they are not projected, displayed, counted, used for
  authority, used for purge, or treated as validated facts.
- **Wire-invalid bytes still drop.** Bytes that fail transport framing, cannot
  be opened by the active carrier, come from an unauthorized source, or are
  otherwise malformed before a stable fact id/hash can be established are
  dropped. Some future upgrades will not make it through the current wire/frame
  layer at all; those bytes never become pending.
- **Pending is syncable and waiting.** Pending bytes may participate in
  negentropy by id/bytes so supported peers can avoid download loops during
  ceiling skew. They are still inert locally. When the manifest/ceiling changes,
  verifier/opening context arrives, or the binary updates to know the tag, the
  pending bytes re-enter the normal `authenticate -> adapt -> project` admission
  path. If they then authenticate and are ceiling-active, they become active
  facts and project normally; if they fail authentication or remain unsupported,
  they stay pending or are rejected according to the admission result.
- **Local creation** of an above-ceiling fact is refused at the command/admission
  boundary. Pending is only an ingress state for bytes received from authenticated
  sync/transport paths.
- **Call this `pending`.** New implementation and tests should say **pending
  facts** or, when distinguishing this from the existing projector wake queue,
  **pending ingress**. Pending ingress is raw admitted bytes waiting to become an active
  authenticated fact; projector-pending is an active fact waiting on ordinary
  context needs.
- **Known-route authentication.** The landed implementation composes
  authentication into projection with `project_authenticated`; the next
  implementation step hoists that work into the core-managed `FactRoute` runner.
  Once a tag is registered, core routes the raw bytes to that tag's authenticator
  as the first stage. Ceiling filtering later decides which registered tags can
  become active. The authenticator returns
  `Authenticated(AuthenticatedFact<T>)`, invalid bytes, or
  `NeedsAuthentication(AuthenticationNeed)` for verifier/opening context.
  Projectors stop invoking `project_authenticated` themselves; that composition
  becomes route-runner logic around the typed authenticator, adapt, and projector.
  Projectors, not authenticators, express semantic context, authority
  requirements, parking, purge rules, and reproject needs. A fact version
  chooses whether verifier key material is embedded or referenced; the runtime
  contract must support `NeedsAuthentication` either way so future versions can
  trade self-contained verification against public-key size without changing
  projector semantics.

### Context integrity (core-enforced)

An authority audit of the current code found authority is already sound — every
authorization decision derives from context facts and their transitive validity
back to a root (workspace creation / root admin / invite secret), re-derived on
every replay, never from a read-model row, a store query, ambient state, CLI
preflight, or network metadata. Two structural guarantees should move into core
so projectors can *rely* on them instead of re-checking, and one threat must be
closed:

- **Payload identity is a core guarantee.** Core builds a matched context's
  payload by loading the fact at `offer.owner` from the content-addressed store,
  so `payload.id == offer.owner` holds by construction. Enforce it once at match
  construction (produce no match if the owner fact does not load) and delete the
  checked/unchecked accessor split, so every projector gets one always-safe
  payload. After the staged route lands, core derives the matched owner's
  payload shape through that owner's route-owned `decode -> adapt` path. This is
  a decoder path, not the authentication gate: the offer exists only because the
  owner fact already passed its own primary route.
- **Scope is pinned to the owning fact (core).** `FactScope` is unhashed
  admission metadata the emitter currently sets freely, and the emission gate
  (`enforce_owner_is_self`) pins only `owner`. Extend it to reject any emitted
  offer/need whose `scope` is not the projecting fact's scope, so a fact can
  never publish context into a **foreign workspace** partition. For "own scope"
  to be trustworthy on received facts, **admission derives a shared fact's scope
  from its own signed `workspace_id`**, never from a sender/transport label.
- **Two threats, two locks.** *Another workspace offering context* → the scope
  pin plus signed-scope derivation. *Another fact type by mistake* → role
  namespacing (versions of a family share a stable role; distinct families do
  not) plus the projector's typed decode, which fails on a foreign tag.

### Phase 4 — Directory layout and version buckets

- A new incompatible fact version is a sibling `_vN/` directory (original stays
  unsuffixed; never renamed). The **bucket holds the deltas**:
  - `fact.rs`: the typed source value for this durable wire shape. It is not a
    durable fact by itself; it carries source ids/provenance when the active
    semantic value needs them.
  - `encode.rs`: typed source value to canonical wire bytes, plus transcript
    helpers for nonce seeds, AEAD associated data, signing bytes, and final
    serialization. This replaces the encoding half of today's `layout.rs`.
  - `decode.rs`: canonical wire bytes or `Fact` to typed source value. It checks
    tag, length, padding, enum values, and canonical field shapes, but it does
    not check fact id or signatures. This replaces the decoding half of today's
    `layout.rs`.
  - `author.rs`: local semantic construction: command/context/keys to an
    authored typed value, including encryption, signing, assembly,
    deterministic nonce use, and policy checks. This replaces fact-family
    `create.rs`; names of non-family intents/handlers may remain `create_*`.
  - `authenticate.rs`: always present per version, kept forever, and routed by
    tag. It calls `decode`, computes/checks the fact id, verifies the
    fact-boundary cryptographic proof (usually signature/domain, sometimes a
    container AEAD opening), enforces intrinsic layout rules, and emits a typed
    authenticated fact. Its result shape is
    `Authenticated(AuthenticatedFact<T>)`, `NeedsAuthentication(AuthenticationNeed)`,
    or `Invalid(AuthenticationError)`.
  - `adapt.rs`: always represented in the route; existing unsuffixed families
    start with an identity adapter. In the linear default, `vN/adapt.rs` converts
    `vN-1::fact` into `vN::fact` or the active semantic value. An adapter never
    parses raw bytes, queries context, parks, holds pending ingress, or performs
    authorization checks.
  - `project.rs`: owned by the active ceiling semantic node; it consumes that
    version's adapted semantic type, checks context/authority/purge requirements,
    and emits rows, context offers, and replayable intents. An old `project.rs`
    may be kept only when the old projector is itself the clearest
    implementation of an adapter.
  - `cli.rs`: present **only when the input surface changes**; selected by
    ceiling; absent ⇒ reuse previous. Its absence asserts that the prior parser's
    collected parameters fully determine the new `author.rs` entry's required
    inputs.
  - `rows.rs` / `queries.rs`: shared at head; a v2 fact projects into the current
    row shape (ceiling-era rows). A genuinely new table is the rare exception.
- Lineage lives in data and the registry, not the tree: a `supersedes_*` field /
  context offer plus the `intro_version` index. Shared field codecs are reached
  through a module-owned typed helper, never another module's raw layout codec.

### Phase 4a — Scope-owned ceiling adapters

Scope-owned adapters apply to retained **durable facts**. They are not a general
conversion layer for ephemeral transport/session prompts, live network frames,
queued operational intents, or local diagnostic bytes. Those surfaces are either
current-runtime work or transport compatibility, and are handled by their own
floor/negotiation/retry rules.

The projection pipeline for primary facts is:

```text
raw retained fact bytes
  -> tag route
  -> version authenticator
  -> typed authenticated fact
  -> source typed value
  -> scope-owned adapter chain to the active ceiling semantic value
  -> ceiling projector
  -> rows, context offers, replayable intents
```

The adapter chain is per scope. Nodes are Rust value types, usually the family
`fact.rs` type for that version, not durable facts. The default convention is
linear: `vN/adapt.rs` converts the `vN-1` source value to the `vN` source value
or active semantic value. Replay to ceiling v2 runs `v0 authenticate -> v0 value
-> v1/adapt.rs -> v1 value -> v2/adapt.rs -> v2 value -> v2/project.rs`.
Branched evolution or shortcuts are allowed only after renaming the edge
explicitly, for example `v2/from_v0.rs`, and declaring the canonical path in the
scope registry. A shortcut must be tested equivalent to the chain it replaces.

An adapter does not create a new signed fact. The original signature remains over
the original bytes and domain; the semantic output carries provenance pointing
back to the signed source fact ids. If the old semantic type lacks data required
by the next semantic type, the next type must represent that absence explicitly
(`Unknown`, `NotPresent`, weaker capability, etc.) or the change needs a new
durable fact. The adapter must not invent authority, silently widen access,
expose data hidden by a ceiling policy, or reinterpret old facts by accident.
An authority adapter may only preserve or narrow authority relative to the previous
authenticated semantic value. Any authority widening requires a new durable
authority fact and normal projector/context validation; it cannot be introduced
by an adapter.

Projectors still own context. Cross-scope projectors should depend on semantic
contracts, not raw foreign fact layouts: content may require
`auth.endpoint_authority@ceiling`, while auth owns how its durable facts and
adapter chain produce the ceiling auth semantic type. The auth projector then checks
workspace membership, revocations, purge facts, and policy facts, and it parks or
rejects according to normal context rules.

Context payloads are adapted too, but they do not re-enter the authentication
gate. A projector's needs and offers match on stable role/scope/range
coordinates. For a matched offer, core loads the owner fact and derives the
payload through that owner's route-owned `decode -> adapt` path. The consuming
projector receives context payloads in the semantic version it expects at the
active ceiling, not the raw historical layout that happened to satisfy the
offer. This keeps version adaptation out of projectors without re-verifying
context signatures: a ceiling-v2 content projector that needs an auth context
sees the auth ceiling-v2 semantic value, even if the retained auth fact was
authored as v0 and reached that value through the auth adapt chain.

This replaces "keep every old projector forever" with a narrower obligation:
keep every old decoder/authenticator forever, keep the linear adapter chain for
retained durable facts to the active ceiling semantic type, and keep the ceiling
projector for the current semantic contract. Security fixes land at the smallest
layer: malformed old bytes are handled in authenticators, unsafe representation
mapping in adapters, unsafe interpretation in projectors or policy facts, and bad
derived state by replaying with the fixed projector.

### Fact durability and replay classes

Durability and replay are **two axes**, not one: *retained* (the bytes survive a
wipe) and *replay-projected* (re-fed through `authenticate → adapt → project` on
an upgrade wipe to rebuild derived state). The current code represents the
second axis with `FactRoute.replayed: bool`.

- **Replay-projected** (`replayed == true`) — retained facts that rebuild
  deterministic derived state on replay. This includes shared content and auth
  history, deterministic sync rows such as `sync::shared_fact`,
  `sync::compare`, and `sync::range_request`, connection lifecycle/receipt/frame
  records, local secrets that are deterministic replay inputs, and the cascade
  test fact. Future versioned families in this class carry `decode.rs`,
  `authenticate.rs`, `adapt.rs`, and `project.rs`, plus `encode.rs`/`author.rs`
  when the family can be locally authored.
- **Retained but not replay-projected** (`replayed == false`) — facts kept in the
  store but deliberately excluded from upgrade replay. Today this set is exactly
  six tags, pinned by a registry guardrail: bootstrap request/response,
  connection request/response, and sync have/need. These families carry
  `decode.rs` + `authenticate.rs` + `project.rs`; they may register an identity
  adapter, but need no physical `adapt.rs` file until a non-identity conversion
  is useful.
- **Pending / non-protocol input** — raw network bytes before they have become
  a fact, live-only queued work, daemon schedules, and wire-admitted bytes held
  pending because the local runtime cannot yet authenticate, decrypt, or
  ceiling-admit them. Pending bytes are retained/syncable as bytes, but are not
  replay-projected and do not have an adapter until they re-enter admission and
  become active facts.

So replay-projected families carry a real or identity `adapt.rs` entry.
Non-replayed families may register an identity adapter in the route but do not
need a physical `adapt.rs` file until a non-identity conversion is useful.

This **replaces the connection-retirement-before-replay dance** for
non-replayed connection establishment facts: the wipe simply does not re-project
bootstrap/connection request/response facts, so replay does not resurrect a dead
session from those live-session-coupled rows.

**Invariant — the replay graph is closed.** A replay-projected fact may depend
(causally or for context) only on other replay-projected facts. Local-durable and
ephemeral facts may depend on replay-durable facts, but nothing replay-projected
may depend on them — else replay would dangle on state it does not rebuild.
(`connection_response` self-contained is the special case.) A `GUARD` test
enforces this.

**In code:** the route carries `replayed: bool`; the wipe-and-replay entry point
marks only `replayed == true` facts pending for projection. The marker is
orthogonal to `FactScope`, so it is declared explicitly rather than derived from
scope.

### Phase 5 — Rendering uniformity

- The projector produces read-model rows; rows are the surfaced meaning, and the
  projector is ceiling-gated. Therefore a newer client **renders at the ceiling,
  not its head**: it withholds a head-only *derivation of existing facts* (a new
  badge, a new filter, a new computed column) until that capability is
  ceiling-active. New *fields* are self-gating (a below-ceiling fact has no
  head-version bytes).
- Reads split: pure formatting / native chrome / `--json` are presentation and
  may differ per platform and release; any change to **row content** (what is
  surfaced) is the display half of a capability and is ceiling-gated.

### Phase 6 — Transport: container facts, floor, negotiation

- **Frames are facts.** Drop any "envelope is not a fact" framing.
  `connection_frame_wire.rs` is the AEAD wire-layout module for the frame facts;
  the cleartext header (`tag + version + size_class + connection_id + nonce`) is
  the key hint. The carrier authenticator/opener proves and opens the frame
  boundary with connection context; the projector materializes the recovered
  inner fact bytes and receipts. Those inner facts then re-enter the normal
  `authenticate -> adapt -> project` pipeline by their own tags. The `TRNS` 4-byte magic is a
  stream recognizer owned by the framing substrate (`core/network.rs`), not a
  fact-version device.
- **Negotiate up** between capable peers (highest common frame version inside the
  authenticated session). **Initiate at the operational floor** when the peer is
  unknown. **Answer in the request's version** for a still-usable older peer.
- **Floor-bounded retirement.** Keep a transport format while some still-usable
  release speaks it; drop it once sub-floor (all speakers expired) or unsafe.
  **Expired / sub-floor peers are out** — no recovery responder. (Delete the
  former "answer old formats for recovery" rule.)
- **Carrier capacity gates ceiling activation.** A fact too large for an in-floor
  frame cannot become ceiling-active until that frame is sub-floor or the fact
  has an old-frame-compatible chunking path (the `file_slice` precedent —
  chunk, don't grow the frame).
- **Connections are local-durable, so not replay-projected.** The wipe does not
  re-project `connection::request`/`response` (see *Fact durability and replay
  classes*), so rebuilt sync indexes never live-tail over a dead pre-upgrade
  session — no `connection_close` / upgrade-retirement fact is needed to
  neutralize them during replay. After the barrier, peers re-handshake fresh.

### Phase 7 — Manifest discipline and guardrails

- Adding or changing a fact family requires a manifest entry naming: the tag,
  its `intro_version`, the blocking non-capable releases and their expiries (per
  platform), the kept old decoders/authenticators, the adapter chain to the active
  ceiling semantic type, the security-deprecation policy, the replay output, and
  the tests below.
- **No-regression gate.** A production release whose `supported_protocol` does
  not cover the current ceiling is refused for production (alpha only). This keeps
  the ceiling monotonic.

### Worked example: a fact-version-safety change (encrypted usernames)

Security changes name the smallest unsafe surface: an **unsafe release** is
blocked by embedded expiry or a `must_update` canary (its historical facts stay
valid unless their fact version is also unsafe); an **unsafe fact version** is
handled by tightening that version's adapter, suppressing affected facts, or
adding a durable policy fact that invalidates a bounded subset (ask live signers
to reissue when useful, but never require universal re-signing for correctness);
**unsafe derived state** is fixed by wipe-and-replay, with no durable migration
when the source facts are safe.

Plaintext usernames are the worked example. `auth::user` carries a plaintext
`username`, signed by the user-invite key that admitted the user; later devices
usually hold only their endpoint signing key (proven by `auth::endpoint_shared`),
not the original invite key, so a normal device cannot reissue the same
`auth::user` shape. The fix is a new ceiling-gated profile fact — a new tag in a
sibling bucket (Phase 4), not a same-shaped rewrite. The old `auth::user`
authenticator still proves the old signed bytes are authentic, while the auth
adapt/projector path preserves membership authority and refuses to use the
plaintext field as a display claim once the policy says it is unsafe.
Illustrative shape:

```text
auth::user_profile_v2 {
  workspace_id,
  subject_user_id,          // old auth_user fact id; still the membership anchor
  supersedes_profile_id,
  encrypted_display_name,
  signer_endpoint_shared_id,
  signer_public_key,
  signature,
}
```

It is signed by an admitted endpoint; its projector needs the old `auth_user`
fact and the signer `auth_endpoint_shared` fact, and admits only when both are in
the same workspace, `endpoint_shared.user_authority_fact_id == subject_user_id`,
and the signer key matches the endpoint_shared row. It may replace display data
only — never membership, admin authority, the original user key, or the subject
id. The old `auth::user` authenticator plus adapt keeps emitting authenticated
membership identity without materializing plaintext into display rows; a policy
fact can hide or suppress old plaintext names; live devices publish encrypted
profile facts opportunistically. Purging the raw plaintext bytes first needs an
authority-preserving replacement or tombstone — authority anchors are not freely
purgeable — or content naming `author_user_id == auth::user.id` loses its context
proof.

### Atomicity and crash-consistency

Several invariants are about *ordering across a commit boundary*. They have no
steady-state behavioral footprint, so they are stated here as first-class design
requirements and are proven by black-box **fault injection** (kill at the
boundary, restart, observe recovery via `state-summary` / `purge-audit`) — never
by a mocked ordering assertion (`C`-bucket in Part II below
§21):

- **Commit-before-effect.** A handler that performs an external effect commits
  the fact that authorizes/derives it *before* the effect. E.g.
  `create_connection_response` commits the responder ephemeral + response facts
  before any byte is sent; a lost send is re-derived from the committed facts.
- **Finish-or-abort before the wipe.** At the upgrade boundary an in-flight
  handler either finishes its commit or aborts without committing before
  wipe-and-replay; a queued-but-not-running intent may be dropped.
- **Randomness committed before reliance.** A protocol-relevant random value a
  handler chooses is committed as a fact before any later effect relies on it,
  so replay is deterministic and the choice is observable.
- **Purge before reconnect.** Local purge/retirement work completes before the
  runtime reconnects, so a peer never receives material a purge fact retired.

### Time-driven effects use trusted time

A time-driven destructive effect — disappearing-message expiry, retention purge,
cover-horizon retire — is driven by the **persisted trusted-time lower bound**
(the same signed lower bound as the ceiling) and re-derived on replay as a
replayable semantic time wake. It must **not** be gated by the operator-settable
logical clock, which is not a fact, not synced, and not replay-stable. Because a
lower bound can never overstate time, premature purge is impossible (a
fast-forwarded clock cannot mass-delete), and a stale device merely *delays*
expiry (conservative), never purges early. The logical clock stays for live
operational scheduling only, never for a replay-relevant destructive decision.

## 3. Test matrix

The full expansion — ~620 concrete, implementable tests across 18 clusters plus
an adversarial completeness pass and a coverage matrix — is **Part II** below.
Each test gives its Setup / Action / Expect / Defends / Refs, with RED (target
behavior) and GREEN (existing-guardrail) tests distinguished.

Proof surface, per project convention: black-box `con` CLI/network tests for
behavior, focused projector/pure-unit tests for proofs, and registry/boundary
guardrails for structure. Every cluster names the invariant it defends. The
matrix is exhaustive over the cross-product of {new version, old version} ×
{create, cli, query, projector, sync, connection} × {content, auth, connection,
sync}; the multi-node intersection cases are the Part II "Multi-node end-to-end
pairs" and "Platform, transition & pending activation" clusters.

### Handler-unit tests are not proof-of-record

A projector is a pure function (fact + context → output); a handler is impure —
it reads store state through `HandlerContext` and performs an effect — so a
mocked handler-unit test can pass on fabricated state the real pipeline would
never produce, i.e. prove a fake invariant. Handler-unit is therefore **not** a
proof-of-record kind. Each is triaged (full table in
Part II §21 below) into:

- **P — pure**: the assertion is really on a constructor (`create::*`),
  authenticator (`authenticate_*`), layout decoder, frame classifier, version
  resolver, or projector. Re-tag `projector-unit`/`pure-unit` (trusted) and build
  its input facts through the real owning-module encoder, never hand-written
  bytes.
- **A — stateful-deterministic**: black-box via a real `con` command + observe
  the emitted fact/row, with `replay-check` for idempotence and order
  independence. (Includes `require_fact` "never fabricate" backstops — observe
  the *absence* of the fact.)
- **B — effectful** (send/receive): multinode black-box (observe the consequence
  on a second real node) plus the rule that any nondeterministic choice is
  committed as a fact before anything relies on it.
- **C — atomicity / ordering / blocked-mode**: black-box fault injection
  (crash/restart, observe recovery via replay) — never a mocked ordering
  assertion.

Triaging the current 106 found ~half (52) were mis-tagged pure tests already in
the trusted classes; the rest resolve to black-box; **no handler needed
significant logic-shedding** — the algorithms already live in pure constructors,
planners (`compare::create::response_plan`), batchers (`fact_batches`), and
projectors, with handlers doing `require_fact` → call → return. A `GUARD`
guardrail should keep handlers thin so this stays true.

## 4. Open decisions

These encode product choices, flagged so they are not silently assumed:

- The skew margin `M` and staleness window `S` values.
- The `must_update` out-of-band delivery channel (provider endpoint vs. signed
  push) and its trust roots.
- Whether alpha and production builds may share a workspace, or are partitioned.
- The exact `Platform` set and whether a third platform changes the fleet-wide
  ceiling computation.

---

# Part II — Test Matrix

## How to read

- Each test gives **Setup / Action / Expect / Defends (which invariant) / Refs
  (real poc-10 entities and files)**.
- **Kinds:** `blackbox-cli` (drive the real `con` binary), `multinode-network`
  (≥2 nodes), `projector-unit`, `handler-unit`, `replay-cli` (the planned
  replay / state-summary / replay-check surface), `guardrail`
  (registry/boundary), `property`.
- **RED vs GREEN.** Most behavior here is unbuilt: tests that assert
  ceiling-filtering, pending ingress for above-ceiling bytes, version buckets,
  render-at-ceiling, and expired-out are **RED** against the current tree and
  *define* the target behavior. Tests that extend existing guardrails (tag
  uniqueness, registry shape, projector purity) are **GREEN** today.
- The six invariants are defined in Part I above §1:
  (1) visibility, (2) rendering uniformity, (3) ceiling monotonicity,
  (4) replay determinism, (5) readers-forever / transport-[floor,head],
  (6) safety floor.

## Inventory corrections (verified against the code)

This matrix is grounded in a direct read of `src`. Corrections to earlier notes,
now reflected throughout:

- `MATCH_COMMANDS` has **47** commands; `key-rotate-recipient` maps to run fn
  `key_recipient_rotation`.
- The replay CLI surface (`replay`, `state-summary`, `replay-check`,
  `intent-registry`, `recurring-intents`) is in `src`.
- There are **43** routed fact-family `authenticate.rs` files and **47**
  `FACT_ROUTES` entries. The four extra routed tags are sealed transit carriers:
  sealed bootstrap request/response (46/47) and sealed connection
  request/response (56/57).
- The unknown-tag error is in `core/projectors.rs` at
  `RouterProjector::project`; future versioning must gate unsupported input
  before that projection dispatch for above-ceiling tags.
- `HANDLER_ROUTES` has **17** routes. `runs_during_replay` and recurrence are
  real metadata; `intro_version` is the missing versioning field.
- All tag numbers, the handler inventory, `content::purge` context-only status,
  the absence of `auth::user_profile_v2`, and the TRNS AEAD layout were verified
  correct.

Sections 1–18 are the test clusters; §19 is the adversarial completeness-pass
additions (two rounds); §20 is the coverage matrix over the cross-product.

---

## 1. Version space & ceiling computation

> Cluster CEIL. Source model: `docs/research/Part I above`
> ("Four Separations" §1, "Why This Holds", "Implementation Shape"). The
> ceiling/manifest/trusted-time machinery is **target policy, not yet shipped**
> (doc Status §; inventory §6 confirms no `ceiling`, `ReleaseManifestEntry`,
> `supported_protocol`, `trusted_time`, `expires_at`, `warn_after`,
> `intro_version`, security-deprecation, or blocked-mode strings exist in
> `src/**`). So most CEIL tests are *forward specs* for the
> `ReleaseManifestEntry` ceiling function the doc names at lines 521-536:
>
> ```rust
> pub struct ReleaseManifestEntry {
>     pub release_id: ReleaseId,
>     pub supported_protocol: RangeInclusive<u32>,
>     pub warn_after: TrustedTime,
>     pub expires_at: TrustedTime,
>     pub signature: ProviderSignature,
> }
> // ceiling = min over still-usable releases of supported_protocol.end(),
> // evaluated at trusted_time + skew margin M.
> ```
>
> Per the brief's inventory the entry also carries a `platform` field (multi-
> platform blockers, CEIL-19..22). The struct as printed in the doc omits it;
> tests that need it name it `entry.platform` and flag the gap.
>
> Real entities these tests touch when they assert concrete behavior:
> `con` CLI (`src/main.rs`, `MATCH_PROTOCOL` app.rs:39); the message family
> `content::message` (tag 50) and its `intro_version` as the canonical
> ceiling-gated capability; `connection::frame_*` carriers (tags 168/169/170)
> for the transport-capacity coupling; `RouterProjector::project`
> (projectors.rs:448) whose unknown-tag `Err` at projectors.rs:456 is the
> *today* behavior the model replaces with admission/pending; the registry
> `FACT_ROUTES`/`MATCH_COMMANDS` (registry.rs).

### CEIL-01 — ceiling is min over still-usable releases of supported_protocol.end() `property`
- **Setup:** Manifest with three still-usable releases (none past `expires_at`, none security-deprecated) at trusted_time `t`: rel-desktop `supported_protocol = 1..=7`, rel-mobile `1..=6`, rel-web `1..=7`. Skew margin `M`; `t` well before every `expires_at`.
- **Action:** Compute the production ceiling = `min` over still-usable releases of `supported_protocol.end()` evaluated at `t + M`.
- **Expect:** ceiling == 6 (the min of {7,6,7}), not 7 and not the local binary's head. Property holds for any permutation of the three entries (order-independent input).
- **Defends:** "One ceiling" rule (separation 1); ceiling = greatest version every still-usable release supports.
- **Refs:** `ReleaseManifestEntry.supported_protocol` (doc:521-536); `MATCH_PROTOCOL` app.rs:39.

### CEIL-02 — empty still-usable set / single release degenerate ceilings `property`
- **Setup:** (a) manifest with exactly one still-usable release `1..=5`; (b) manifest where every release is past `expires_at` at `t+M`.
- **Action:** Compute ceiling for each.
- **Expect:** (a) ceiling == 5 (min over a singleton == that release's `end()`). (b) no still-usable release exists: the client must NOT advance to an unbounded ceiling — it treats the local self-release as the only still-usable member (a client is always still-usable to itself until its own `expires_at`), so ceiling == the local release's `supported_protocol.end()`, never `u32::MAX`.
- **Defends:** "One ceiling" boundary; ceiling never floats free of a concrete supporting release.
- **Refs:** `ReleaseManifestEntry` (doc:521-536).

### CEIL-03 — ceiling holds at the blocker's end() while the blocker is still usable `property`
- **Setup:** rel-old `1..=6` with `expires_at = T`; rel-new `1..=7`; capability C = `content::message` v2 introduced at `intro_version = 7`. trusted_time `t < T` (well inside `T`, so `t + M < T`).
- **Action:** Compute ceiling and ask whether C is producible.
- **Expect:** ceiling == 6; C (intro 7) is above ceiling, dormant; local creation of a C-fact is refused.
- **Defends:** "Expiry-driven advance"; capability dormant while its blocker is still usable.
- **Refs:** worked timeline (doc:94-100); `content::message` tag 50.

### CEIL-04 — ceiling advances exactly at trusted_time > expires_at + M `property`
- **Setup:** Same as CEIL-03. rel-old `1..=6` `expires_at = T`; rel-new `1..=7`; M = skew margin. capability C intro 7.
- **Action:** Evaluate ceiling at three trusted times: (a) `t = T`; (b) `t = T + M` (boundary, NOT strictly greater); (c) `t = T + M + 1`.
- **Expect:** (a) ceiling == 6 (blocker still usable). (b) ceiling == 6 — advance requires strictly `> expires_at + M`, the boundary itself does not advance. (c) ceiling == 7 — rel-old no longer still-usable, min over {7} == 7, C becomes producible.
- **Defends:** "Skew margin" / property 2 ("emit is time-gated"); advance only at `trusted_time > expires_at + M` and NOT before, including not at the exact boundary.
- **Refs:** "Skew margin" (doc:278-279); "Why This Holds" 2 (doc:264-265).

### CEIL-05 — advance does not occur one tick early (off-by-one guard) `guardrail`
- **Setup:** rel-old `1..=6` `expires_at = T`; M fixed. trusted_time stepped from `T+M-2` to `T+M`.
- **Action:** For each integer trusted_time in `[T+M-2, T+M]` compute the ceiling.
- **Expect:** ceiling == 6 for every value in the closed interval `[T+M-2, T+M]`; it only flips to 7 at `T+M+1`. No value at or below `T+M` advances.
- **Defends:** Guards the boundary against `>=` vs `>` regression; "and not before" clause of separation 1.
- **Refs:** "Skew margin" (doc:278-279); ceiling formula (doc:534-536).

### CEIL-06 — ceiling is monotonic non-decreasing across manifest updates `property`
- **Setup:** Start ceiling computed == 6 from a manifest. Stream of signed manifest deltas (each "only raises knowledge" per doc:530): add later release entries, extend `expires_at` values, add a higher-supporting release.
- **Action:** Apply each delta in arbitrary order, recompute ceiling after each.
- **Expect:** the recorded ceiling sequence is non-decreasing — no delta lowers it. A signed delta that only adds knowledge can raise or hold the ceiling, never drop it.
- **Defends:** Invariant (3) CEILING MONOTONICITY; "Later entries ... only raise knowledge" (doc:530).
- **Refs:** `ReleaseManifestEntry` monotonic union (doc:519-536).

### CEIL-07 — ceiling rises monotonically as blockers expire one by one `property`
- **Setup:** Three blockers: rel-A `1..=4` `expires_at=T1`, rel-B `1..=5` `expires_at=T2`, rel-C `1..=6` `expires_at=T3`, with `T1<T2<T3`; plus rel-head `1..=7`. Capabilities at intro 5,6,7.
- **Action:** Advance trusted_time past `T1+M`, then `T2+M`, then `T3+M`; recompute ceiling at each step.
- **Expect:** ceiling sequence == 4 → 5 → 6 → 7, strictly increasing as each blocker drops out; never decreases at any intermediate step.
- **Defends:** Invariant (3); "with the monotonic train, this gate keeps the ceiling non-decreasing" (doc:150).
- **Refs:** "Expiry-driven advance" (doc:138-145).

### CEIL-08 — re-evaluation after a backward manifest input never lowers the ceiling `guardrail`
- **Setup:** Ceiling == 7 from a manifest where rel-old already expired. A replayed/older signed manifest snapshot arrives that still lists rel-old as not-yet-expired (an apparently-regressive observation).
- **Action:** Feed the older snapshot into the monotonic union and recompute.
- **Expect:** ceiling stays 7. The monotonic union takes the max-knowledge view (latest signed `expires_at` observed is authoritative, doc:296); a stale lower snapshot cannot resurrect rel-old as a blocker.
- **Defends:** Invariant (3); "treat the latest signed `expires_at` they have observed ... as authoritative" (doc:296).
- **Refs:** monotonic union (doc:530, 296).

### CEIL-09 — no-regression: production build dropping a ceiling-active capability is refused `guardrail`
- **Setup:** Ceiling-active capability set includes `content::message` v2 (intro 7); current ceiling == 7. A candidate **production** release declares `supported_protocol = 1..=6` (drops support for the intro-7 capability).
- **Action:** Validate the candidate release against the no-regression gate for the `production` channel.
- **Expect:** REFUSED for production — the release would become a new blocker and could lower the ceiling, a visibility violation for its own users. The gate rejects it; the release does not enter the production manifest.
- **Defends:** Invariant (3) no-regression gate (separation 1, doc:146-150).
- **Refs:** "No regression" (doc:146-150); `MATCH_PROTOCOL` production channel.

### CEIL-10 — no-regression: same dropping build is ALLOWED for alpha `guardrail`
- **Setup:** Same candidate as CEIL-09: `supported_protocol = 1..=6` against a ceiling-active set requiring intro 7.
- **Action:** Validate the candidate against the gate for the `alpha` channel.
- **Expect:** ALLOWED for alpha — "Such a build may ship only to alpha." It is admitted to the alpha/dogfood/test surface but never registered in the production manifest, so it cannot become a production blocker.
- **Defends:** Invariant (3); "Alpha isolation" (doc:159-166); the production-vs-alpha scope split is a property of the build, not the workspace.
- **Refs:** "No regression" / "Alpha isolation" (doc:146-166).

### CEIL-11 — no-regression scope split is per-build, not per-workspace `guardrail`
- **Setup:** An alpha build (`1..=6`, dropping intro-7) and a production build (`1..=7`) share one workspace; ceiling == 7.
- **Action:** Have the alpha build emit an above-its-support fact and observe the production build.
- **Expect:** The alpha build is not added to the production still-usable set, so it does NOT pull the workspace ceiling down to 6; the production build keeps ceiling 7 and drops/refuses the alpha build's above-ceiling facts as protocol input. The distinction is build-channel, not workspace membership.
- **Defends:** Invariant (3); "Alpha isolation ... a property of the build, not the workspace" (doc:159-162).
- **Refs:** "Alpha isolation" (doc:159-166).

### CEIL-12 — security-deprecation recomputes the ceiling UPWARD `property`
- **Setup:** Still-usable set {rel-old `1..=6`, rel-new `1..=7`}; ceiling == 6; rel-old has NOT yet reached `expires_at`. A signed `must_update` canary marking rel-old security-deprecated arrives.
- **Action:** Apply the canary, recompute the still-usable set and ceiling.
- **Expect:** rel-old leaves the still-usable set immediately (before its `expires_at`); ceiling recomputes to `min` over {rel-new} == 7. The intro-7 capability becomes ceiling-active. Ceiling moved UP as a result of a deprecation.
- **Defends:** Invariant (3) directionality; "Security-deprecation is the deliberate exception. A `must_update` canary removes a release from the still-usable set early" (doc:285-289); separation 2 (doc:177-182).
- **Refs:** `must_update` canary (doc:177-182, 533-534).

### CEIL-13 — security-deprecating the head release does NOT lower the ceiling below emitted facts `guardrail`
- **Setup:** Still-usable {rel-old `1..=6`, rel-new `1..=7`}; ceiling == 7 (rel-old already expired). A `must_update` canary now deprecates rel-new (the head).
- **Action:** Apply the canary; recompute on a client running rel-new.
- **Expect:** The deprecated client itself enters blocked mode (stops shared production, separation 2), but the *computed ceiling for still-usable peers* is unaffected by removing an already-counted higher release — it does not regress below 7 for clients that already emitted intro-7 facts. A deprecation can only remove a member, raising or holding the min, never lowering it.
- **Defends:** Invariant (3); separations 2 and 3 ("Blocking a release never invalidates the historical facts it wrote", doc:185-186).
- **Refs:** separation 2 (doc:168-186); "Why This Holds" (doc:285-289).

### CEIL-14 — capability dormant while a still-usable non-capable release exists, even though binary has the code `blackbox-cli`
- **Setup:** Build a `con` binary whose code includes a new ceiling-gated capability C (e.g. a hypothetical higher `content::message` version at intro 7), but the local manifest has rel-old `1..=6` still usable (ceiling == 6).
- **Action:** Invoke the `con` command that would create a C-fact (e.g. `send` resolving to the intro-7 run-fn bucket) under production.
- **Expect:** REFUSED — local creation of an above-ceiling fact is refused; the binary carries C's code but production must not register C's reader/projector/command path. The `send` command resolves to the highest `intro_version <= ceiling (6)` bucket, never the intro-7 bucket.
- **Defends:** Invariant (1) VISIBILITY; "A binary may contain future protocol code, but production must not register that reader, projector, or command path until the capability is ceiling-active" (doc:128-131); CLI bucket selection ("ceiling selects the highest intro_version<=ceiling").
- **Refs:** `MATCH_COMMANDS` `send`→`send` run fn (registry.rs); `content::message` tag 50; "Protocol ceiling" (doc:125-137).

### CEIL-15 — that dormant capability activates exactly when the last non-capable release expires `blackbox-cli`
- **Setup:** Continue CEIL-14: same `con` binary; rel-old `1..=6` `expires_at=T`; rel-head `1..=7`; capability C intro 7.
- **Action:** Advance trusted_time past `T+M`; re-run the C-creating `con` command.
- **Expect:** Now ACCEPTED — ceiling == 7, C is ceiling-active (intro 7 <= 7), the run-fn bucket for intro-7 is selected, the C-fact is created and admitted in production.
- **Defends:** Invariant (1); "New shared durable fact versions become producible and admissible only when the ceiling reaches them" (doc:136-137).
- **Refs:** worked timeline (doc:94-100); `content::message` tag 50.

### CEIL-16 — dormant capability remains dormant if ANY one of several non-capable releases is still usable `property`
- **Setup:** Two non-capable blockers rel-A `1..=6` `expires_at=T1` and rel-B `1..=6` `expires_at=T2` with `T1<T2`; rel-head `1..=7`; capability C intro 7.
- **Action:** Advance trusted_time past `T1+M` but before `T2+M`; recompute ceiling and C activation.
- **Expect:** ceiling == 6 still — rel-B is still usable. C stays dormant. Only when trusted_time passes `T2+M` (the LAST non-capable release) does ceiling become 7. Activation gated on the max expiry among non-capable releases.
- **Defends:** Invariant (1); "the last still-usable release that cannot ... it expires" (doc:138-140).
- **Refs:** "Expiry-driven advance" (doc:138-145).

### CEIL-17 — ceiling-active requires BOTH intro_version<=ceiling AND transportable by every still-usable carrier `property`
- **Setup:** ceiling == 7 (every still-usable release supports protocol 7). Capability C = a new large `content::file` descriptor variant at intro 7 whose byte size EXCEEDS the SMALL frame plaintext capacity (`CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES = 4 KiB`) and a still-usable release's only carrier is `connection::frame_small`.
- **Action:** Evaluate ceiling-active for C: check both `intro_version (7) <= ceiling (7)` AND "every still-usable release can transport it".
- **Expect:** C is NOT ceiling-active despite `intro<=ceiling` — the transport leg fails because a still-usable carrier cannot move C's byte size. Both conjuncts are required; the version conjunct alone is insufficient.
- **Defends:** Invariant (1) (admissible/projectable/displayable/transportable by every still-usable release); "Carrier capacity gates the ceiling" (doc:468-474); ceiling-active definition (doc:89-92).
- **Refs:** `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` (connection_frame_wire.rs); `content::file` tag 54; ceiling-active glossary (doc:53-54).

### CEIL-18 — ceiling-active when intro<=ceiling AND a chunked (file_slice-precedent) carrier path exists `property`
- **Setup:** Same C as CEIL-17 but now C ships with an old-carrier-compatible chunking path modeled on the `content::file_slice` (tag 55) precedent that fits inside `connection::frame_file_slice` (tag 169) capacity. ceiling == 7.
- **Action:** Re-evaluate ceiling-active for C.
- **Expect:** C IS ceiling-active — `intro (7) <= ceiling (7)` AND every still-usable carrier can transport it via the chunked path. Carrier-capacity precondition satisfied by chunk-don't-grow.
- **Defends:** Invariant (1); "until the new fact family has an old-carrier-compatible chunking path" (doc:470-472); the `file_slice` precedent.
- **Refs:** `connection::frame_file_slice` tag 169, `content::file_slice` tag 55; doc:468-474.

### CEIL-19 — multi-platform blocker: mobile release lacking C holds the ceiling below C on desktop `property`
- **Setup:** Cross-platform manifest: rel-desktop `platform=desktop` `supported_protocol=1..=7`; rel-mobile `platform=mobile` `supported_protocol=1..=6` `expires_at=T`; capability C = `content::message` v2 intro 7. trusted_time `t < T`. Ceiling is min ACROSS ALL PLATFORMS.
- **Action:** Compute the production ceiling on a desktop client.
- **Expect:** ceiling == 6 on desktop even though the desktop release supports 7 — the still-usable mobile release at `1..=6` is the cross-platform blocker. C dormant on desktop. (Test names `entry.platform`; flags that the doc's printed struct omits the field but the brief's inventory and the "ACROSS ALL PLATFORMS" rule require it.)
- **Defends:** Invariant (1); ceiling = min over still-usable releases ACROSS ALL PLATFORMS (model: "CEILING ... ACROSS ALL PLATFORMS, of supported_protocol.end()").
- **Refs:** `ReleaseManifestEntry.platform` (brief inventory; doc:521-536 prints the struct without it); `content::message` tag 50.

### CEIL-20 — multi-platform blocker releases the ceiling on desktop only after the mobile blocker expires `property`
- **Setup:** Continue CEIL-19: rel-mobile `1..=6` `expires_at=T`; rel-desktop `1..=7`.
- **Action:** Advance trusted_time past `T+M`; recompute desktop ceiling.
- **Expect:** ceiling on desktop becomes 7 only after `t > T+M`; C activates on desktop. Until then the mobile blocker holds desktop at 6 — desktop cannot self-advance ahead of a still-usable peer platform.
- **Defends:** Invariant (1); cross-platform expiry-driven advance.
- **Refs:** "Expiry-driven advance" (doc:138-145); `entry.platform`.

### CEIL-21 — desktop-only capability still blocked by a non-capable mobile release (no per-platform ceiling) `property`
- **Setup:** Capability C is only ever *used* on desktop, but it is a shared durable fact (`content::message` v2). rel-mobile `1..=6` still usable; rel-desktop `1..=7`. The policy is a single GLOBAL ceiling, not per-platform.
- **Action:** Ask whether desktop may emit C while mobile is still usable.
- **Expect:** NO — desktop must not emit C. The policy "uses a global production protocol ceiling, not per-workspace or per-peer readiness" (doc:36-40); a still-usable mobile peer could receive C and fail to display it, violating visibility. No per-platform ceiling exemption.
- **Defends:** Invariant (1); "global production protocol ceiling, not per-workspace or per-peer readiness" (doc:36-40).
- **Refs:** doc:36-40; ceiling-active glossary (doc:53-54).

### CEIL-22 — multi-platform security-deprecation of the mobile blocker raises desktop ceiling upward `property`
- **Setup:** rel-mobile `platform=mobile` `1..=6` (not yet at `expires_at`); rel-desktop `1..=7`; ceiling on desktop == 6. A `must_update` canary deprecates the mobile release.
- **Action:** Apply the canary; recompute desktop ceiling.
- **Expect:** mobile leaves still-usable set; desktop ceiling recomputes to 7 (min over {rel-desktop}); C activates on desktop. Upward recompute driven by cross-platform deprecation.
- **Defends:** Invariant (3) directionality across platforms; security-deprecation exception (doc:285-289).
- **Refs:** `must_update` (doc:177-182); `entry.platform`.

### CEIL-23 — grace-window extension BEFORE the original deadline keeps the ceiling held `property`
- **Setup:** Blocker rel-old `1..=6` `expires_at=T`; rel-head `1..=7`; capability C intro 7. A signed manifest delta extends rel-old's `expires_at` to `T2 > T`, and the extension reaches the capable producer (rel-head) at trusted_time `t_ext < T` (before the ORIGINAL deadline).
- **Action:** Advance trusted_time across the original `T+M`; recompute ceiling and check C on the capable producer.
- **Expect:** ceiling stays 6 across `T+M` (producer honors the extended `expires_at=T2`); C remains dormant until `t > T2+M`. The grace extension is honored because it arrived before the original deadline — no producer raises the ceiling while the extended blocker is still live.
- **Defends:** Invariant (1)/(3); "A grace extension is only safe if it reaches every capable producer before the original deadline" (doc:144-145, 291-296).
- **Refs:** "Expiry-driven advance" (doc:144-145); "Grace windows" (doc:291-296).

### CEIL-24 — grace-window extension AFTER the original deadline cannot un-advance an already-raised ceiling `guardrail`
- **Setup:** Blocker rel-old `1..=6` `expires_at=T`. A capable producer (rel-head `1..=7`) embedded the ORIGINAL `expires_at=T` and never saw an extension before `T`. trusted_time crosses `T+M`; producer raises ceiling to 7 and emits a C-fact (intro 7). THEN a late signed delta arrives extending rel-old to `T2 > T`.
- **Action:** Apply the late extension; recompute ceiling on the producer.
- **Expect:** ceiling does NOT regress to 6 — monotonicity forbids it (CEIL-06); the already-emitted intro-7 fact must stay visible. The late extension is recorded but cannot un-advance. This is the unsafe-grace case the doc warns about: an extension that does not reach a producer before the original deadline produces a window where a producer raised the ceiling while the extended blocker is still live — the model's mitigation is monotonicity + propagation margin, NOT rollback.
- **Defends:** Invariant (3) monotonicity as the backstop for an unsafe grace extension; "otherwise a producer that embedded the original deadline raises the ceiling while the extended blocker is still live" (doc:293-294).
- **Refs:** "Grace windows" (doc:291-296); monotonic union (CEIL-06).

### CEIL-25 — warn_after has NO ceiling effect; only expires_at moves the ceiling `property`
- **Setup:** Blocker rel-old `1..=6` `warn_after=W`, `expires_at=T`, with `W < T`; rel-head `1..=7`; capability C intro 7.
- **Action:** Advance trusted_time across `W` (past warn_after) but keep it below `T`; recompute ceiling.
- **Expect:** ceiling stays 6 — crossing `warn_after` only triggers the update prompt and keeps full shared production; it does NOT remove rel-old from the still-usable set and does NOT advance the ceiling. C stays dormant. Only crossing `expires_at+M` advances.
- **Defends:** Invariant (1); separation 2 "`warn_after` ... has no protocol effect" (doc:172-176).
- **Refs:** `ReleaseManifestEntry.warn_after` (doc:524); separation 2 (doc:170-176).

### CEIL-26 — pure read-model change is NOT ceiling-gated and never moves the ceiling `property`
- **Setup:** A change that touches only read-model row/index shape for `content::message` (no fact-format change, no new tag, same `intro_version`). Manifest unchanged; ceiling == 6.
- **Action:** Compute the ceiling and ask whether the row-shape change requires waiting for any blocker.
- **Expect:** ceiling unchanged at 6; the read-model change is free — wipe-and-replay rebuilds rows from retained facts under the new schema; no ceiling gate, no new capability, no `intro_version` bump. (Negative control: not every code change is a ceiling capability.)
- **Defends:** Invariant (2) RENDERING UNIFORMITY / separation 4 "Pure read-model changes are free" (doc:248-252); separation 1 capability definition (only a new fact family or incompatible change is a capability).
- **Refs:** "Pure read-model changes are free" (doc:248-252); `content::message` rows (registry.rs read_models).

### CEIL-27 — ceiling is computed locally and is not negotiated over the wire `guardrail`
- **Setup:** Two peers A (manifest gives ceiling 6) and B (manifest gives ceiling 7, B has seen more recent signed deltas) connected on an authenticated session.
- **Action:** A and B exchange facts; observe each side's effective ceiling. Provide no protocol message that sets a "negotiated ceiling".
- **Expect:** Each client uses ITS OWN locally-computed ceiling (A=6, B=7) from manifest+trusted_time; there is no on-wire field that overrides it. B refuses to lower to A's ceiling and A refuses to raise to B's via negotiation; A drops/refuses B's above-A's-ceiling facts until a later resend after A's ceiling rises. "The ceiling ... is computed locally by each client ... it is not negotiated."
- **Defends:** Invariant (1); "The ceiling is computed locally by each client from the manifest and trusted time; it is not negotiated" (doc:130-131).
- **Refs:** doc:130-131; transport vs ceiling separation (doc:103-118).

### CEIL-28 — ceiling = min(end) holds when ranges are non-uniform but overlapping `property`
- **Setup:** Still-usable releases with floors and heads that differ: rel-A `3..=6`, rel-B `1..=7`, rel-C `2..=6`, rel-D `4..=8`. All still usable at `t+M`.
- **Action:** Compute ceiling.
- **Expect:** ceiling == 6 == `min(6,7,6,8)` of the `end()` values; floors do not affect the ceiling (the ceiling is a function of `supported_protocol.end()` only, per the formula `min ... of supported_protocol.end()`). The result is well-defined as long as some common version exists in every range (here 4..=6 overlaps all).
- **Defends:** Invariant (1); ceiling formula exactly `min over still-usable of supported_protocol.end()` (doc:534-536).
- **Refs:** ceiling formula (doc:534-536).
## 2. Trusted time & blocked mode

> **Grounding note (read before authoring).** Verified against `/home/holmes/poc-10/src`
> on commit `bb87049`: the **only** time primitive that exists today is the
> store-local logical clock in `src/core/clock.rs` (CLI command `clock`, run fn
> `clock` in `MATCH_COMMANDS`, owner `crate::core::clock`/`CLOCK_USAGE`). It is a
> *lower bound* for the next authored timestamp (`next_timestamp`), explicitly
> documented as **not protocol data and not synced** (clock.rs:1-10). The only
> wire/fact that records an observed time is `connection::frame_observation`
> (tag `173`, `TYPE_CONNECTION_FRAME_OBSERVATION`, field `received_at_local_ms:
> u64be` — `frame_observation/layout.rs:9-11,26-30`), a *local* receive fact, and
> the daemon's `current_wall_clock_ms` (`app.rs:78-83`, raw `SystemTime::now()`).
> `trusted_time`, `ReleaseManifestEntry`, `supported_protocol`, `warn_after`,
> `expires_at`, the protocol *ceiling*, *blocked mode*, *staleness block*, skew
> margin `M`, and staleness window `S` are **specified in
> `docs/research/Part I above` (rules 1-3, 10) but NOT yet
> implemented** (grep of `src/**/*.rs` finds none of these symbols; the one
> `ceiling` hit is integer-division arithmetic in `content/file/project.rs:277`).
>
> Therefore the cluster is split. Tests prefixed *as `blackbox-cli`/`projector-unit`/
> `handler-unit`/`property` against `clock`/`frame_observation`/`next_timestamp`*
> exercise shipped behavior. Tests marked `guardrail` are **spec-anchoring /
> scaffolding** tests: they assert the proposed entity exists with the named
> shape and the named invariant, and are expected to FAIL-as-RED until the
> trusted-time/ceiling subsystem is built. Each guardrail names the exact
> design-doc rule it defends so it is implementable the moment the type lands.
> The `{new,old}` version axis and per-scope axis are enumerated explicitly where
> they intersect (ceiling-advance gating spans scopes; blocked-mode creation
> refusal spans fact families).

---

### TIME-01 — logical clock is a lower bound, never overrides a larger observed authored max  `projector-unit`
- **Setup:** fresh in-memory `Store` opened with `CORE_SCHEMA_SOURCE` (mirrors `clock.rs` unit-test harness). No clock row set.
- **Action:** call `core::clock::next_timestamp(&store, 7)`; then `set_logical_time(&store, 100)`; then `next_timestamp(&store, 7)` and `next_timestamp(&store, 125)`.
- **Expect:** returns `8`, then `100`, then `126`. The logical clock raises the floor (when 100 > 7+1) but a larger observed authored max (125) still wins via `from_observed.max(...)`.
- **Defends:** trusted/local time is a LOWER BOUND on the next authored time, never a source of truth that rewinds past observed facts (model: "TRUSTED TIME = ... a lower bound on real time").
- **Refs:** `src/core/clock.rs` `next_timestamp` (76-79), `logical_time` (21-31), existing test `clock_is_a_lower_bound_for_next_timestamp` (141-151).

### TIME-02 — `clock set` to a SMALLER value does not regress the next authored timestamp below observed max  `blackbox-cli`
- **Setup:** built `con` binary, store seeded with at least one shared fact whose authored timestamp = 1000 (e.g. `con send` once after `clock set 1000`).
- **Action:** `con clock set 5` then read `con clock`.
- **Expect:** `con clock` output lines show `logical_time: 5`, `max_observed_timestamp: 1000` (or higher), and `next_timestamp: 1001` — the smaller logical value is stored but the next authored timestamp is still driven by the observed max, never `< observed_max+1`.
- **Defends:** "trusted time only increases" semantics for the AUTHORING path — a smaller (signed/local) observation cannot pull the next-issued time below what we already observed.
- **Refs:** `clock` command (`MATCH_COMMANDS`), `run_cli`/`apply_cli_args` (clock.rs:82-125), `next_timestamp` (76-79).

### TIME-03 — `clock advance` accumulates monotonically and never decreases  `blackbox-cli`
- **Setup:** built `con`, fresh store, no clock set.
- **Action:** `con clock advance 5`, then `con clock advance 7`, then read `con clock`.
- **Expect:** stored `logical_time` = `12`; there is NO CLI verb that subtracts (only `set|advance|clear`); `advance` overflow on `u64` errors with `"logical clock advance overflows u64"` rather than wrapping down.
- **Defends:** the only monotonic-increase primitive that exists — advance is additive-only, mirroring "trusted time only increases" at the local layer.
- **Refs:** `advance_logical_time` (clock.rs:51-57), `CLOCK_USAGE = "clock [set TIMESTAMP|advance DELTA|clear]"` (18), existing test `advance_and_clear_are_store_local` (153-165).

### TIME-04 — `clock clear` returns to unset; lower bound falls back to observed-max+1  `blackbox-cli`
- **Setup:** built `con`, `con clock set 100` already applied, no shared facts authored yet (observed max = 0).
- **Action:** `con clock clear` then `con clock`.
- **Expect:** `logical_time: unset`, `next_timestamp: 1` (observed_max 0 saturating_add 1). Clearing removes the floor; it does not crash and does not leave a stale 100.
- **Defends:** REPLAY DETERMINISM-adjacent — local clock is store-local scaffolding, freely clearable, not durable protocol state (clock.rs:1-10 doc contract).
- **Refs:** `clear_logical_time` (clock.rs:60-69), `next_timestamp` saturating_add (77).

### TIME-05 — `frame_observation` fact records an observed receive-time and round-trips fixed-width  `projector-unit`
- **Setup:** construct `ConnectionFrameObservationFact { frame_fact_id:[1;32], origin_addr:127.0.0.1:41001, received_at_local_ms:123 }`.
- **Action:** `encode_fact` then `decode_fact` (tag 173 path).
- **Expect:** encoded length == `CONNECTION_FRAME_OBSERVATION_FACT_BYTES` (= 1 + 32 + OriginAddr slot + 8); decode yields the identical struct; `received_at_local_ms` survives as `u64be` at `RECEIVED_AT_OFFSET`.
- **Defends:** the observed-time field is a stable wire-versioned fact (tag 173), the substrate any future "signed observation" would extend; the time slot is a real fixed 8-byte BE field, not implicit.
- **Refs:** `frame_observation/layout.rs:9-54`, existing test `connection_frame_observation_roundtrips_fixed_width` (64-76); inventory §4.

### TIME-06 — `frame_observation` is LOCAL-only: not in shared/transportable path, observed time stays a lower bound, not authoritative  `guardrail`
- **Setup:** registry inventory — `connection::frame_observation` (173) is routed in `FACT_ROUTES` but, per model, frame_observation "does NOT carry a frame ciphertext; it references the frame fact id" and is a *local receive* record.
- **Action:** assert (registry/guardrail) that `connection::frame_observation` is NOT among the shared-durable families that gate the ceiling, and that `received_at_local_ms` is sourced from the local receive path (`app.rs` `InboundNetworkFrame.received_at_local_ms`), never trusted as global time.
- **Expect:** the fact projector emits a local row/index only; no read-model treats `received_at_local_ms` as trusted_time; deletion/clearing it does not change any shared row's authored time.
- **Defends:** distinction between LOCAL observed time and TRUSTED TIME — observed local receive time must never be promoted to a global lower bound that gates production.
- **Refs:** `frame_observation/{fact,project,create}.rs`, `app.rs:62-71` (`received_at_local_ms: input.received_at_local_ms`), inventory §4.

### TIME-07 — daemon wall clock is raw `SystemTime::now()` with no monotonic/trusted guard today (RED baseline)  `guardrail`
- **Setup:** read `current_wall_clock_ms` (`app.rs:78-83`).
- **Action:** assert the current implementation calls `SystemTime::now().duration_since(UNIX_EPOCH)` directly with no comparison against a persisted greatest-trusted-time and no blocked-mode short-circuit.
- **Expect:** test documents/asserts the present unguarded behavior; once trusted time lands this guardrail flips to require `current_wall_clock_ms` (or its replacement) to be clamped to `max(persisted_trusted_time, now)` and to refuse on rollback.
- **Defends:** establishes the gap the trusted-time subsystem must close (design rule 3: "If the local clock rolls backward too far, shared production use blocks").
- **Refs:** `app.rs:78-83`, design doc rule 3 (Part I above).

### TIME-08 — trusted_time persists the GREATEST value seen; a smaller signed observation is ignored  `guardrail`
- **Setup:** (proposed) a persisted `trusted_time: u64` initialized from a signed observation at T=1000.
- **Action:** feed a second signed observation carrying T=400 (smaller).
- **Expect:** persisted `trusted_time` stays `1000` (monotonic max); the 400 observation is accepted-but-ignored for the time floor (it must not lower trusted_time).
- **Defends:** invariant "TRUSTED TIME = monotonic max of signed observations" — smaller signed obs ignored.
- **Refs:** design doc rule 3 (55-58); proposed `trusted_time` store key (parallel to `CLOCK_KEY` in clock.rs:16).

### TIME-09 — trusted_time advances when a LARGER signed observation arrives  `guardrail`
- **Setup:** (proposed) persisted `trusted_time = 1000`.
- **Action:** feed a signed observation carrying T=2000 (larger, signature valid).
- **Expect:** persisted `trusted_time` becomes `2000`; the advance is durable across restart.
- **Defends:** "monotonic max" — strictly larger signed observations raise the floor.
- **Refs:** design doc rule 3 (55-58); shape mirrors `set_logical_time`/`advance_logical_time` (clock.rs:37-57) but gated on signature.

### TIME-10 — trusted_time learned from EMBEDDED RELEASE METADATA (source 1)  `guardrail`
- **Setup:** (proposed) running binary whose embedded `ReleaseManifestEntry` carries a build/sign timestamp; no signed registry facts, no canary yet.
- **Action:** start the client cold (empty store) so the only time source is embedded metadata.
- **Expect:** `trusted_time` initializes to the embedded-metadata timestamp (a release cannot be older than its own build/sign time), and that value becomes the lower bound for ceiling evaluation.
- **Defends:** design rule 3 — "Clients persist the greatest trusted time learned from **embedded release metadata**, signed registry facts, or signed canaries." (source 1 of 3).
- **Refs:** design doc rule 3 (55-58); proposed `ReleaseManifestEntry{release_id,platform,supported_protocol,warn_after,expires_at,signature}`.

### TIME-11 — trusted_time learned from a SIGNED REGISTRY FACT (source 2) raises it above embedded metadata  `guardrail`
- **Setup:** (proposed) `trusted_time` initialized from embedded metadata at T=1000.
- **Action:** admit a signed registry fact (the fleet-wide signed manifest distribution) whose authored/observation time is T=1500, signature valid.
- **Expect:** `trusted_time` rises to `1500`; an unsigned or bad-signature registry fact is rejected and leaves `trusted_time` unchanged.
- **Defends:** design rule 3 source 2 (signed registry facts); only SIGNED facts move trusted time.
- **Refs:** design doc rule 3; the manifest is a "FLEET-WIDE signed manifest" (model) / "signed registry facts" (rule 3).

### TIME-12 — trusted_time learned from a SIGNED CANARY (source 3) and a canary can security-deprecate a release  `guardrail`
- **Setup:** (proposed) `trusted_time` from prior sources at T=1500; a release R is otherwise not-yet-expired.
- **Action:** admit a signed canary carrying observation time T=1600 AND a `must_update`/security-deprecation marker for release R.
- **Expect:** `trusted_time` rises to `1600`; release R is marked security-deprecated and is dropped from the still-usable set (so it no longer caps the ceiling); an unsigned canary moves neither time nor deprecation.
- **Defends:** design rule 3 source 3 (signed canaries) + "security-deprecated by canary" (rule 1) + Security Changes "must_update canary" (doc:90-95).
- **Refs:** design doc rules 1 & 3, Security Changes section (90-102).

### TIME-13 — three time sources reconcile to the single greatest value (source-independent max)  `property`
- **Setup:** (proposed) embedded metadata=Tm, signed registry fact=Tr, signed canary=Tc, applied in any of the 6 orderings.
- **Action:** apply all three signed observations in a randomized order (seeded).
- **Expect:** resulting `trusted_time == max(Tm,Tr,Tc)` regardless of application order; idempotent on replay of the same set.
- **Defends:** monotonic-max is order-independent (echoes REPLAY DETERMINISM "order-independent") and source-agnostic.
- **Refs:** design doc rule 3; property analog of clock.rs `next_timestamp` max-fold.

### TIME-14 — backward clock jump WITHIN tolerance does not block  `guardrail`
- **Setup:** (proposed) `trusted_time = 10_000`; rollback tolerance configured (e.g. small skew allowance); local `SystemTime::now()` returns `9_999` (within tolerance of trusted_time).
- **Action:** evaluate mode on the next tick.
- **Expect:** client stays in NORMAL mode; shared production creation still allowed; `trusted_time` is NOT lowered (stays 10_000).
- **Defends:** design rule 3 — only a rollback *too far* blocks; small skew is tolerated; trusted_time still monotonic.
- **Refs:** design doc rule 3 (55-58); model "backward clock jump beyond tolerance => blocked".

### TIME-15 — backward clock jump BEYOND tolerance enters BLOCKED MODE  `guardrail`
- **Setup:** (proposed) `trusted_time = 10_000_000`; local `SystemTime::now()` returns a value far below trusted_time minus tolerance (implausible rollback).
- **Action:** evaluate mode on the next tick / next shared-create attempt.
- **Expect:** client enters BLOCKED MODE; shared production output is withheld; `trusted_time` is not corrupted; mode is surfaced (e.g. a status line / error on create).
- **Defends:** model "backward clock jump beyond tolerance => blocked mode"; design rule 3 "shared production use blocks until time is plausible again."
- **Refs:** design doc rule 3; proposed blocked-mode gate around `current_wall_clock_ms` (app.rs:78-83).

### TIME-16 — STALENESS: no fresh signed observation within window S enters BLOCKED MODE (staleness block)  `guardrail`
- **Setup:** (proposed) last signed observation at T_last; window `S` configured; local time advances past `T_last + S` with no new signed observation.
- **Action:** evaluate mode at `now > T_last + S`.
- **Expect:** client enters BLOCKED MODE — shared production withheld — because it can no longer trust that its ceiling is current.
- **Defends:** model "no refresh within staleness window S => blocked mode (staleness block)".
- **Refs:** design doc rule 3 (trusted-time freshness); proposed staleness window `S`.

### TIME-17 — a fresh signed observation within S keeps NORMAL mode (no false staleness block)  `guardrail`
- **Setup:** (proposed) last signed observation at T_last; window `S`; a NEW valid signed observation arrives at `T_last + (S/2)`.
- **Action:** evaluate mode after the refresh.
- **Expect:** stays NORMAL; the staleness timer resets to the new observation; shared production remains allowed.
- **Defends:** staleness gate must not block a healthy, regularly-refreshing client.
- **Refs:** design doc rule 3; proposed staleness window `S`.

### TIME-18 — LEAVING blocked mode after a fresh, plausible signed observation  `guardrail`
- **Setup:** (proposed) client currently in BLOCKED MODE (from TIME-15 rollback OR TIME-16 staleness).
- **Action:** admit a fresh valid signed observation whose time is plausible (>= trusted_time and within tolerance of local clock; resets staleness window).
- **Expect:** client transitions back to NORMAL mode; shared production creation resumes; no wipe required to leave blocked mode.
- **Defends:** model "leaving blocked mode after a fresh signed observation"; design rule 3 "until time is plausible again."
- **Refs:** design doc rule 3.

### TIME-19 — blocked mode caused by rollback is NOT cleared by a stale/replayed old observation  `guardrail`
- **Setup:** (proposed) client in BLOCKED MODE due to rollback; an OLD signed observation (time < current trusted_time, i.e. a smaller obs) is re-admitted.
- **Action:** admit the smaller/stale signed observation.
- **Expect:** stays BLOCKED; a smaller observation cannot satisfy the freshness/plausibility requirement (consistent with TIME-08 monotonic-max).
- **Defends:** exiting blocked mode requires a genuinely FRESH observation, not replay of an old one; prevents downgrade attacks.
- **Refs:** design doc rule 3; ties to TIME-08.

### TIME-20 — in BLOCKED MODE, local creation of a shared fact is REFUSED — content::message (scope: content)  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE, workspace exists, ceiling covers `content::message` (tag 50).
- **Action:** `con send "hi"`.
- **Expect:** creation refused with a blocked-mode error; NO new `content::message` fact is written; existing messages still readable via `con messages`/`con view`.
- **Defends:** model "in blocked mode creation refused" (shared production withheld); INVARIANT 1/2 protected by not emitting under an untrusted ceiling.
- **Refs:** `content::message` (tag 50), `send`/`messages`/`view` (MATCH_COMMANDS #25/#32/#33); design rule 3.

### TIME-21 — in BLOCKED MODE, local creation refused — content::reaction (scope: content)  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE; a message exists to react to.
- **Action:** `con react <msg> 👍`.
- **Expect:** refused with blocked-mode error; no `content::reaction` (tag 52) fact written.
- **Defends:** blocked-mode creation refusal across the content scope (per-family enumeration).
- **Refs:** `content::reaction` (tag 52), `react` (MATCH_COMMANDS #26).

### TIME-22 — in BLOCKED MODE, local creation refused — content::file / file_slice (scope: content)  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE.
- **Action:** `con send-file ./blob`.
- **Expect:** refused; no `content::file` (54) nor `content::file_slice` (55) facts written; partial-slice authoring does not begin.
- **Defends:** blocked-mode refusal extends to multi-fact (file + slices) shared creation.
- **Refs:** `content::file`/`content::file_slice` (54/55), `send-file` (MATCH_COMMANDS #27).

### TIME-23 — in BLOCKED MODE, local creation refused — auth::workspace / auth::user / auth::admin (scope: auth)  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE.
- **Action:** attempt `con create-workspace`, `con invite`, `con grant-admin`.
- **Expect:** each shared-authority creation is refused with blocked-mode error; no `auth::workspace` (131) / `auth::user_invite` (10) / `auth::admin` (139) facts written. (Purely local secret material setup that is NOT a shared fact is out of scope of this assertion.)
- **Defends:** blocked-mode refusal across the auth scope; authority changes are the most ceiling-sensitive (design doc table line 274).
- **Refs:** `create-workspace`/`invite`/`grant-admin` (MATCH_COMMANDS #1/#2/#34); auth tags 131/10/139.

### TIME-24 — in BLOCKED MODE, local creation refused — sync::shared_fact share path (scope: sync)  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE; a fact exists locally.
- **Action:** attempt to author a new shared advertisement via the `share_fact_with_sync` intent path / `con sync-range`.
- **Expect:** no NEW shared fact is produced under blocked mode (shared production withheld); read-only sync status queries still answer.
- **Defends:** blocked-mode refusal across the sync scope's create surface; distinguishes shared-create from read.
- **Refs:** `sync::shared_fact` (162), `share_fact_with_sync` intent (HANDLER_ROUTES #6), `sync-range`/`sync-status` (MATCH_COMMANDS #38/#39).

### TIME-25 — in BLOCKED MODE, connection-frame create (shared transport authoring) is gated; retirement-before-replay still allowed  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE with an open connection.
- **Action:** attempt to seal/send a new `connection::frame_*` carrying a freshly-authored shared fact; separately issue a `connection::close`/upgrade-retirement.
- **Expect:** sealing a frame that would carry a newly-authored *shared production* fact is withheld; `connection::close` (45) / retirement remains permitted (retire connections before replay is an operational safety action, not shared production).
- **Defends:** model "in blocked mode creation refused" while TRANSPORT "Retire connections ... before replay" still runs; separates production-create from connection lifecycle.
- **Refs:** `connection::frame_small/file_slice/bundle` (168/169/170), `connection::close` (45), `connection_frame_wire.rs`.

### TIME-26 — in BLOCKED MODE, a RECEIVED below-ceiling fact still ADMITS and projects normally  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE; ceiling covers `content::message` (50); a peer sends a normal below-ceiling `content::message`.
- **Action:** deliver the received frame (`receive_network_frame` intent path).
- **Expect:** the received fact is admitted, projected, displayed, counted — blocked mode withholds OUTPUT (production create) only, not INPUT admission. `con messages`/`content-count` reflect it.
- **Defends:** model "in blocked mode ... received-fact admission and replay still run"; INVARIANT 1 (visibility of ceiling-active facts) holds even while blocked.
- **Refs:** `receive_network_frame` intent (HANDLER_ROUTES #12, app.rs:62-72), `content::message` projector (tag 50), `content-count`/`messages`.

### TIME-27 — in BLOCKED MODE, a RECEIVED above-ceiling fact becomes PENDING, not active  `guardrail`
- **Setup:** (proposed) `con` in BLOCKED MODE; ceiling does NOT cover some future tag (e.g. proposed `message:2`); a peer sends that above-ceiling fact.
- **Action:** deliver the received above-ceiling frame.
- **Expect:** if the frame opens and the sender is authorized, the bytes are retained as pending by stable id/hash: no read-model rows, no offers/needs, no forwarding as active protocol truth, and no projection. The current direct-projector unknown-tag error remains a guard; the future admission gate must prevent above-ceiling network input from becoming active protocol truth.
- **Defends:** model "received-fact admission ... still run [in blocked mode]"; ADMISSION pending rule.
- **Refs:** future admission gate before `RouterProjector::project`, ADMISSION model.

### TIME-28 — in BLOCKED MODE, wipe+REPLAY runs to completion and rebuilds derived state  `replay-cli`
- **Setup:** (proposed) `con` in BLOCKED MODE with a populated store and prior above-ceiling inputs retained as pending ingress.
- **Action:** run the wipe+replay path (today: the cascade replay surface `con test-replay-deps-reverse`; conceptually the upgrade replay).
- **Expect:** replay completes, derived rows rebuilt deterministically; replay observes NO fresh time, sends NO frames, signs NO new shared facts (design rule 8); blocked mode does not abort replay. Pending above-ceiling inputs stay inert unless the replay's admission ceiling/context now admits them.
- **Defends:** model "in blocked mode ... replay still run[s]"; INVARIANT 4 (replay deterministic, ceiling-independent); design rule 8.
- **Refs:** `replay`, `replay-check`, `state-summary`, and `test-replay-deps-reverse` replay surfaces.

### TIME-29 — pending above-ceiling input activates on next wipe+replay once the ceiling rises  `replay-cli`
- **Setup:** (proposed) client previously retained a wire-admitted fact with a future tag as pending; client subsequently leaves blocked mode AND ceiling rises (e.g. blocking release expired) to cover that tag.
- **Action:** raise ceiling, then wipe+replay.
- **Expect:** the pending bytes re-enter `authenticate -> adapt -> project`, route to the tag's kept-forever adapter, and project if authentication and semantic context succeed. No network resend is required for bytes already retained as pending.
- **Defends:** ADMISSION pending activation after ceiling rise; INVARIANT 4 (replay determinism over retained facts only).
- **Refs:** ADMISSION model; ceiling-filtered routing by own tag; design rules 4/5.

### TIME-30 — trusted_time as a LOWER BOUND gates ceiling advance with margin M: advance only at trusted_time > blocker.expires_at + M  `guardrail`
- **Setup:** (proposed) one blocking release `R` with `expires_at = E`; skew margin `M`; `trusted_time = E + (M/2)` (past expiry but within skew margin).
- **Action:** evaluate the ceiling.
- **Expect:** the ceiling does NOT advance past `R`'s cap yet (`trusted_time <= E + M`); a capability blocked only by `R` remains NOT ceiling-active; `con` still refuses to create that above-ceiling capability.
- **Defends:** model "Skew margin M: advance the ceiling only at trusted_time > blocker.expires_at + M"; INVARIANT 3 (ceiling monotonicity / no premature regression).
- **Refs:** design rules 1-2 (43-54); proposed `ReleaseManifestEntry.expires_at`, margin `M`.

### TIME-31 — ceiling advances once trusted_time exceeds blocker.expires_at + M  `guardrail`
- **Setup:** (proposed) blocking release `R`, `expires_at = E`, margin `M`; `trusted_time = E + M + 1`.
- **Action:** evaluate the ceiling, then attempt to create the formerly-blocked capability.
- **Expect:** ceiling advances to include the capability whose only blocker was `R`; creation now succeeds (subject to carrier capacity — see TIME-33); advance is monotonic (never retreats on a later equal evaluation).
- **Defends:** model expiry-driven advance with margin M; design rule 2.
- **Refs:** design rules 1-2; proposed ceiling computation = min over still-usable releases of `supported_protocol.end()`.

### TIME-32 — ceiling is min ACROSS ALL PLATFORMS of still-usable releases at trusted_time (multi-platform blocker)  `guardrail`
- **Setup:** (proposed) two `ReleaseManifestEntry` for different platforms: platform A supports protocol up to 7 (`expires_at` far future), platform B supports up to 6 (`expires_at` far future); trusted_time well before any expiry.
- **Action:** compute ceiling.
- **Expect:** ceiling = `6` (min over ALL platforms of `supported_protocol.end()` among still-usable releases), NOT 7; a protocol-7-only capability is not ceiling-active because platform B cannot transport it.
- **Defends:** model "CEILING = min over still-usable releases ... ACROSS ALL PLATFORMS, of supported_protocol.end()"; INVARIANT 1 (every still-usable release must be able to transport a ceiling-active capability).
- **Refs:** design rule 1 (43-47); proposed `ReleaseManifestEntry{platform, supported_protocol:RangeInclusive<u32>}`.

### TIME-33 — carrier capacity GATES ceiling activation even when trusted_time/expiry allow it (chunk-don't-grow)  `guardrail`
- **Setup:** (proposed) trusted_time > blocker.expires_at + M so time/expiry permit advance, but the new capability's fact does not fit the existing connection-frame carrier (would exceed a size class).
- **Action:** evaluate whether the capability is ceiling-active.
- **Expect:** capability is NOT ceiling-active until a carrier that can transport it exists (the `file_slice` precedent: chunk, don't grow the frame); creation still refused.
- **Defends:** model "Carrier capacity GATES ceiling activation (chunk-don't-grow; the file_slice precedent)"; INVARIANT 1 transportability clause.
- **Refs:** `connection_frame_wire.rs` size classes (small 4KiB / file_slice / bundle <64KiB, inventory §4), `content::file_slice` (55).

### TIME-34 — backward trusted_time can never lower an already-advanced ceiling (no ceiling regression)  `guardrail`
- **Setup:** (proposed) ceiling already advanced to 7 at trusted_time T1; later a smaller signed observation arrives (ignored per TIME-08) OR a clock rollback triggers blocked mode.
- **Action:** re-evaluate ceiling after the regress attempt.
- **Expect:** ceiling stays 7 (does not drop to 6); a rollback puts the client in BLOCKED MODE (withholds production) rather than secretly lowering the ceiling and re-enabling old behavior.
- **Defends:** INVARIANT 3 ceiling monotonicity + model "trusted time as a lower bound used to gate ceiling advance" (lower bound only ever raises); rollback => block, not regress.
- **Refs:** design rules 1-3; ties to TIME-08/TIME-15/TIME-30.

### TIME-35 — `clock` (logical) and `trusted_time` are distinct stores; setting the logical clock cannot move trusted_time or change mode  `guardrail`
- **Setup:** (proposed, once trusted_time exists) `trusted_time` persisted at T=5000; logical clock unset.
- **Action:** `con clock set 1` and `con clock advance 999999`.
- **Expect:** `trusted_time` unchanged (still 5000); blocked-mode evaluation unaffected by the operator-local logical clock; only signed observations move trusted_time. The two keys (`CLOCK_KEY="now"` vs a separate trusted-time key) do not alias.
- **Defends:** the local operator clock is scaffolding and must NOT be a backdoor to forge trusted time or escape/enter blocked mode (clock.rs:1-10 doc contract).
- **Refs:** `CLOCK_KEY` (clock.rs:16), proposed separate trusted-time key; design rule 3 ("only signed" sources).

### TIME-36 — replay does not observe fresh time (trusted_time read is frozen during replay)  `guardrail`
- **Setup:** (proposed) store with facts authored across a time span; wipe+replay invoked.
- **Action:** run replay and assert it never calls `SystemTime::now()`/`current_wall_clock_ms` and never advances `trusted_time`.
- **Expect:** replay derives state purely from retained facts + the ceiling-active adapters; no fresh-time observation occurs; `trusted_time` after replay == before replay.
- **Defends:** design rule 8 ("Replay must not observe fresh time") + INVARIANT 4 (replay deterministic, ceiling-independent).
- **Refs:** design rule 8 (71-77), `current_wall_clock_ms` (app.rs:78-83) must be unreachable on the replay path.
## 3. Manifest & release safety

Scope note. The fleet-wide signed release manifest, the expiry-derived protocol
ceiling, trusted time, blocked mode, and the `must_update` canary are the
**planned** mechanisms recorded in `docs/research/Part I above`
("Core Policy" rules 1-3, "Security Changes", "Implementation Shape") and in the
consolidated model. They are NOT yet implemented in `src` (verified: no
`ReleaseManifestEntry`, `supported_protocol`, `warn_after`/`expires_at` as
release fields, `trusted_time`, `must_update`, or ceiling type exists today —
the only `expires_at_minute` in src is `content::message` disappearing-message
state). Per the doc's "Implementation Shape", signed release/canary/time
observations are to be **stored as durable local facts** (sibling to the
existing `auth::local_*` family, e.g. `auth::local_signer_secret`,
`auth::local_secret_retirement`), and ceiling checks gate command construction
and fact admission. These tests therefore define the behavior the manifest layer
must exhibit and bind each assertion to the real entities it must touch:
`FACT_ROUTES` / `RouterProjector::project` (`src/core/projectors.rs:448-459`,
unknown-tag `Err` at line 456), `Runtime::submit_fact` /
`submit_fact_to_store` (`src/core/runtime.rs:268`,
`src/core/pipeline/project_pending_facts.rs`), the `con` CLI (`MATCH_COMMANDS`),
and the wipe+replay path. Invariants referenced are the consolidated set:
(1) VISIBILITY, (2) RENDERING UNIFORMITY, (3) CEILING MONOTONICITY,
(4) REPLAY DETERMINISM, (5) READERS FOREVER / TRANSPORT IN [floor,head],
(6) SAFETY FLOOR.

A note on the {new,old} version axis used throughout: where a release adds the
new fact tag (e.g. `message:2`), tests are written for both the perspective of a
NEW (capable) release/binary and an OLD (non-capable, still-usable) release, and
per scope where the scope changes the answer.

---

### MAN-01 — Forged manifest entry (bad signature) is rejected, ceiling unchanged  `handler-unit`
- **Setup:** A node booted with an embedded fleet manifest containing two valid signed `ReleaseManifestEntry` rows (platform=linux `supported_protocol=6..=7`, platform=ios `supported_protocol=6..=6`), trusted_time T0, computed ceiling = 6.
- **Action:** Deliver a third `ReleaseManifestEntry` (platform=ios `supported_protocol=6..=7`) whose `signature` field is corrupted (one byte flipped) to the manifest-ingest handler / signed-local-fact admission path.
- **Expect:** The entry is refused at signature verification; it is NOT persisted as a manifest local fact, does NOT enter the known-release union, and the ceiling stays 6 (the forged "ios now supports 7" claim cannot raise it). No panic; rejection is logged, not an `Err` that aborts the runtime.
- **Defends:** Mechanism: fleet-wide SIGNED manifest is the only ceiling input; invariant (3) CEILING MONOTONICITY no-regression gate cannot be bypassed by unsigned claims.
- **Refs:** proposed `ReleaseManifestEntry{release_id,platform,supported_protocol,warn_after,expires_at,signature}`; signed-local-fact path sibling to `auth::local_signer_secret`; `Runtime::submit_fact` (`src/core/runtime.rs:268`).

### MAN-02 — Unsigned manifest entry (signature absent/empty) is rejected  `handler-unit`
- **Setup:** Same node as MAN-01, ceiling 6.
- **Action:** Deliver a `ReleaseManifestEntry` with an empty/zero `signature` (no signature at all) claiming platform=ios `supported_protocol=6..=8`.
- **Expect:** Refused (missing signature is treated identically to a bad signature); not persisted, not in the union, ceiling stays 6. Distinct rejection reason ("unsigned") observable in diagnostics but same effect as MAN-01.
- **Defends:** Mechanism: only SIGNED entries count toward the union; (3).
- **Refs:** proposed `ReleaseManifestEntry.signature`; signed-local-fact admission.

### MAN-03 — Forged entry with valid signature from a non-fleet key is rejected  `handler-unit`
- **Setup:** Node with the fleet manifest-signing public key pinned (embedded). Ceiling 6.
- **Action:** Deliver a `ReleaseManifestEntry` correctly self-signed by an attacker key (valid signature, wrong signer) claiming platform=android `supported_protocol=6..=9`.
- **Expect:** Refused at signer-identity check (signature verifies against attacker key, not the pinned fleet key); not persisted, ceiling stays 6.
- **Defends:** Mechanism: manifest trust is anchored to a pinned fleet signer, not "any valid signature"; (3).
- **Refs:** proposed pinned fleet manifest signer; `ReleaseManifestEntry.signature`.

### MAN-04 — Manifest knowledge is a monotonic union: a new entry never forgets a known release  `handler-unit`
- **Setup:** Node knows two signed entries: relA (platform=ios `6..=6`, expires_at far future) and relB (platform=linux `6..=7`). Ceiling = 6 (relA caps it).
- **Action:** Deliver a third valid signed entry relC (platform=android `6..=7`). Then deliver a manifest snapshot that happens to OMIT relA (e.g. a newer fleet manifest that only lists relB, relC).
- **Expect:** relA is NOT forgotten — the union still contains {relA, relB, relC}; ceiling stays 6 because relA (`6..=6`, not expired, not deprecated) still caps it. A manifest that omits a previously-learned, still-usable release cannot silently drop it from the ceiling computation.
- **Defends:** Mechanism: manifest knowledge is a MONOTONIC UNION (never forget a release); (3).
- **Refs:** proposed manifest union store (durable local facts); ceiling = min over still-usable releases.

### MAN-05 — Monotonic union: expires_at can only move LATER, never earlier  `handler-unit`
- **Setup:** Node knows signed entry relA (platform=ios `6..=6`, `expires_at = E1`). trusted_time < E1.
- **Action:** Deliver a re-signed relA with `expires_at = E0` where E0 < E1 (an attempt to retire relA earlier than already known).
- **Expect:** The known `expires_at` for relA stays E1 (max(E1, E0) = E1). The earlier value is ignored. relA remains still-usable until E1; the ceiling does NOT advance early off the back of a reverted expiry.
- **Defends:** Mechanism: monotonic union never reverts `expires_at` earlier; protects (1) VISIBILITY (a still-deployed older release is not prematurely dropped from the visibility guarantee).
- **Refs:** proposed `ReleaseManifestEntry.expires_at`; per-release monotonic `expires_at` merge.

### MAN-06 — Monotonic union: a LATER expires_at is accepted (grace-window extension)  `handler-unit`
- **Setup:** Node knows signed relA (platform=ios `6..=6`, `expires_at = E1`), trusted_time approaching E1, ceiling 6 about to advance to 7 at E1.
- **Action:** Deliver a re-signed relA with `expires_at = E2` where E2 > E1 (operator extends the grace window per doc rule 2: "set that release's expires_at later").
- **Expect:** Known `expires_at` for relA becomes E2. The ceiling does NOT advance to 7 at E1; it now waits until trusted_time > E2 + M. No separate readiness signal is introduced.
- **Defends:** Mechanism: monotonic union accepts later expiry; doc "Expiry-driven ceiling advance" rule 2; (3).
- **Refs:** proposed `ReleaseManifestEntry.expires_at`; ceiling-advance gate.

### MAN-07 — warn_after surfaces an update prompt; full production continues (new-capable binary)  `blackbox-cli`
- **Setup:** A NEW (capable) binary whose own release relN has `warn_after = W`, `expires_at = E`, supported_protocol includes the ceiling. trusted_time set so W < trusted_time < E. Ceiling 6.
- **Action:** Run a normal shared-production command, e.g. `con send <workspace> "hello"`.
- **Expect:** The command SUCCEEDS and emits a `content::message` (tag 50) fact; an update prompt / warning is surfaced (e.g. on stderr or a status field) because trusted_time passed `warn_after`. Production is NOT withheld — create/admit/project/display all run normally.
- **Defends:** Mechanism: `warn_after` is advisory only (prompt), distinct from `expires_at` (hard block); does not violate (1).
- **Refs:** proposed `ReleaseManifestEntry.warn_after`; `con send` -> `send` run fn (content::message::cli); fact tag 50.

### MAN-08 — warn_after for an OLD release surfaces on that release; its production still flows  `blackbox-cli`
- **Setup:** An OLD (still-usable, non-capable) binary running release relO with `warn_after = W` passed but `expires_at = E` in the future. Ceiling 6 (relO supports `6..=6`).
- **Action:** Run `con react <workspace> <message-id> :thumbsup:` (a ceiling-active capability relO supports).
- **Expect:** Command succeeds, emits a `content::reaction` (tag 52) fact; the warn prompt is shown. The OLD release continues producing shared facts at the ceiling. warn_after never blocks.
- **Defends:** Mechanism: warn_after is advisory on every release, capable or not; (1).
- **Refs:** `con react` -> `react` (content::message::cli); `content::reaction` tag 52; proposed `warn_after`.

### MAN-09 — Past expires_at on OWN release blocks shared production (new-version perspective)  `blackbox-cli`
- **Setup:** A binary whose own release relX has `expires_at = E`; trusted_time advanced to T > E + M. Ceiling at head; relX is now PAST EXPIRY.
- **Action:** Run `con send <workspace> "post-expiry"`.
- **Expect:** Shared production is BLOCKED: the `send` refuses to create/emit the `content::message` fact (clear "release expired, update required" error, out-of-band update directed). Local reads and replay still run (see MAN-10).
- **Defends:** Invariant (5) EXPIRED PEERS ARE OUT; doc rule 1 "still usable if not past expires_at"; (1).
- **Refs:** `con send`; `ReleaseManifestEntry.expires_at`; trusted_time + skew margin M.

### MAN-10 — Past own expires_at still permits local reads + replay (data is safe)  `blackbox-cli`
- **Setup:** Same expired binary as MAN-09, with retained facts already in the store from before expiry.
- **Action:** Run read-only commands `con messages <workspace>` and `con count`, then a wipe+replay pass.
- **Expect:** Reads SUCCEED and show pre-expiry content; wipe+replay rebuilds derived state deterministically. Only SHARED PRODUCTION (creating/transporting new shared facts) is blocked; local data remains accessible and replayable. "Local data is safe (replays after update)".
- **Defends:** Invariant (5) "local data is safe"; (4) REPLAY DETERMINISM independent of block state.
- **Refs:** `con messages` -> `messages`, `con count` -> `count`; wipe+replay path; `expires_at`.

### MAN-11 — Past expires_at on ANOTHER release lowers/holds the ceiling, does not block local production  `handler-unit`
- **Setup:** NEW capable binary relN (`6..=7`, not expired). Manifest also knows relO (platform=ios `6..=6`, `expires_at = E`). trusted_time < E. Ceiling = 6 (relO caps it).
- **Action:** Advance trusted_time to T > E + M (relO now past expiry) by delivering a signed time observation; recompute ceiling.
- **Expect:** relO drops out of the still-usable set; ceiling RISES to 7 (min over remaining still-usable releases, all of which support 7). relN's own production is NOT blocked (relN itself is not expired); the only effect of another release's expiry is a ceiling INPUT change. message:2 / file:3 capabilities become ceiling-active on the next wipe+replay.
- **Defends:** Mechanism: ceiling = min over still-usable releases ACROSS ALL PLATFORMS; doc rule 2 expiry-driven advance; (1)(3).
- **Refs:** ceiling computation inputs; trusted_time + M; proposed `supported_protocol` RangeInclusive end.

### MAN-12 — Skew margin M: ceiling does NOT advance at exactly expires_at, only past expires_at + M  `property`
- **Setup:** Manifest knows blocker relO (`6..=6`, `expires_at = E`) and relN (`6..=7`). Ceiling = 6.
- **Action:** For trusted_time values t in {E - 1, E, E + 1, E + M - 1, E + M, E + M + 1}, recompute the ceiling.
- **Expect:** Ceiling stays 6 for all t <= E + M (inclusive of E + M); ceiling = 7 only for t > E + M. Property: ceiling-advance predicate is strictly `trusted_time > blocker.expires_at + M`, never earlier. Order of observations does not change the final ceiling for a given final trusted_time (monotone).
- **Defends:** Mechanism: skew margin M; advance only at `trusted_time > blocker.expires_at + M`; (3).
- **Refs:** proposed skew margin M; trusted_time; `ReleaseManifestEntry.expires_at`.

### MAN-13 — must_update canary covering OWN release blocks shared production immediately  `blackbox-cli`
- **Setup:** Binary running release relX. Manifest/ceiling otherwise healthy (relX not past `expires_at`). A signed `must_update` canary naming relX (security-deprecation) is delivered.
- **Action:** Persist the canary, then run `con send <workspace> "after canary"`.
- **Expect:** Shared production is BLOCKED IMMEDIATELY (no waiting for `expires_at`): `send` refuses to emit the `content::message` fact, with a "release security-deprecated, update required" message. Distinct from the slow expiry path — the canary short-circuits relX out of the still-usable set at once.
- **Defends:** Mechanism: `must_update` canary security-deprecates a release immediately; doc "Security Changes / Unsafe release"; (5)(6).
- **Refs:** proposed signed `must_update` canary (durable local fact, sibling to `auth::local_secret_retirement`); `con send`; ceiling still-usable predicate (not deprecated).

### MAN-14 — must_update canary must be signed (forged canary rejected, production continues)  `handler-unit`
- **Setup:** Binary running relX, healthy. An UNSIGNED / wrong-key `must_update` canary naming relX is delivered (an attacker trying to force a denial-of-service "everyone must update").
- **Action:** Deliver the forged canary to the canary-ingest path; then run `con send`.
- **Expect:** Canary is REJECTED at signature/signer check; not persisted; relX stays still-usable; `con send` SUCCEEDS. A forged canary cannot strand the fleet.
- **Defends:** Mechanism: canary is signed-monotonic-persisted; forged canary cannot deprecate a release; protects availability against (6) abuse.
- **Refs:** proposed signed `must_update` canary; pinned fleet signer; `con send`.

### MAN-15 — must_update canary is monotonic + persisted (cannot be revoked by a later unsigned/older message)  `handler-unit`
- **Setup:** Binary running relX. A valid signed `must_update` canary for relX has been persisted; production is blocked. Restart the binary (canary persisted across restart).
- **Action:** After restart, deliver an unsigned "all clear" message and a re-signed canary with an OLDER monotonic counter/timestamp than the persisted one; then run `con send`.
- **Expect:** After restart the canary is STILL in effect (persisted) — `con send` blocked even before any new message. The unsigned all-clear is ignored; the older-counter re-sign does not roll back the deprecation. Only a properly-signed, monotonically-newer manifest action could lift it (out of scope of attacker control).
- **Defends:** Mechanism: canary is monotonic + persisted; security deprecation is sticky; (6).
- **Refs:** proposed `must_update` canary persistence (durable local fact); monotonic counter merge.

### MAN-16 — must_update canary for ANOTHER release only updates ceiling inputs (own production unaffected)  `handler-unit`
- **Setup:** NEW capable binary relN (`6..=7`, healthy). Manifest knows relO (platform=ios `6..=6`) which caps the ceiling at 6. A signed `must_update` canary naming relO (NOT relN) is delivered.
- **Action:** Persist the canary; recompute ceiling; then run a shared-production command on relN.
- **Expect:** relN's own production is NOT blocked (the canary names relO, not relN). relO is removed from the still-usable set immediately, so the ceiling RISES to 7 (the canary acts purely as a ceiling INPUT, like an instantaneous expiry). relN keeps producing; message:2/file:3 become ceiling-active on next wipe+replay.
- **Defends:** Mechanism: a canary for another release only updates ceiling inputs (does not block self); contrast with MAN-13; (1)(3).
- **Refs:** proposed `must_update` canary; ceiling = min over still-usable releases; relN/relO distinction (new vs old version axis).

### MAN-17 — must_update canary for another release does NOT block local reads/replay either  `blackbox-cli`
- **Setup:** Binary relN with retained facts. A signed canary names relO (another release). Ceiling rises to 7 after canary.
- **Action:** Run `con messages` and a wipe+replay.
- **Expect:** Reads succeed; replay rebuilds deterministically; the canary-against-another-release changes only the ceiling, never relN's local read/replay path.
- **Defends:** Mechanism: canary-for-other = ceiling input only; (4)(5).
- **Refs:** `con messages`; wipe+replay; `must_update` canary.

### MAN-18 — Out-of-band manifest delivery (embedded in binary) primes the union before any network  `blackbox-cli`
- **Setup:** A freshly installed binary with the fleet manifest entries EMBEDDED (out-of-band delivery via the binary itself, before any peer contact), trusted_time T0 from embedded release metadata.
- **Action:** On first boot, before connecting to any peer, run `con count` / inspect the computed ceiling.
- **Expect:** The embedded manifest entries seed the known-release union and an initial trusted_time WITHOUT a network round-trip; the ceiling is computed from the embedded set. The binary is immediately able to enforce the ceiling offline.
- **Defends:** Mechanism: out-of-band delivery primes manifest knowledge; doc "Implementation Shape / store signed release/canary/time observations as durable local facts"; doc rule 3 "embedded release metadata".
- **Refs:** embedded manifest; trusted_time from embedded metadata; ceiling computation.

### MAN-19 — Gossip catch-up: a node learns a newer signed entry from a peer and merges it monotonically  `multinode-network`
- **Setup:** Two nodes. Node A knows {relA `6..=6` exp E1, relB `6..=7`}, ceiling 6. Node B additionally knows a signed re-signed relA with `expires_at = E2 > E1` (operator extended grace). A and B connect.
- **Action:** Manifest facts gossip over the connection (carried as durable local-derived facts via the normal sync/connection path); A receives B's relA(E2).
- **Expect:** A merges relA's `expires_at` to E2 (max), monotonic union grows; A's ceiling-advance now waits for E2 like B. Gossip catch-up converges both nodes to the SAME union; no node forgets relB. Convergence is order-independent.
- **Defends:** Mechanism: out-of-band + gossip catch-up; monotonic union convergence; (3).
- **Refs:** connection/sync transport (`sync::shared_fact`, connection frames); proposed manifest-as-local-fact gossip; monotonic merge.

### MAN-20 — Gossip catch-up cannot LOWER a peer's ceiling via a stale/forgetful manifest  `multinode-network`
- **Setup:** Node A has advanced its ceiling to 7 (relO expired past E + M). Node B is behind: B still lists relO as not-yet-expired and gossips its (older) manifest view to A.
- **Action:** A receives B's manifest snapshot (which still shows relO unexpired) plus B's trusted_time which is < A's trusted_time.
- **Expect:** A does NOT lower its ceiling back to 6. trusted_time is monotonic-max (B's lower time is ignored as a lower bound), and the union does not "un-expire" relO once A's trusted_time already passed E + M. Ceiling stays 7. A node cannot be tricked into ceiling regression by a lagging peer.
- **Defends:** Mechanism: trusted_time monotonic max; ceiling never regresses; (3) CEILING MONOTONICITY.
- **Refs:** trusted_time monotonic max; ceiling recompute; gossip catch-up.

### MAN-21 — Historical facts from a security-deprecated release stay valid (fact version still safe)  `replay-cli`
- **Setup:** Store contains a retained `auth::user` (tag 14) fact and `content::message` (tag 50, version 1) facts that were originally written by release relX. A signed `must_update` canary later security-deprecates relX. The message:1 and user fact VERSIONS are NOT flagged unsafe.
- **Action:** Run a wipe+replay pass.
- **Expect:** The historical user/message facts REPLAY and re-materialize their read-model rows normally via their own tag-keyed adapters; they are NOT invalidated, pending, or dropped just because relX was deprecated. Deprecating a release deprecates the BINARY, not the facts it wrote.
- **Defends:** Mechanism: "Historical facts from a security-deprecated release stay valid unless their fact version is unsafe"; doc "Security Changes / Unsafe release"; (5) READERS FOREVER; (4).
- **Refs:** `auth::user` tag 14, `content::message` tag 50; wipe+replay via FACT_ROUTES adapters; `RouterProjector::project` (`src/core/projectors.rs:448`).

### MAN-22 — Historical facts whose FACT VERSION is unsafe are suppressed even though the release wrote them legitimately  `replay-cli`
- **Setup:** Store contains retained `content::file` (tag 54) facts written by relX. A fact-version-safety action marks `file:vK` (the version those facts use) as UNSAFE (e.g. an unsafe BAO proof format), independent of any release deprecation.
- **Action:** Run a wipe+replay pass.
- **Expect:** The affected `file:vK` facts are withheld/handled by the tightened `file:vK` adapter (retained as historical evidence, not materialized into display rows) — but facts from OTHER, safe file versions still replay. The trigger is the FACT VERSION being unsafe, NOT the release. Contrast MAN-21: there the release was deprecated but the fact version was safe -> facts stayed valid.
- **Defends:** Mechanism: fact-version safety is orthogonal to release safety; doc "Security Changes / Unsafe fact version"; (6) SAFETY FLOOR; (5).
- **Refs:** `content::file` tag 54; tightened/suppressing adapter; doc "Files and file slices" upgrade-path row.

### MAN-23 — Release deprecation and fact-version deprecation are independent (matrix: 4 corners)  `property`
- **Setup:** A retained `content::message` (tag 50) fact written by relX. Two independent flags: {relX deprecated?} x {message:1 version unsafe?}.
- **Action:** For each of the four combinations, run wipe+replay and observe the fact's fate.
- **Expect:** (a) release-safe + fact-safe -> fact materializes normally. (b) release-DEPRECATED + fact-safe -> fact STILL materializes (MAN-21). (c) release-safe + fact-UNSAFE -> fact suppressed (MAN-22). (d) release-DEPRECATED + fact-UNSAFE -> fact suppressed (driven by the fact-version flag, not the release). The release flag never affects fact validity; only the fact-version flag does.
- **Defends:** Mechanism: orthogonality of release safety vs fact-version safety; (5)(6).
- **Refs:** `content::message` tag 50; release-deprecation (canary) vs fact-version-deprecation; wipe+replay.

### MAN-24 — Embedded-vs-learned reconciliation: a newer LEARNED entry supersedes the stale EMBEDDED one  `handler-unit`
- **Setup:** Binary ships with EMBEDDED relA (`6..=6`, `expires_at = E1`). At runtime it LEARNS (signed, gossiped) a re-signed relA with `expires_at = E2 > E1`.
- **Action:** Reconcile embedded vs learned for relA; recompute ceiling and still-usable predicate.
- **Expect:** Reconciliation keeps the MONOTONIC max — `expires_at = E2`. The embedded value is a seed/lower-bound; the learned-newer value wins where it is monotonically greater. relA stays usable until E2.
- **Defends:** Mechanism: embedded-vs-learned entries reconciled via the same monotonic-union merge; (3).
- **Refs:** embedded manifest seed; learned manifest fact; per-release monotonic merge.

### MAN-25 — Embedded-vs-learned reconciliation: a stale LEARNED entry cannot revert an EMBEDDED entry  `handler-unit`
- **Setup:** Binary ships with EMBEDDED relA (`6..=6`, `expires_at = E2`, a fresh build). At runtime it receives a signed but OLDER relA with `expires_at = E1 < E2` (from a lagging gossip source).
- **Action:** Reconcile; recompute.
- **Expect:** The embedded `expires_at = E2` is retained (max(E2, E1) = E2). A stale learned entry cannot revert the embedded knowledge earlier. Symmetric with MAN-05/MAN-24 — merge is direction-independent (always max for expiry).
- **Defends:** Mechanism: embedded-vs-learned reconciliation never reverts; monotonic union; (1)(3).
- **Refs:** embedded manifest; learned manifest fact; monotonic `expires_at` merge.

### MAN-26 — Embedded-vs-learned reconciliation for SUPPORTED_PROTOCOL range (capability, not time)  `handler-unit`
- **Setup:** Binary ships with EMBEDDED relN (own release) `supported_protocol = 6..=7`. A learned re-signed relN claims `6..=9` (a forged or mistaken widening).
- **Action:** Reconcile relN's `supported_protocol` and recompute the ceiling input contributed by relN.
- **Expect:** A release's OWN supported_protocol is anchored to what the running binary actually implements (the embedded/self-known capability is authoritative for self; a learned wider claim for one's own release does not let it admit protocol it cannot speak). For a DIFFERENT release, the signed entry's range is taken as-is (subject to signature). The widening claim for self is not used to raise self's admission surface.
- **Defends:** Mechanism: capability reconciliation; a binary cannot be talked into admitting protocol it cannot implement; (3) no-regression gate is about real capability.
- **Refs:** proposed `ReleaseManifestEntry.supported_protocol` RangeInclusive<u32>; embedded self-capability vs learned claim.

### MAN-27 — Pending above-ceiling input activates when the ceiling rises via expiry/canary  `replay-cli`
- **Setup:** Ceiling = 6 (relO `6..=6` caps it). A peer delivered a `content::message` version-2 fact (a NEW tag for the incompatible wire shape), and admission retained it as pending because it was above-ceiling.
- **Action:** Advance trusted_time past relO's `expires_at + M` (relO falls out; ceiling -> 7), then run a wipe+replay.
- **Expect:** Now that message:2's tag is ceiling-active, the old pending copy re-enters admission, routes to the kept-forever projector, and materializes if authentication/context succeeds. No fresh network resend is required for bytes already retained as pending.
- **Defends:** ADMISSION: pending above-ceiling input activates only after the ceiling admits it; (3) ceiling gates activation.
- **Refs:** new message:2 tag + sibling `_v2/` projector in `FACT_ROUTES`; pending before projection; wipe+replay; ceiling rise from `expires_at`/canary.

### MAN-28 — Manifest-driven ceiling rise is gated by carrier capacity (chunk-don't-grow)  `handler-unit`
- **Setup:** Manifest is poised to raise the ceiling to a version that introduces a fact family whose byte size exceeds the BUNDLE carrier limit (`CONNECTION_FRAME_BUNDLE` < 64 KiB, `connection_frame_wire.rs`) that a still-usable release is limited to.
- **Action:** Advance trusted_time so the time/expiry side would otherwise activate the new capability; recompute ceiling-active set.
- **Expect:** The new fact family does NOT become ceiling-active even though the manifest/time would allow it, because a still-usable release's carrier cannot transport it (doc "Connection And Sync" rule 4). Capability stays dormant until either every carrier-limited release expires OR an old-carrier-compatible chunking path exists (the `content::file_slice` tag 55 precedent).
- **Defends:** Mechanism: carrier capacity GATES ceiling activation; doc rule 4 "Carrier limits are real"; (1).
- **Refs:** `connection::frame_bundle` tag 170, `CONNECTION_FRAME_BUNDLE_FACT_SLOTS`/`<64KiB` in `connection_frame_wire.rs`; `content::file_slice` tag 55 chunking precedent.

### MAN-29 — Staleness window S without manifest/time refresh enters BLOCKED MODE  `blackbox-cli`
- **Setup:** Binary healthy (own release not expired) but it has received NO fresh signed time/manifest observation for longer than the staleness window S; trusted_time is stale.
- **Action:** Run `con send <workspace> "stale"`.
- **Expect:** Shared production is WITHHELD (BLOCKED MODE) because trusted_time is too stale to safely assert "no still-usable release has expired"; local reads (`con messages`) and replay still run. The block lifts when a fresh signed observation refreshes trusted_time within tolerance.
- **Defends:** Mechanism: staleness window S without refresh => BLOCKED MODE (shared production withheld; local reads + replay still run).
- **Refs:** `con send` / `con messages`; trusted_time staleness window S; signed time observation as durable local fact.

### MAN-30 — Backward clock rollback beyond tolerance enters BLOCKED MODE; trusted_time does not regress  `blackbox-cli`
- **Setup:** Binary with persisted trusted_time = T. Local wall clock is rolled BACKWARD beyond the rollback tolerance.
- **Action:** Run `con send`; then inspect the persisted trusted_time.
- **Expect:** Shared production is BLOCKED (clock implausible); trusted_time stays at T (monotonic-max lower bound never regresses on a backward jump). Local reads + replay still run. A backward clock cannot un-expire a release or lower the ceiling.
- **Defends:** Mechanism: backward clock rollback beyond tolerance => BLOCKED MODE; trusted_time is a monotonic lower bound; (3).
- **Refs:** trusted_time monotonic max; rollback tolerance; `con send` block path.

### MAN-31 — must_update canary for own release: in-flight wipe+replay still completes before block takes hold on sends  `replay-cli`
- **Setup:** Binary relX with a freshly-applied signed `must_update` canary against relX. Pre-canary retained facts exist; an upgrade wipe+replay is initiated as part of/after applying the canary.
- **Action:** Run the wipe+replay barrier; observe ordering of replay vs the new send-block.
- **Expect:** Replay/purge completion runs to finish (it is local, deterministic, ceiling-independent) — the canary blocks SHARED PRODUCTION (network sends, new shared-fact creation) but does NOT abort the local rebuild. Per doc rule 8, full replay/purge finishes before any network send resumes; the canary simply keeps the network-send gate closed.
- **Defends:** Mechanism: canary blocks shared production immediately but local replay still runs; (4)(5); doc rule 8 ordering.
- **Refs:** `must_update` canary; wipe+replay barrier; doc "Replay is deterministic and local" rule 8.

### MAN-32 — Ceiling = min ACROSS ALL PLATFORMS (the lowest platform caps everyone)  `property`
- **Setup:** Manifest knows still-usable releases on three platforms: linux `6..=8`, android `6..=7`, ios `6..=6`. None expired/deprecated.
- **Action:** Compute the ceiling.
- **Expect:** Ceiling = 6 = min over all still-usable releases of `supported_protocol.end()`, ACROSS ALL PLATFORMS (ios `6..=6` caps the whole fleet, not just ios). Property: dropping the lowest platform (ios expires) recomputes ceiling = 7; dropping the next (android expires) -> 8. Monotone non-decreasing as releases leave the still-usable set.
- **Defends:** Mechanism: CEILING = min over still-usable releases ACROSS ALL PLATFORMS of `supported_protocol.end()`; (1)(3).
- **Refs:** proposed `ReleaseManifestEntry{platform, supported_protocol}`; ceiling = min over still-usable end().

### MAN-33 — A capability is CEILING-ACTIVE only if every still-usable release can transport it (not just intro_version<=ceiling)  `handler-unit`
- **Setup:** Ceiling = 7 (numerically covers a new fact family with `intro_version = 7`). But one still-usable release at protocol 7 has a carrier that cannot transport the new family's byte size/dependency shape.
- **Action:** Evaluate whether the new family is ceiling-active.
- **Expect:** It is NOT ceiling-active, because the predicate is `intro_version <= ceiling AND every still-usable release can transport it` — the second clause fails. The fact family stays dormant in production despite `intro_version <= ceiling`. (Combines with MAN-28's carrier gate.)
- **Defends:** Mechanism: ceiling-active iff `intro_version <= ceiling AND every still-usable release can transport it`; (1).
- **Refs:** ceiling-active predicate; `connection_frame_wire.rs` carrier; intro_version on routes (`FACT_ROUTES` / `RouterProjector`).
## 4. Fact routing, admission, pending, intro_version

These tests defend the model's admission/pending/routing rules. Today's
code has three structural gaps these tests are written to drive out and then
lock: (a) `FactRoute { tag, projector, replayed }` carries no `intro_version`;
(b) `RouterProjector` is not ceiling-filtered — it dispatches every registered
tag unconditionally; (c) authentication is currently composed into projection
with `project_authenticated`, with no core-managed route runner that treats
authentication, adapting, and projection as separate stages. Versioning adds an
admission gate ahead of projection: wire-invalid input drops; wire-admitted
unknown or above-ceiling bytes become pending; and ceiling-active known tags
authenticate by tag, pass through the route's adapt slot, then project. Tests below
that assert pending ingress and ceiling-filtering are
RED against the current tree and define the target
behavior; tests that assert global tag uniqueness / registry shape are GREEN
guardrails that extend `fact_route_tags_are_globally_unique`.

Conventions used below: "ceiling C" = the active protocol-version ceiling
computed from the signed `ReleaseManifestEntry` fleet at `trusted_time`.
"intro_version V(tag)" = the protocol version that first bundled a fact tag.
A fact is "above-ceiling" iff `V(tag) > C`. All CLI invocations use the real
`con` binary (`src/main.rs`). Replay/status commands exist in `src`, but most
versioning assertions against a future ceiling still start RED.

---

### ROUTE-01 — at-ceiling content::message admits, projects, and is counted  `blackbox-cli`
- **Setup:** Single `con` node, fresh store, workspace created (`con create-workspace`). Manifest fleet yields ceiling C = the current head protocol version P_head; `V(content::message=50) <= C` (message has always been in-bundle).
- **Action:** `con send <workspace> "hello"` then `con messages <workspace>` and `con content-count <workspace>`.
- **Expect:** The message fact (tag 50) is admitted and persisted; `con messages` displays "hello"; `con content-count` increments by 1; exit code 0; no pending state, no error on stderr.
- **Defends:** Invariant (1) VISIBILITY — a ceiling-active fact is admissible/projectable/displayable. Baseline for ADMISSION.
- **Refs:** `content::message` tag 50 `TYPE_CONTENT_MESSAGE`; `MATCH_COMMANDS` send/messages/content-count; `RouterProjector` route `project_content_message` (registry.rs:604); read model `content_messages`/`OPENED_MESSAGE_ROWS`.

### ROUTE-02 — below-ceiling fact admits and projects via its own historical adapter  `projector-unit`
- **Setup:** In-process router built from `FACT_ROUTES`. Ceiling C = P_head. Construct a `content::reaction` fact (tag 52) whose `V(52) < C` strictly (reaction introduced before head).
- **Action:** Call `RouterProjector::new(FACT_ROUTES, &[]).project(fact, ctx)` (the body invoked by `ProtocolProjector::project`, registry.rs:568).
- **Expect:** `Ok(ProjectionOutput)` with the reaction's row mutation (`content_reactions`/`REACTION_ROWS`); the selected route is the reaction route keyed by tag 52 regardless of C being higher. No error.
- **Defends:** Invariant (4) REPLAY DETERMINISM — projection keyed by the fact's OWN tag, ceiling-independent; ADMISSION at/below ceiling.
- **Refs:** `content::reaction` tag 52; `project_content_reaction` (registry.rs:606); `RouterProjector::project` (projectors.rs:448-459); `FactRoute.tag` lookup (projectors.rs:455).

### ROUTE-03 — local creation of an above-ceiling fact is REFUSED at the CLI  `blackbox-cli`
- **Setup:** `con` head binary that KNOWS a fact tag with `V(tag) > C` (e.g. a `message:2` variant or the proposed `user_profile_v2`). Manifest fleet pins ceiling C below that tag's intro_version (one still-usable release only supports up to C).
- **Action:** Invoke the CLI command that would mint the above-ceiling fact (e.g. `con send --schema 2 ...` or `con create-profile-v2 ...` once such a command exists for the new bucket).
- **Expect:** Command exits non-zero with a refusal message naming the ceiling (e.g. "fact <tag> not yet ceiling-active: intro_version V > ceiling C"); NO fact is written to the store; `con content-count`/relevant reader is unchanged.
- **Defends:** ADMISSION — local creation of above-ceiling fact REFUSED; Invariant (3) CEILING MONOTONICITY (don't emit what peers can't transport).
- **Refs:** `MATCH_COMMANDS` (registry.rs:367); ceiling gate at fact-creation; `Runtime::submit_fact` (runtime.rs:268) must reject before persist.

### ROUTE-04 — local creation refusal is per-tag, not per-scope (sibling tag still admits)  `blackbox-cli`
- **Setup:** Same head binary. Ceiling C such that one new content tag T_new (`V(T_new) > C`) is above-ceiling but the existing `content::message` (50) and `content::file` (54) are at/below ceiling.
- **Action:** Run two commands in sequence: (a) the command that would mint T_new (above-ceiling), then (b) `con send <ws> "ok"` (tag 50, at-ceiling).
- **Expect:** (a) refused, nothing written; (b) succeeds and is visible/counted. The refusal of T_new does NOT disable the rest of the `content` scope.
- **Defends:** ADMISSION granularity — refusal keyed by the FACT TAG (the versioning knob), not the scope.
- **Refs:** VERSIONING KNOB = fact tag; `content` scope families tags 50/52/53/54/55/147; `MATCH_COMMANDS` send.

### ROUTE-05 — received above-ceiling fact becomes PENDING before projection  `projector-unit`
- **Setup:** Router over `FACT_ROUTES` with a ceiling filter applied. Ceiling C. Build a fact whose first byte is a tag T with `V(T) > C` — model this with a tag that the ceiling-filtered router treats as inactive (e.g. a future `message:2` tag, or a registered tag deliberately marked intro_version > C).
- **Action:** Deliver the fact through the receive/admission path before projection.
- **Expect:** The fact is retained as pending bytes before authenticator/adapt/projector dispatch: NO row mutations, NO emitted inner facts, NO display, NOT counted, NO authority, NO purge effect. It may be indexed by id/bytes for negentropy, but it is not an active validated fact. This must not surface as a user-facing projector error.
- **Defends:** ADMISSION — received above-ceiling input is pending: syncable and waiting, but not active protocol truth.
- **Refs:** future ceiling admission gate before `RouterProjector::project`; current unknown-tag projection error is the implementation gap the gate avoids for wire-admitted future input.

### ROUTE-06 — pending received fact is retained as bytes, not projected  `projector-unit`
- **Setup:** Ceiling-filtered router, ceiling C. Receive an above-ceiling fact F (tag T, `V(T) > C`) via the receive path (`submit_fact`).
- **Action:** After receiving, enumerate the durable fact log / store contents.
- **Expect:** F's raw bytes are present in the pending byte store/index exactly as received. It is NOT in any read-model row table, NOT in `con messages`, NOT in `con content-count`, and NOT active projection input until admission is retried at a ceiling/context that can accept it.
- **Defends:** ADMISSION — pending fact bytes are retained and syncable but inert.
- **Refs:** future pending byte store; read models in `read_models` (registry.rs:36-182) must NOT contain it.

### ROUTE-07 — pending above-ceiling input is invisible across every reader  `blackbox-cli`
- **Setup:** A node that has received a pending above-ceiling `content::message`-family variant. Ceiling C below its intro_version.
- **Action:** Run each content reader: `con messages`, `con content-count`, `con view`, `con files`.
- **Expect:** None of the readers surface or count the pending input; outputs are identical to a node that never received it. Exit code 0 (no error surfaced to the user for a peer-sent future fact).
- **Defends:** ADMISSION — pending input is retained but inactive; Invariant (2) RENDERING UNIFORMITY (render at ceiling, withhold above-ceiling derivations).
- **Refs:** `MATCH_COMMANDS` messages/content-count/view/files; read models OPENED_MESSAGES/CONTENT_MESSAGES.

### ROUTE-08 — pending above-ceiling input activates after ceiling rises  `replay-cli`
- **Setup:** Node receives above-ceiling fact F (tag T, `V(T) > C0`) and stores it pending. Then the signed manifest fleet advances so the new ceiling C1 >= `V(T)` (every still-usable release now supports T, and `trusted_time > blocker.expires_at + M`).
- **Action:** Re-run admission for pending bytes, then perform wipe + replay (rebuild derived state from the retained active fact log) at ceiling C1.
- **Expect:** F authenticates/adopts the now-active route, moves from pending to active retained fact, projects normally, and becomes displayed/counted. State equals a node that first received F natively at C1.
- **Defends:** ADMISSION — pending input activates when ceiling/context admits it; Invariant (4) REPLAY DETERMINISM.
- **Refs:** wipe+replay rebuild; ceiling-filtered `RouterProjector`; `FactRoute` for tag T; trusted-time gate (skew margin M).

### ROUTE-09 — pending input stays pending across replay if ceiling did not rise  `replay-cli`
- **Setup:** Node received pending above-ceiling fact F (tag T, `V(T) > C0`). Manifest unchanged; ceiling stays C0.
- **Action:** wipe + replay at ceiling C0.
- **Expect:** F remains pending, unprojected, undisplayed, and uncounted. Derived state is identical to a node that never received it, except pending-byte inventory/diagnostics.
- **Defends:** ADMISSION + Invariant (4) — pending bytes do not enter the projection graph until admitted.
- **Refs:** ceiling-filtered admission gate; replay path; pending byte inventory.

### ROUTE-10 — replay selects the historical adapter by the fact's OWN tag, independent of current ceiling (below-ceiling tag)  `replay-cli`
- **Setup:** Node has retained facts spanning two on-wire shapes of one family, e.g. `content::file_slice` (tag 55) plus a hypothetical successor slice tag T2. Current ceiling C >= max(V(55), V(T2)) so BOTH are active. Both old and new facts are in the log.
- **Action:** wipe + replay.
- **Expect:** Each retained fact is dispatched to the projector keyed by ITS first byte: tag-55 facts -> `project_content_file_slice`; tag-T2 facts -> the T2 projector. The high ceiling does NOT cause old tag-55 facts to be re-interpreted by the newer projector. Resulting rows match each fact's own era.
- **Defends:** Invariant (4) REPLAY DETERMINISM — ceiling-independent; every retained fact replays via the historical adapter keyed by its OWN tag.
- **Refs:** `RouterProjector::effective_tag` reads `fact.bytes.first()` (projectors.rs:434); per-tag `FactRoute`; `content::file_slice` tag 55.

### ROUTE-11 — old projector still selected by tag even when newer sibling is the ceiling default  `projector-unit`
- **Setup:** Router with two registered routes for one family: tag A (old, `V(A)` small) and tag B (new, `V(B)` near head), both <= C. A fact carrying tag A.
- **Action:** Project the tag-A fact.
- **Expect:** Route lookup `routes.iter().find(|r| r.tag == A)` selects the OLD projector A, never B; the find is by exact tag equality, never "highest active". Output is A-era rows.
- **Defends:** Invariant (5) READERS FOREVER — old fact readers kept forever and chosen by tag; Invariant (4).
- **Refs:** `RouterProjector::project` tag-equality find (projectors.rs:455); `FactRoute.tag`.

### ROUTE-12 — ceiling-filtered router EXCLUDES above-ceiling routes from active dispatch  `projector-unit`
- **Setup:** Build the ceiling-filtered router with ceiling C. `FACT_ROUTES` contains a route for tag T with `V(T) > C` (registered but above-ceiling). Also a tag U with `V(U) <= C`.
- **Action:** Inspect the active route set (or attempt dispatch of T vs U).
- **Expect:** T is NOT in the active dispatch set: receiving T stores it pending before projection (per ROUTE-05), not projected; U dispatches normally. The router's active routes == { routes with intro_version <= C }.
- **Defends:** "the ceiling-filtered router excludes above-ceiling routes from active dispatch"; Invariant (1)/(3).
- **Refs:** `RouterProjector` (projectors.rs:423) gains an intro_version-aware filter over `FACT_ROUTES`; ceiling C.

### ROUTE-13 — raising the ceiling adds the route to active dispatch (monotone activation)  `projector-unit`
- **Setup:** Ceiling C0 with tag T above-ceiling (`V(T) > C0`). Then ceiling C1 >= V(T).
- **Action:** Build router at C0 (assert T inactive), then build at C1 (assert T active); dispatch a tag-T fact under each.
- **Expect:** At C0: a received T is retained pending and not projected. At C1: the pending T re-enters admission and projects normally. Activation is gated solely by `intro_version <= ceiling` (plus transportability), and is monotone in the ceiling.
- **Defends:** Invariant (3) CEILING MONOTONICITY; "ceiling-active iff intro_version<=ceiling AND every still-usable release can transport it".
- **Refs:** ceiling-filtered `RouterProjector`; `FactRoute` intro_version; ceiling computation.

### ROUTE-14 — received fact whose tag is genuinely unknown becomes pending only if wire-admitted  `projector-unit`
- **Setup:** Ceiling-filtered router over `FACT_ROUTES`. Construct a fact with a first byte that is NOT any of the 47 registered tags and is NOT a declared-but-above-ceiling tag (e.g. tag 200, never registered, no intro_version).
- **Action:** Deliver the bytes through the receive/admission path.
- **Expect:** If the bytes made it through authenticated sync/transport with a stable id/hash, they are retained pending as unknown-tag bytes; they are not projected, parsed for context, or considered active truth. If the bytes are malformed or not wire-admitted, they drop. Current direct projector calls may still return the unknown-tag error; versioning's admission gate sits before that.
- **Defends:** Boundary of ADMISSION — unknown wire-admitted bytes may wait for a future binary, but are not silently active.
- **Refs:** future admission gate before `RouterProjector::project`; 47-route `FACT_ROUTES`; the current unknown-tag `Err` remains a direct-projector guard.

### ROUTE-15 — empty fact bytes are rejected/dropped before projection  `projector-unit`
- **Setup:** Ceiling-filtered router. A fact with zero bytes.
- **Action:** Deliver the empty bytes through the receive/admission path.
- **Expect:** The input is rejected/dropped before projection; no rows, no fact log entry, no forwarding. Current direct projector calls may still return `Err("cannot project empty fact bytes")`; admission should prevent empty network input from becoming protocol truth.
- **Defends:** Boundary of ADMISSION — there is no tag to gate or authenticate.
- **Refs:** `RouterProjector::effective_tag` empty-bytes guard (projectors.rs:434-436).

### ROUTE-16 — every FactRoute declares an intro_version (registry completeness)  `guardrail`
- **Setup:** Registry guardrail test in `registry.rs` tests module, alongside `fact_route_tags_are_globally_unique`.
- **Action:** Iterate `FACT_ROUTES`; for each entry read its `intro_version`.
- **Expect:** Every one of the 47 routes has a declared `intro_version` (compile-time: the `FactRoute` struct field is non-optional; runtime: each value is a sane u32, and the set of values is a subset of the protocol versions named by the bundle map). Today `FactRoute` has `{tag, projector, replayed}` — this test forces adding `intro_version` and populating all 47 in `projector_routes!`.
- **Defends:** "every fact route declares intro_version" — registry completeness.
- **Refs:** `FactRoute`; `projector_routes!` macro; 47 routes in `FACT_ROUTES`.

### ROUTE-17 — every HandlerRoute declares intro_version and runs_during_replay (registry completeness)  `guardrail`
- **Setup:** Registry guardrail over `HANDLER_ROUTES` (17 routes).
- **Action:** Iterate `HANDLER_ROUTES`; read each route's `intro_version` and `runs_during_replay`.
- **Expect:** All 17 routes declare `intro_version`; `runs_during_replay` is already a non-optional field and remains explicitly set. Network-side routes in `COMMAND_EXCLUDED_HANDLER_ROUTES` should have `runs_during_replay = false`.
- **Defends:** "every handler route declares intro_version"; HandlerRoute also carries runs_during_replay.
- **Refs:** `HandlerRoute`; `HANDLER_ROUTES`; `COMMAND_EXCLUDED_HANDLER_ROUTES`.

### ROUTE-18 — every CliCommand declares intro_version per run-fn bucket (registry completeness)  `guardrail`
- **Setup:** Registry guardrail over `MATCH_COMMANDS` (47 commands).
- **Action:** Iterate `MATCH_COMMANDS`; for each command read its version-tagged run-fn bucket(s).
- **Expect:** Each command maps a stable name to a list of `(intro_version, run_fn)` entries with at least one entry, each entry declaring an intro_version. Today `CliCommand` has a single bare `run` fn — this drives the version-bucket shape. All 47 names from the inventory present, including `key-rotate-recipient -> key_recipient_rotation`.
- **Defends:** "every cli route declares intro_version"; CliCommand = stable name -> version-tagged list of run fns.
- **Refs:** `CliCommand` / `cli_command!`; `MATCH_COMMANDS`; inventory section 2 (47 commands).

### ROUTE-19 — CLI version bucket selects highest intro_version <= ceiling  `blackbox-cli`
- **Setup:** A command whose input surface changed across versions, so it has two buckets: `(V_old, run_old)` and `(V_new, run_new)` with `V_old <= C < V_new` for ceiling C.
- **Action:** Invoke the command (e.g. `con send ...`) at ceiling C.
- **Expect:** `run_old` is selected (highest intro_version <= ceiling), NOT `run_new`. Behavior/output matches the V_old surface. At a raised ceiling C' >= V_new, `run_new` is selected.
- **Defends:** "ceiling selects the highest intro_version<=ceiling" for CLI buckets; Invariant (2) (render/act at the ceiling).
- **Refs:** `CliCommand` version buckets; `MATCH_COMMANDS`; ceiling C.

### ROUTE-20 — absent CLI bucket entry reuses the previous run fn under the param-subset contract  `guardrail`
- **Setup:** A command introduced at protocol version V_a with run fn R_a, and a later protocol version V_b > V_a that bundled a NEW fact for that command's family but did NOT change the input surface (no bucket entry at V_b).
- **Action:** Resolve the command at ceiling C = V_b (bucket has no V_b entry).
- **Expect:** Resolution reuses R_a (the previous bucket); the guardrail also asserts the param-subset contract `v_next.required_inputs ⊆ active_cli.collected_params` (the reused fn's collected params cover the new version's required inputs). No "missing run fn for ceiling" panic.
- **Defends:** "an ABSENT bucket entry => reuse previous (asserts parameter compatibility)"; param-subset contract.
- **Refs:** `CliCommand` bucket reuse rule; param-subset contract from model; `MATCH_COMMANDS`.

### ROUTE-21 — fact tags are globally unique across ALL versions of all families (extends fact_route_tags_are_globally_unique)  `guardrail`
- **Setup:** Extend `fact_route_tags_are_globally_unique` (registry.rs:717-729) to span every version-tagged route, including future `_vN/` sibling routes (e.g. tag 50 message:1 AND a future message:2 tag must both be distinct u8s).
- **Action:** Collect every `FactRoute.tag` across all version buckets into a set; check for duplicates; also assert no tag collides with the non-fact sealed envelope tags 46/47 or the TRNS magic's first byte usage.
- **Expect:** All tags distinct; zero duplicates. A new wire shape MUST take a NEW tag, never reuse an old family's tag. The 47 current routed tags (inventory section 1 map) all distinct (already passing); the test additionally guards future additions.
- **Defends:** "fact tags globally unique across all versions"; extends `fact_route_tags_are_globally_unique`; VERSIONING KNOB = new tag for incompatible shape.
- **Refs:** `fact_route_tags_are_globally_unique` (registry.rs:717-729); full tag map (inventory section 1); sealed tags 46/47 (NOT in FACT_ROUTES).

### ROUTE-22 — a new wire shape that reuses an existing tag fails the uniqueness guardrail  `guardrail`
- **Setup:** Deliberately add a second `FactRoute` reusing an existing tag (e.g. register a "message:2" projector under tag 50) in a test fixture / mutation.
- **Action:** Run the extended uniqueness guardrail (ROUTE-21).
- **Expect:** The guardrail FAILS, naming the duplicate tag 50, with the message that "fact tags must be globally unique so runtime dispatch never guesses between fact types". This proves the guardrail actually catches the wrong way to version (mutate-the-tag's-meaning) vs the right way (new tag).
- **Defends:** Negative case for "fact tags globally unique"; VERSIONING KNOB correctness.
- **Refs:** `fact_route_tags_are_globally_unique` (registry.rs:718-728); `FactRoute.tag`.

### ROUTE-23 — connection frame admits at ceiling and parks an above-ceiling INNER fact as pending  `projector-unit`
- **Setup:** Ceiling C. A `connection::frame_small` fact (tag 168, the TRNS container) whose decrypted inner bundle packs two content facts: one at-ceiling `content::message` (tag 50) and one above-ceiling inner fact (tag T, `V(T) > C`).
- **Action:** Open and project the frame_small container fact; materialize its recovered inner fact bytes and re-submit them through the ceiling-filtered router.
- **Expect:** The container fact admits and opens; the inner tag-50 message authenticates/projects and is counted/displayed; the inner above-ceiling fact T is retained pending, not counted, and not active. The container projection result is `Ok`; one pending inner fact does not fail the whole frame.
- **Defends:** ADMISSION pending applies to emitted inner fact bytes; Invariant (1); "connection frame is a CONTAINER FACT whose opened children re-enter authenticate/project by their own tags".
- **Refs:** `connection::frame_small` tag 168 `project_connection_frame_small`; `connection_frame_wire.rs` inner-bundle decode; ceiling admission gate; tag 50.

### ROUTE-24 — connection scope: above-ceiling NEW frame carrier drops if it cannot open, existing frame tags still admit  `projector-unit`
- **Setup:** Ceiling C. `FACT_ROUTES` has the four current frame routes (168/169/170/173) all <= C, plus a future frame variant tag T_frame with `V(T_frame) > C`. Receive a T_frame fact and a frame_small (168) fact.
- **Action:** Project both through the ceiling-filtered router.
- **Expect:** frame_small (168) admits and decrypts. T_frame drops if the current wire/frame layer cannot classify or open it; no inner facts exist locally. If a future frame's bytes can be carried by an active frame and recovered as inner fact bytes, those inner bytes use ROUTE-23 pending semantics.
- **Defends:** TRANSPORT vs ADMISSION boundary — wire-invalid carrier bytes drop; wire-admitted inner facts can become pending.
- **Refs:** `connection::frame_small/file_slice/bundle/observation` tags 168/169/170/173 (registry.rs:630-633); ceiling-filtered router.

### ROUTE-25 — auth scope: above-ceiling auth fact is refused on local create and pending on receive  `projector-unit`
- **Setup:** Ceiling C below the proposed `auth::user_profile_v2` intro_version (this family does NOT exist yet — inventory section 1 confirms absent; model it as the canonical above-ceiling auth tag with a registered-but-inactive route). Existing `auth::user` (tag 14) is at/below ceiling.
- **Action:** (a) Local: attempt to create a user_profile_v2 fact. (b) Receive: project a received user_profile_v2 fact through the ceiling-filtered router.
- **Expect:** (a) local creation REFUSED, nothing written. (b) received fact retained pending, with no auth rows, no authority grant, no purge effect, and no reader output. Meanwhile `auth::user` (14) admits and projects normally (e.g. `con users` lists existing users). Per-scope axis: auth behaves like content/connection.
- **Defends:** ADMISSION refuse(local)+pending(received) in the AUTH scope; per-scope enumeration; Invariant (1)/(3).
- **Refs:** `auth::user` tag 14 `project_user` (registry.rs:636); proposed `auth::user_profile_v2` (absent per inventory); ceiling-filtered router.

### ROUTE-26 — sync scope: above-ceiling sync fact variant is pending; existing sync facts admit  `projector-unit`
- **Setup:** Ceiling C. Existing `sync::shared_fact` (tag 162) and `sync::compare` (tag 165) at/below ceiling. A future sync variant tag T_sync with `V(T_sync) > C` arrives from a peer running a newer protocol.
- **Action:** Project the T_sync fact and a sync::compare (165) fact through the ceiling-filtered router.
- **Expect:** sync::compare admits and projects; T_sync is retained pending and not projected. A newer peer sending a future sync message must NOT crash the receiver or create active protocol truth. Per-scope axis: sync behaves like the others.
- **Defends:** ADMISSION pending in the SYNC scope; Invariant (1); robustness against a newer peer; per-scope enumeration.
- **Refs:** `sync::shared_fact` tag 162, `sync::compare` tag 165; ceiling-filtered admission gate.

### ROUTE-27 — multinode: newer peer's above-ceiling fact arrives as pending, not active  `multinode-network`
- **Setup:** Two `con` nodes. Node B runs a NEWER protocol head (V_b) and emits a fact at tag T with `V(T) = V_b`. Node A runs an older head; its local ceiling C_a < V(T). A and B are connected (post-bootstrap, sync running).
- **Action:** B sends the tag-T fact to A over a `connection::frame_*`; A receives it.
- **Expect:** A stores T pending, does not show it, does not project it, and does not use it for authority/purge. The connection may continue; after A's manifest fleet raises C_a >= V(T), A can re-run admission on the pending bytes without a network re-download.
- **Defends:** ADMISSION end-to-end: received above-ceiling input is pending, syncable, and inactive until the ceiling covers it; Invariant (1)/(5).
- **Refs:** `connection::frame_small` tag 168; `receive_network_frame` handler (registry.rs:705); `ReceiveNetworkFrameHandler`; `submit_fact` (runtime.rs:268); ceiling-filtered router.

### ROUTE-28 — pending above-ceiling bytes are syncable but remain inactive  `multinode-network`
- **Setup:** Node A received pending above-ceiling fact F (tag T) from newer node B. A is also connected to node X running the SAME old protocol as A (ceiling < V(T)).
- **Action:** Run sync between A and X (`share_fact_with_sync` path).
- **Expect:** A may advertise/serve F's pending bytes by id if the transport can carry them, so X can also store F pending. Neither A nor X projects, displays, counts, authorizes, or purges from F while their ceiling is below T. Pending sync prevents repeated download churn without activating future semantics.
- **Defends:** Invariant (1)/(3)/(5) — above-ceiling bytes may sync, but semantic activation is still ceiling-gated.
- **Refs:** `share_fact_with_sync` (registry.rs:676), `ShareFactWithSyncHandler`; `sync::shared_fact` tag 162; ceiling gate on offers.

### ROUTE-29 — pending fact materializes when ceiling rises, without re-download  `replay-cli`
- **Setup:** Node receives pending above-ceiling fact F (tag T received under C0), then the ceiling rises to C1 >= V(T).
- **Action:** wipe + replay at C1 (forward order, then assert order-independence with a `--scramble`-style reorder of the retained log if available; otherwise reverse-order replay).
- **Expect:** Admission promotes F from pending to active, then replay/projector dispatch sees the retained active fact; final derived state equals native-at-C1. Pending arrival order before activation does not affect the converged state.
- **Defends:** Invariant (4) REPLAY DETERMINISM — order-independent over retained active facts; pending is an input queue before admission.
- **Refs:** wipe+replay; ceiling-filtered router at C1; `FactRoute` tag T.

### ROUTE-30 — pending input is distinct from a normal empty projection  `projector-unit`
- **Setup:** Ceiling-filtered admission/projection path. Two facts: (a) a benign at-ceiling fact whose projector legitimately produces NO rows (a no-op admit), and (b) an above-ceiling input.
- **Action:** Deliver both through admission/projection and inspect store/read-model side effects.
- **Expect:** (a) is a normal admitted fact with whatever durable fact-log status its family normally has. (b) is retained pending, with no read-model rows and no `ProjectionOutput` bookkeeping. Pending is not silently collapsed into "projected with no rows".
- **Defends:** ADMISSION mechanism — above-ceiling input is syncable pending bytes, not an active no-op projection.
- **Refs:** future admission gate; `ProjectionOutput` remains projection-only.
## 5. Authors (`author.rs`) across new/old x scope

Scope of this cluster: the *author* layer (`author.rs` in the target shape; often
today's `create.rs` or a fact-builder plus `layout::encode_fact`) that emits a
brand-new local fact. Under the consolidated model local authoring is
version-bucketed: `fact/encode/decode/author/authenticate/adapt/project` per
version as needed. The version-neutral entry (the CLI run fn / intent handler)
must dispatch to the **ceiling-appropriate** `author.rs`, never the binary's
head. Local creation of an above-ceiling fact is **REFUSED** (admission rule).
**Ceiling-appropriate** means the highest bucket that is both `<= ceiling` and
has an `author`/`encode` path compiled into this build — i.e.
`min(ceiling, highest-authored-version)`. A build may sit *below* the ceiling on
purpose: a ceiling rise only *permits* a newer shape, and emission begins only in
the release that ships that family's write path, with the read side
(`decode`/`authenticate`/`adapt`/`project`) shipping ahead. The ceiling permits;
a deploy triggers. The stall is gated by what the build compiles in, not a
manifest opt-in flag — see Phase 1, "Permission ceiling vs. write activation."
Deterministic authors (`auth::key_wrap::create::create_key_wrap_fact` today,
`sync::need_id::create::fact` today, `sync::compare::create::start_compare_fact`
today) must reproduce identical bytes on replay (invariant 4).

Creation is deliberately called out because it is currently the least tidy part
of the protocol boundary. Command code, `create.rs`, `layout.rs`, crypto
transcripts, final encoding, and `Runtime::submit_fact` often know too much
about each other. The target write pipeline is explicit:

```text
cli args
  -> command run fn
  -> author
  -> encode
  -> authenticate self-check
  -> admit/submit
  -> read pipeline
```

- **Command** parses user/handler input, loads the needed store/context/key
  snapshot, checks blocked mode, selects the ceiling bucket, and calls the
  selected author. It does not build canonical bytes.
- **Author** performs local semantic construction. It signs, encrypts, assembles
  the typed fact value, chooses deterministic nonces from transcript helpers,
  and returns an authored value plus scope/timestamp/admission metadata.
- **Encode** owns every canonical byte string. Its transcript helpers produce the
  bytes fed to crypto — nonce seed inputs, AEAD associated data, signing bytes,
  and the final serialized fact. Those transcript bytes are not secrets and not
  semantic construction; they are the byte contract that authoring, decoding,
  and authentication share.
- **Authenticate self-check** runs the same family authenticator over locally
  authored bytes before the command reports success or returns a fact id.
  `Authenticated` admits; `Invalid` is a synchronous author/encode bug;
  `NeedsAuthentication` must resolve through the same auth-need machinery (or
  fail/park with a clear missing-context result), never silently skip the proof.
  For embedded-key signed facts this deliberately re-verifies the signature just
  produced, catching mismatches between signing bytes, final encoding, decoding,
  and verification before any bad local fact is emitted to peers.

Grounding note: today every family has a single live constructor (one `create.rs`
or one `fact.rs` + `layout::encode_fact` builder) and exactly one tag in
`FACT_ROUTES`. These tests describe the behavior a *second* bucket version (e.g.
`message:2`, `file:3`) must exhibit and the regressions the current
single-version code would show if a newer binary naively emitted its head. Where
a family has no `create.rs` today (reaction, file, file_slice, have_id,
recipient_key), the target role is still `author.rs`; the current implementation
uses the `FamilyFact` struct + `layout::encode_fact` as that authoring path.

Invariants referenced: (1) VISIBILITY, (2) RENDERING UNIFORMITY, (3) CEILING
MONOTONICITY, (4) REPLAY DETERMINISM, (5) READERS FOREVER / TRANSPORT [floor,head],
(6) SAFETY FLOOR. Plus the ADMISSION (refuse-above-ceiling) and version-neutral
dispatch mechanisms.

Carry this TODO list forward while the model families are being built:

- Model the full write pipeline for one signed/encrypted content family and one
  deterministic handler-authored family before fan-out.
- Move crypto transcript helpers into `encode.rs`; keep actual signing,
  encryption, and assembly in `author.rs`.
- Add a shared self-check helper that runs the family authenticator on authored
  bytes before durable admission, with explicit handling for
  `NeedsAuthentication`.
- Add guardrails that prevent command paths and handlers from bypassing the
  ceiling-selected author/encode/self-check boundary.
- After the model shape is accepted, migrate remaining `create.rs` and
  fact-builder paths mechanically instead of improvising per family.

---

### CREATE-01 — content::message create at ceiling emits the ceiling tag/version  `blackbox-cli`
- **Setup:** Single `con` binary whose head supports `message:2`. Fleet manifest pins ceiling = protocol 7, whose bundle includes `message:2` (i.e. `message:2.intro_version <= ceiling`). Trusted time fresh, not BLOCKED.
- **Action:** `con send <workspace> "hello"` (run fn `send` -> `content::message::cli` -> `content::message::commands::send_message`).
- **Expect:** Exactly one persisted fact with first byte `TYPE_CONTENT_MESSAGE = 50` produced by the `message_v2` constructor; `con messages` displays it; `con content-count` counts it. No pending, no "no target projector registered" error.
- **Defends:** Invariant (1) VISIBILITY + ceiling-active create; version-neutral dispatch selects the ceiling create.
- **Refs:** `protocol/content/message/commands.rs::send_message`, `content/message/encode.rs::TYPE_CONTENT_MESSAGE=50`, registry `MATCH_COMMANDS` `send`, `FACT_ROUTES` tag 50.

### CREATE-02 — content::message: newer binary below ceiling emits the CEILING version not its head  `blackbox-cli`
- **Setup:** `con` binary head supports `message:3` (newer than fleet). Manifest ceiling = protocol 7 (bundle has `message:2`, NOT `message:3` — some still-usable release on another platform only reaches `message:2`).
- **Action:** `con send <workspace> "below ceiling"`.
- **Expect:** The emitted message fact is the **`message_v2`** wire shape (the ceiling bucket), even though `create.rs` for `message_v3` exists in this binary. A peer on the older still-usable release admits, projects, and renders it. The binary does NOT emit `message_v3`.
- **Defends:** Invariant (1)+(2): clients render/create AT THE CEILING, not their head. Version-neutral dispatch chooses ceiling create.
- **Refs:** `content/message/commands.rs` (v2 vs v3 buckets), version-neutral run fn `send`, ceiling resolution over `ReleaseManifestEntry.supported_protocol`.

### CREATE-03 — content::message constructor refuses to emit above-ceiling  `guardrail`
- **Setup:** Binary head has a `message_v3` constructor compiled in (encoder EXISTS). Ceiling = protocol 7, `message_v3.intro_version` (say protocol 8) > ceiling.
- **Action:** Attempt to drive the `message_v3` create path directly (e.g. force-select the head bucket / submit a tag-for-v3 fact for local creation).
- **Expect:** Local creation is REFUSED with an admission error (above-ceiling local create rejected), NOT persisted, NOT silently downgraded into v2. The v3 encoder existing is not sufficient to emit.
- **Defends:** ADMISSION: "local creation of an above-ceiling fact is REFUSED" — even though the encoder exists.
- **Refs:** admission gate vs `core/runtime.rs::submit_fact@268`, `content/message/commands.rs` v3 bucket, ceiling check.

### CREATE-04 — content::reaction create at ceiling emits tag 52  `blackbox-cli`
- **Setup:** Ceiling bundle includes `reaction:1` (head version). Trusted time fresh.
- **Action:** `con react <message-id> <emoji>` (run fn `react` -> `content::message::cli`, builds `ContentReactionFact` via `reaction/layout::encode_fact`).
- **Expect:** One persisted fact first byte `TYPE_CONTENT_REACTION = 52`; reaction projects into `CONTENT_REACTIONS` read-model and renders against the target message.
- **Defends:** Invariant (1) VISIBILITY; per-scope (content/reaction) ceiling create.
- **Refs:** `protocol/content/reaction/fact.rs::ContentReactionFact`, `content/reaction/layout.rs` (tag 52), run fn `react`.

### CREATE-05 — content::reaction: newer binary below ceiling emits ceiling reaction shape  `blackbox-cli`
- **Setup:** Binary head supports `reaction:2`; ceiling bundle still pins `reaction:1`.
- **Action:** `con react <message-id> <emoji>`.
- **Expect:** Emitted reaction is the `reaction_v1` wire shape (tag 52, ceiling), not `reaction_v2`; older still-usable release admits and renders it.
- **Defends:** Invariant (2) render-at-ceiling; version-neutral reaction constructor selects ceiling builder not head.
- **Refs:** `content/reaction/fact.rs` v1 vs v2 builders, `reaction/layout::encode_fact`.

### CREATE-06 — content::file create at ceiling emits tag 54 + correct slice budget  `blackbox-cli`
- **Setup:** Ceiling bundle includes `file:3` (file head). Carrier capacity (file_slice frame, tag 169) is sufficient for `file:3`'s slice plan.
- **Action:** `con send-file <workspace> <path>` (run fn `send_file` -> `content::message::cli`, builds `ContentFileFact`).
- **Expect:** One descriptor fact first byte `TYPE_CONTENT_FILE = 54` with `slice_bytes`/`total_slices` consistent with the ceiling `file:3` slice plan; `con files` lists it.
- **Defends:** Invariant (1) VISIBILITY; carrier capacity GATES the file constructor version.
- **Refs:** `protocol/content/file/fact.rs::ContentFileFact`, `file/layout.rs` (tag 54), run fn `send_file`, file_slice carrier.

### CREATE-07 — content::file: newer binary below ceiling emits ceiling file version, gated by carrier  `blackbox-cli`
- **Setup:** Binary head supports `file:4` (e.g. larger slices); ceiling = protocol 7 with `file:3`. The fleet's frame_file_slice carrier (tag 169) only carries `file:3`-sized slices.
- **Action:** `con send-file <workspace> <large file>`.
- **Expect:** Descriptor emitted as `file_v3` (ceiling), slices sized to fit the ceiling frame_file_slice capacity; `file_v4` constructor is NOT used. Slices transport to an older still-usable peer.
- **Defends:** Invariants (1)+(2); "Carrier capacity GATES ceiling activation (chunk-don't-grow; the file_slice precedent)."
- **Refs:** `content/file/fact.rs` v3/v4 buckets, `connection_frame_wire.rs::CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES`, frame_file_slice tag 169.

### CREATE-08 — content::file_slice create at ceiling emits tag 55  `blackbox-cli`
- **Setup:** Ceiling bundle includes the head `file_slice` version. A `content::file` descriptor already exists.
- **Action:** Send a file large enough to require slices (`con send-file`), driving `content::file_slice` constructor (`file_slice/fact.rs` builder).
- **Expect:** Each slice fact has first byte `TYPE_CONTENT_FILE_SLICE = 55`, projects into `FILE_SLICES` read-model; slice count matches the descriptor's `total_slices`.
- **Defends:** Invariant (1); per-scope (content/file_slice) ceiling create.
- **Refs:** `protocol/content/file_slice/fact.rs`, `file_slice/layout.rs` (tag 55), `FILE_SLICES` read-model.

### CREATE-09 — content::file_slice: bytes-per-slice stays at the CEILING-sized chunk  `property`
- **Setup:** Binary head defines a `file_slice` v-next with a *larger* plaintext slot; ceiling pins the current `file_slice` size. `CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES` derives from `file_slice::layout::CONTENT_FILE_SLICE_BYTES`.
- **Action:** Property test over many file sizes: construct slices below ceiling vs at ceiling.
- **Expect:** For any file, the slice plaintext size chosen equals the ceiling `CONTENT_FILE_SLICE_BYTES`, never the larger head size, so frames stay within `CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES`. Growing the chunk is refused; chunk-count grows instead.
- **Defends:** Invariant (5)+(2): chunk-don't-grow; carrier gates the slice constructor version.
- **Refs:** `file_slice/layout.rs::CONTENT_FILE_SLICE_BYTES`, `connection_frame_wire.rs` file_slice sizing.

### CREATE-10 — content::file_deletion create at ceiling emits tag 53  `blackbox-cli`
- **Setup:** Ceiling bundle includes head `file_deletion`. A file exists.
- **Action:** `con delete-file <file-id>` (run fn `delete_file` -> `content::file_deletion::cli` -> `content::file_deletion::create`).
- **Expect:** One fact first byte `TYPE_CONTENT_FILE_DELETION = 53` from the ceiling `file_deletion` constructor; projects into `FILE_DELETIONS`, file disappears from `con files`.
- **Defends:** Invariant (1); per-scope (content/file_deletion) ceiling create.
- **Refs:** `protocol/content/file_deletion/create.rs`, `file_deletion/layout.rs` (tag 53), run fn `delete_file`, `FILE_DELETIONS`.

### CREATE-11 — content::message_deletion (deletions) create at ceiling emits tag 51  `blackbox-cli`
- **Setup:** Ceiling bundle includes head `message_deletion`. A message exists.
- **Action:** `con delete-message <message-id>` (run fn `delete_message` -> `content::message::cli`, which uses `content::message_deletion::create`).
- **Expect:** One fact first byte `TYPE_CONTENT_MESSAGE_DELETION = 51` from the ceiling `message_deletion` constructor; projects into `MESSAGE_TOMBSTONES`/`MESSAGE_DELETIONS`, message hidden in `con messages`.
- **Defends:** Invariant (1); per-scope (content/message_deletion = the "deletions" scope) ceiling create.
- **Refs:** `protocol/content/message_deletion/create.rs`, `message_deletion/layout.rs` (tag 51), run fn `delete_message`.

### CREATE-12 — deletions constructor: newer binary below ceiling emits ceiling deletion shape  `blackbox-cli`
- **Setup:** Binary head supports `message_deletion:2`; ceiling pins `message_deletion:1`.
- **Action:** `con delete-message <message-id>`.
- **Expect:** Deletion fact is `message_deletion_v1` (ceiling tag 51 shape), not v2; older still-usable peer admits the tombstone and hides the message identically.
- **Defends:** Invariant (2): render/create at ceiling; deletions must be transportable by every still-usable release.
- **Refs:** `content/message_deletion/create.rs` v1/v2 buckets, run fn `delete_message`.

### CREATE-13 — auth::user create at ceiling emits tag 14  `blackbox-cli`
- **Setup:** Ceiling bundle includes head `auth::user`. Workspace + invite present.
- **Action:** Accept an invite path that drives `auth::user::commands` to construct the user fact (`con accept ...`).
- **Expect:** One fact first byte `TYPE_USER = 14` from the ceiling `user` constructor; `con users` lists the user.
- **Defends:** Invariant (1); per-scope (auth/user) ceiling create.
- **Refs:** `protocol/auth/user/commands.rs`, `auth/user/layout.rs` (tag 14), run fn `accept`, `con users`.

### CREATE-14 — auth::user_profile_v2 is a NEW family => new tag + new bucket, no editing old `auth::user`  `guardrail`
- **Setup:** Plan introduces `auth::user_profile_v2` as a *new* fact family (confirmed absent today). It gets its own `layout.rs` with a brand-new unique tag, its own `create.rs`, its own `_vN` directory, and one new `FACT_ROUTES` entry.
- **Action:** Add the family; run `cargo test fact_route_tags_are_globally_unique` (registry.rs 717-729) and confirm `auth::user` (tag 14) source is unchanged.
- **Expect:** `user_profile_v2` has a distinct tag not colliding with the 47 existing routed tags; `FACT_ROUTES` count becomes 48; `auth::user/create.rs` and `layout.rs` are byte-identical to before (the new family is additive, not an edit of the old code).
- **Defends:** VERSIONING KNOB = fact tag: "an incompatible wire shape => a NEW tag + a NEW kept-forever projector + a sibling _vN/ directory ... No editing old code." Invariant (5) READERS FOREVER.
- **Refs:** absence of `auth::user_profile_v2` (inventory §1), `registry.rs::FACT_ROUTES`, `fact_route_tags_are_globally_unique`.

### CREATE-15 — auth::user_profile_v2 create refused while below ceiling  `guardrail`
- **Setup:** `user_profile_v2` family compiled in with `intro_version = protocol 8`; ceiling = protocol 7 (a still-usable release cannot transport `user_profile_v2`).
- **Action:** Attempt local creation of a `user_profile_v2` fact (its constructor exists).
- **Expect:** REFUSED as above-ceiling; not persisted. A capability is CEILING-ACTIVE only iff `intro_version <= ceiling AND every still-usable release can transport it`; here it is not active.
- **Defends:** ADMISSION + capability-active definition; invariant (3) CEILING MONOTONICITY (don't introduce a capability the fleet can't carry).
- **Refs:** `auth::user_profile_v2::create` (new), ceiling = min over still-usable releases of `supported_protocol.end()`.

### CREATE-16 — auth::key_wrap deterministic create reproduces identical bytes on replay  `replay-cli`
- **Setup:** Workspace with a recipient key, source secret, signer secret. A `create_key_wrap` intent has already produced a `key_wrap` fact (tag 155) once.
- **Action:** Wipe derived state and replay; the `CreateKeyWrapHandler` re-runs `create_key_wrap_intent` -> `auth::key_wrap::create::create_validated_key_wrap_fact` from the same input facts.
- **Expect:** The recreated `key_wrap` fact is BYTE-IDENTICAL (same `sender_wrap_public_key`, `nonce`, `ciphertext`, fact id) — the constructor uses `deterministic_sender_wrap_secret` + `deterministic_nonce` keyed only off the intent + recipient + source. Replay is idempotent.
- **Defends:** Invariant (4) REPLAY DETERMINISM: "recreates only deterministic facts"; deterministic constructor reproduces identical bytes.
- **Refs:** `auth/create_key_wrap.rs::create_key_wrap_intent` + `create_key_wrap_key`, `auth/key_wrap/create.rs::create_key_wrap_fact` (`deterministic_sender_wrap_secret`, `deterministic_nonce`), tag 155.

### CREATE-17 — create_key_wrap intent key is a pure function of inputs (replay-stable idempotence key)  `handler-unit`
- **Setup:** A fixed `CreateKeyWrapIntent` (workspace, frontier, recipient_key_id, source_fact_id, signer_secret_fact_id, source kind).
- **Action:** Call `create_key_wrap_intent(...)` twice with identical inputs; also `decode_create_key_wrap_intent` round-trips.
- **Expect:** Both intents have an identical 212-byte payload and identical `key` (from `create_key_wrap_key`); decode validates `create_key_wrap_key(input) == intent.key`. No timestamp/random in the key => replay produces the same idempotence key, so the wrap is created exactly once.
- **Defends:** Invariant (4); deterministic constructor entry is order/time-independent.
- **Refs:** `auth/create_key_wrap.rs::{create_key_wrap_intent, create_key_wrap_key, encode_create_key_wrap_payload, decode_create_key_wrap_intent}` (212-byte payload, payload[0]==1).

### CREATE-18 — auth::key_wrap create at ceiling emits tag 155 via version-neutral handler dispatch  `blackbox-cli`
- **Setup:** Ceiling bundle includes head `key_wrap`. Recipient + source + signer present.
- **Action:** `con key-wrap ...` (run fn `key_wrap` -> `auth::key_wrap::cli`), which submits a `create_key_wrap` intent handled by `CreateKeyWrapHandler`.
- **Expect:** One fact first byte `TYPE_KEY_WRAP = 155` from the ceiling `key_wrap` constructor; `con keys` reflects it. The HANDLER_ROUTES `create_key_wrap` route dispatched to the ceiling-appropriate `create.rs`.
- **Defends:** Invariant (1); version-neutral intent-handler entry dispatches to ceiling create.
- **Refs:** `HANDLER_ROUTES` `create_key_wrap` -> `CreateKeyWrapHandler`, `auth/key_wrap/create.rs`, run fn `key_wrap`, tag 155.

### CREATE-19 — auth::key_wrap: newer binary below ceiling emits ceiling key_wrap shape  `handler-unit`
- **Setup:** Binary head supports `key_wrap:2` (e.g. new wrapped-secret kind); ceiling pins `key_wrap:1`.
- **Action:** Submit a `create_key_wrap` intent; handler resolves the ceiling-appropriate constructor.
- **Expect:** Emitted wrap is `key_wrap_v1` (tag 155 ceiling shape); a still-usable older release `unwrap_key_wrap` (UnwrapKeyWrapHandler) can open it. The v2 constructor is not used below ceiling.
- **Defends:** Invariant (2)+(1); create at ceiling; transportability by every still-usable release.
- **Refs:** `auth/key_wrap/create.rs` v1/v2 buckets, `HANDLER_ROUTES` `create_key_wrap`/`unwrap_key_wrap`.

### CREATE-20 — auth::recipient_key create at ceiling emits tag 150  `blackbox-cli`
- **Setup:** Ceiling bundle includes head `recipient_key`. Workspace + endpoint present.
- **Action:** `con key-recipient ...` (run fn `key_recipient` -> `auth::key_wrap::cli`), constructing a `RecipientKeyFact` via `recipient_key/layout::encode`.
- **Expect:** One fact first byte `TYPE_RECIPIENT_KEY = 150` from the ceiling recipient_key builder; supersedes any prior key per `previous_recipient_key_id`; `con keys` reflects it.
- **Defends:** Invariant (1); per-scope (auth/recipient_key) ceiling create.
- **Refs:** `protocol/auth/recipient_key/fact.rs::RecipientKeyFact`, `recipient_key/layout.rs` (tag 150), run fn `key_recipient`.

### CREATE-21 — auth::recipient_key: newer binary below ceiling emits ceiling recipient_key shape  `blackbox-cli`
- **Setup:** Binary head supports `recipient_key:2`; ceiling pins `recipient_key:1`.
- **Action:** `con key-rotate-recipient ...` (run fn `key_recipient_rotation`).
- **Expect:** Rotated recipient key emitted as `recipient_key_v1` (tag 150 ceiling shape), not v2; older still-usable release admits it and the key-wrap chain continues.
- **Defends:** Invariant (2); create at ceiling. Also exercises the `key-rotate-recipient` -> `key_recipient_rotation` mapping.
- **Refs:** `auth/recipient_key/fact.rs` v1/v2 builders, run fn `key_recipient_rotation` (note: NOT `key_rotate_recipient`).

### CREATE-22 — connection::request create at ceiling emits tag 42  `blackbox-cli`
- **Setup:** Two nodes; ceiling bundle includes head `connection::request`. Initiator has an invite secret.
- **Action:** Drive a connection bootstrap from node A (`con accept`/link flow), which constructs a `ConnectionRequestFact` via `connection::request::create` + `commands.rs`.
- **Expect:** One durable request fact first byte `TYPE_CONNECTION_REQUEST = 42` from the ceiling constructor, signed via `invite_signing_transcript`; node B's request projector admits it.
- **Defends:** Invariant (1); per-scope (connection/request) ceiling create.
- **Refs:** `protocol/connection/request/create.rs::invite_signing_transcript`, `connection/request/commands.rs`, `request/layout.rs` (tag 42).

### CREATE-23 — connection::request: newer initiator below ceiling emits ceiling request shape  `multinode-network`
- **Setup:** Node A binary head supports `connection::request:2`; fleet ceiling pins `request:1`. Node B is an older still-usable release that only speaks `request:1`.
- **Action:** A initiates a connection to B.
- **Expect:** A constructs `request_v1` (tag 42 ceiling shape), B admits and replies; A does NOT emit `request_v2`. (Transport may negotiate up only between two `request:2`-capable peers; against unknown/older B it initiates at the operational floor.)
- **Defends:** Invariant (1)+(2)+(5); TRANSPORT: "initiate at the operational floor when the peer is unknown; answer in the request's version".
- **Refs:** `connection/request/create.rs` v1/v2 buckets, `send_bootstrap_request.rs`, request tag 42.

### CREATE-24 — connection::response create at ceiling emits tag 44  `blackbox-cli`
- **Setup:** Two nodes; ceiling bundle includes head `connection::response`. A valid request fact exists at B.
- **Action:** B's `create_connection_response` intent (CreateConnectionResponseHandler) runs `connection::response::create`.
- **Expect:** One response fact first byte `TYPE_CONNECTION_RESPONSE = 44` from the ceiling constructor; A's response projector admits it and the connection opens.
- **Defends:** Invariant (1); per-scope (connection/response) ceiling create; version-neutral handler dispatch.
- **Refs:** `protocol/connection/response/create.rs`, `connection/create_connection_response.rs::CreateConnectionResponseHandler`, `response/layout.rs` (tag 44), `HANDLER_ROUTES` `create_connection_response`.

### CREATE-25 — connection::response answers in the request's version, not the responder's head  `multinode-network`
- **Setup:** Responder B binary head supports `response:2`; an incoming `request_v1` from an older still-usable A; fleet ceiling pins `response:1`.
- **Action:** B handles `create_connection_response`.
- **Expect:** B constructs `response_v1` (tag 44 ceiling shape) matching the request's era; A (older still-usable) admits it. B does not answer with `response_v2`.
- **Defends:** Invariant (1)+(2); TRANSPORT: "answer in the request's version for a still-usable older peer." Create-at-ceiling.
- **Refs:** `connection/response/create.rs` v1/v2 buckets, `create_connection_response.rs`, response tag 44.

### CREATE-26 — sync::compare deterministic create reproduces identical summary bytes  `replay-cli`
- **Setup:** A fixed connection id and a fixed set of `available_facts`. A `sync::compare` fact (tag 165) was produced once via `start_compare_fact`.
- **Action:** Re-run `sync::compare::create::start_compare_fact(connection_id, available_facts)` with the same inputs (and replay path).
- **Expect:** The compare fact is byte-identical: same `RangeSummary` from `summarize_range`, same `TimestampRange::ROOT`, same `connection_id`, `response_requested = true`, timestamp 0 (global). Determinism holds regardless of fact iteration order (summary is order-independent).
- **Defends:** Invariant (4) REPLAY DETERMINISM (order-independent, deterministic constructor); per-scope (sync/compare).
- **Refs:** `protocol/sync/compare/create.rs::{start_compare_fact, start_compare_fact_with_summary, summarize_range}`, `compare/layout.rs` (tag 165).

### CREATE-27 — sync::compare create at ceiling emits tag 165 via SendSyncCompareResponseHandler  `handler-unit`
- **Setup:** Ceiling bundle includes head `sync::compare`. A connection is seeded.
- **Action:** The `send_sync_compare_response` intent (SendSyncCompareResponseHandler) runs `compare::create::response_plan`/`response_facts`.
- **Expect:** Emitted compare/response facts carry first byte `TYPE_SYNC_COMPARE = 165` from the ceiling constructor; child compares and `send_fact_ids` are planned. No above-ceiling tags emitted.
- **Defends:** Invariant (1); per-scope (sync/compare) ceiling create; version-neutral handler dispatch.
- **Refs:** `sync/compare/create.rs::response_plan`, `sync/send_compare_response.rs::SendSyncCompareResponseHandler`, `HANDLER_ROUTES` `send_sync_compare_response`, tag 165.

### CREATE-28 — sync::compare: newer binary below ceiling emits ceiling compare shape  `handler-unit`
- **Setup:** Binary head supports `compare:2` (e.g. richer summary fields); ceiling pins `compare:1`.
- **Action:** Run `send_sync_compare_response` against an older still-usable peer's compare.
- **Expect:** Emitted compare is `compare_v1` (tag 165 ceiling shape); the older peer parses the summary. `compare_v2` constructor unused below ceiling.
- **Defends:** Invariant (2); create at ceiling; sync must be transportable by every still-usable release.
- **Refs:** `sync/compare/create.rs` v1/v2 buckets, `send_compare_response.rs`.

### CREATE-29 — sync::have_id create at ceiling emits tag 166  `handler-unit`
- **Setup:** Ceiling bundle includes head `sync::have_id`. A compare response decides to advertise ids. (have_id has no `create.rs`; the constructor is `SyncHaveIdFact` + `have_id/layout::encode_fact` inside the sync handlers.)
- **Action:** Run the compare-response path that emits have-id advertisements (`SendSyncCompareResponseHandler` -> have_id builder).
- **Expect:** Each have-id fact first byte `TYPE_SYNC_HAVE_ID = 166` from the ceiling builder; peer maps them to need-ids.
- **Defends:** Invariant (1); per-scope (sync/have) ceiling create even with no `create.rs` (fact+layout is the constructor).
- **Refs:** `protocol/sync/have_id/fact.rs::SyncHaveIdFact`, `have_id/layout.rs` (tag 166), `send_compare_response.rs`.

### CREATE-30 — sync::need_id deterministic create reproduces identical bytes  `handler-unit`
- **Setup:** A fixed `SyncNeedIdFact` body and a fixed timestamp. A need-id fact (tag 167) was produced once via `need_id::create::fact`.
- **Action:** Re-call `sync::need_id::create::fact(body, timestamp)` with identical body+timestamp (and on replay).
- **Expect:** Byte-identical need-id fact: `FactScope::Global`, same timestamp, same `layout::encode_fact(&body)`. The constructor is a pure function of (body, timestamp) — no hidden state.
- **Defends:** Invariant (4) REPLAY DETERMINISM (deterministic constructor); per-scope (sync/need).
- **Refs:** `protocol/sync/need_id/create.rs::fact`, `need_id/layout.rs` (tag 167), `SendNeededFactIdHandler`.

### CREATE-31 — sync::need_id create at ceiling emits tag 167 via SendNeededFactIdHandler  `handler-unit`
- **Setup:** Ceiling bundle includes head `sync::need_id`. A have-id advertised a fact missing locally.
- **Action:** `send_needed_fact_id` intent (SendNeededFactIdHandler) calls `need_id::create::fact`.
- **Expect:** One need-id fact first byte `TYPE_SYNC_NEED_ID = 167` from the ceiling constructor; triggers the peer's `send_requested_fact`.
- **Defends:** Invariant (1); per-scope (sync/need) ceiling create; version-neutral handler dispatch.
- **Refs:** `sync/need_id/create.rs::fact`, `sync/send_needed_fact_id.rs::SendNeededFactIdHandler`, `HANDLER_ROUTES` `send_needed_fact_id`, tag 167.

### CREATE-32 — sync::need_id: newer binary below ceiling emits ceiling need_id shape  `handler-unit`
- **Setup:** Binary head supports `need_id:2`; ceiling pins `need_id:1`.
- **Action:** Run `send_needed_fact_id` against an older still-usable peer.
- **Expect:** Emitted need-id is `need_id_v1` (tag 167 ceiling shape); older peer's `send_requested_fact` understands it. `need_id_v2` unused below ceiling.
- **Defends:** Invariant (2); create at ceiling.
- **Refs:** `sync/need_id/create.rs` v1/v2 buckets, `send_needed_fact_id.rs`.

### CREATE-33 — version-neutral CLI entry reuses previous bucket's create when v-next adds NO new create  `handler-unit`
- **Setup:** Protocol bumps `message` to v-next that changes ONLY projection (read-model), not the wire/constructor: there is no `message_v_next/create.rs`, and no new `cli` bucket (input surface unchanged). Ceiling rises to include v-next.
- **Action:** `con send <workspace> "x"` resolves the constructor bucket.
- **Expect:** With an ABSENT create/cli bucket at v-next, the version-neutral entry REUSES the previous version's `create.rs` (asserts param-subset compatibility: `v_next.required_inputs ⊆ active_cli.collected_params`). Same bytes as before the bump for the fact; only the derived read-model differs.
- **Defends:** "an ABSENT bucket entry => reuse previous"; VERSION BUCKETS "cli ONLY if the input surface changed (absent=reuse prev)"; invariant (2) (new derivation withheld until ceiling-active but constructor unchanged).
- **Refs:** `MATCH_COMMANDS` `send` run fn, version-bucket reuse contract, `content/message/commands.rs`.

### CREATE-34 — version-neutral entry dispatches by ceiling without editing old create.rs  `guardrail`
- **Setup:** Two buckets exist: `message/create.rs` (v1, kept forever) and `message_v2/create.rs` (new). The version-neutral `send` run fn picks the highest `intro_version <= ceiling`.
- **Action:** Inspect dispatch: set ceiling to the v1 era, then to the v2 era; observe which `create.rs` is invoked. Confirm `message/create.rs` (v1) source is unchanged by the v2 addition.
- **Expect:** Ceiling=v1-era -> v1 `create.rs` invoked; ceiling=v2-era -> v2 `create.rs` invoked. The v1 file is byte-identical pre/post the v2 addition (additive sibling `_vN/`, not an edit). Dispatch is data-driven off the bucket table + ceiling.
- **Defends:** "the version-neutral constructor entry dispatches to the ceiling-appropriate create.rs without editing old code"; invariant (5) READERS FOREVER.
- **Refs:** `MATCH_COMMANDS`/`cli_command!` macro, ceiling resolution, `content/message/commands.rs` v1 vs sibling v2.

### CREATE-35 — above-ceiling refusal applies in BLOCKED MODE too (no above-ceiling create when stale)  `guardrail`
- **Setup:** Ceiling would be protocol 8 if fresh, but trusted time is past the staleness window S without refresh => BLOCKED MODE. Effective production ceiling withheld.
- **Action:** Attempt `con send` resolving a v-next constructor that requires the higher ceiling.
- **Expect:** Construction uses the last safely-attested ceiling bucket (not the unattested higher one); above-ceiling create is REFUSED while blocked. Local reads + replay still run, but shared production of the higher-version fact is withheld.
- **Defends:** TRUSTED TIME / BLOCKED MODE: "shared production withheld; local reads + replay still run"; ADMISSION refuse-above-ceiling.
- **Refs:** trusted-time staleness window S, ceiling resolution, `content/message/commands.rs` bucket selection.

### CREATE-36 — constructor never emits the sealed envelope tags (46/47) as routed facts  `guardrail`
- **Setup:** Bootstrap handshake constructors (`connection::request`/`response` create) and the sealed-frame APIs in `bootstrap_request/layout.rs`.
- **Action:** Construct a bootstrap request; inspect the durable fact vs the sealed network frame.
- **Expect:** The durable/local fact carries `TYPE_CONNECTION_BOOTSTRAP_REQUEST = 171` (routed) and the sealed network frame carries `TYPE_SEALED_CONNECTION_REQUEST = 46` with internal `VERSION = 1` (NOT in FACT_ROUTES). No constructor ever emits 46/47 as a routed fact, so the sealed envelope's internal version byte never participates in fact-tag versioning.
- **Defends:** VERSIONING KNOB = fact tag for routed facts; "No internal version bytes for routed facts"; the sealed VERSION byte is a socket/stream concern only.
- **Refs:** `connection/bootstrap_request/layout.rs` (TYPE_CONNECTION_BOOTSTRAP_REQUEST=171, TYPE_SEALED_CONNECTION_REQUEST=46, internal VERSION:u8=1), inventory §4.
## 6. CLI commands, version buckets, compatibility contract

Scope note. The model under test versions a `CliCommand` (`src/core/cli.rs:82`)
from today's single `run: fn(&mut C, CliArgs) -> Result<CliOutput, String>`
field into a STABLE NAME bound to a version-tagged list of run fns. Ceiling
selects the run fn with the highest `intro_version <= ceiling`. A version
bucket carries a `cli/` delta ONLY when the input surface changed; an ABSENT
bucket entry means the previous parser is REUSED, which is sound only under the
param-subset contract `v_next.required_inputs ⊆ active_cli.collected_params`.
Real commands exercised: `send`, `react`, `send-file`, `delete-message`,
`grant-admin`, `invite`, `disappearing-set` (all in `MATCH_COMMANDS`,
`src/protocol/registry.rs:367`). Today's code has a single run fn per command,
so the structural/guardrail tests below are written against the model the bucket
layout introduces; the black-box tests assert behavior already observable on
`con`. Anchors: `cli_command!` macro (registry.rs:356), `core::cli::run`
dispatch (cli.rs:94), name-uniqueness check `validate_command_names`
(cli.rs:115), `CliArgs::require_len`/`get`/`values`.

### CLI-01 — `send` name resolves identically at ceiling v1 and ceiling v2  `blackbox-cli`
- **Setup:** One `con` binary; a created workspace `W`; manifest pins ceiling to
  protocol v1 (the version that introduced `content::message` tag 50). Run twice
  in two DBs, one at ceiling v1 and one at a manifest that raises ceiling to v2.
- **Action:** `con --db DB send <W_hex> "hello"` under each ceiling.
- **Expect:** Both invocations dispatch via `core::cli::run` to the command
  named `send` (no "unknown command"), both emit `send_output` lines
  `workspace_id:`, `fact_id:`, `message_id:`, `created_at_ms:`, `text: hello`.
  The command NAME `send` is stable; only the bound run fn may differ by ceiling.
- **Defends:** Stable-name contract (CliCommand name constant across versions);
  invariant (1) visibility — a ceiling-active command works at every ceiling
  >= its intro.
- **Refs:** `MATCH_COMMANDS` send entry (registry.rs:452), `content::message::cli::send`/`SEND_USAGE`, `core::cli::run`.

### CLI-02 — ceiling below introducing version selects the v1 `send` run fn  `handler-unit`
- **Setup:** `send` modeled with a two-entry run-fn list:
  `{intro_version:1 -> send_v1, intro_version:2 -> send_v2}`. Ceiling = 1.
- **Action:** Resolve the run fn for command `send` at ceiling 1.
- **Expect:** The resolver returns `send_v1` (highest `intro_version <= 1`); the
  `intro_version:2` entry is NOT selected because 2 > 1.
- **Defends:** "ceiling selects highest intro_version<=ceiling"; v1 parser below
  the introducing version of v2.
- **Refs:** modeled run-fn list over `content::message::cli`; `CliCommand.run` field (core/cli.rs:90).

### CLI-03 — ceiling at/after introducing version selects the v2 `send` run fn  `handler-unit`
- **Setup:** Same two-entry `send` run-fn list as CLI-02. Ceiling = 2.
- **Action:** Resolve the run fn for command `send` at ceiling 2.
- **Expect:** Resolver returns `send_v2` (highest `intro_version <= 2`).
- **Defends:** v2 surface activates at/after its intro_version; the {v2}/{at-or-after} axis.
- **Refs:** modeled `send` run-fn list; ceiling selection logic.

### CLI-04 — ceiling strictly between two cli buckets selects the lower bucket  `handler-unit`
- **Setup:** `send` run-fn list `{1 -> send_v1, 3 -> send_v3}` (NO v2 cli entry).
  Ceiling = 2.
- **Action:** Resolve the run fn for `send` at ceiling 2.
- **Expect:** Resolver returns `send_v1` (highest intro_version <= 2 is 1, since
  3 > 2). It does NOT fall through to `send_v3` and does NOT error.
- **Defends:** "ceiling selects the highest intro_version<=ceiling" when ceiling
  lands in a gap; lower-bound selection, not nearest or highest.
- **Refs:** modeled `send` run-fn list.

### CLI-05 — bucket with NO cli.rs reuses the previous parser  `guardrail`
- **Setup:** Protocol bump from v1 to v2 changes `content::message` wire shape
  (new tag) but the `send` INPUT surface is unchanged (still
  `send WORKSPACE_ID_HEX TEXT`, `SEND_USAGE`). The `message/_v2/` bucket has
  `layout/fact/project/create` but NO `cli/`.
- **Action:** At ceiling 2, resolve the run fn for `send`.
- **Expect:** The resolver reuses the v1 `send` parser (the active cli surface);
  no new run fn is introduced for v2. The same `SEND_USAGE` string is printed.
- **Defends:** "absent bucket entry => reuse previous"; bucket carries cli ONLY
  when the input surface changed.
- **Refs:** `content::message::cli` SEND_USAGE; modeled `message/_v2/` bucket layout.

### CLI-06 — param-subset contract holds: v2 constructor satisfiable from v1 params  `guardrail`
- **Setup:** `send_v2` constructor `required_inputs = {workspace_id, text}`. The
  active (v1) `send` parser `collected_params = {workspace_id, text}` (from
  `SEND_USAGE = "send WORKSPACE_ID_HEX TEXT"`).
- **Action:** Assert `v2.required_inputs ⊆ active_cli.collected_params`.
- **Expect:** Subset holds (`{workspace_id,text} ⊆ {workspace_id,text}`), so the
  v2 message fact is constructible from prior params; the absent-cli reuse from
  CLI-05 is sound.
- **Defends:** param-subset contract guardrail
  (`v_next.required_inputs ⊆ active_cli.collected_params`); invariant (1).
- **Refs:** `content::message::cli::send` (cli.rs:67-75), `SEND_USAGE`,
  `message::commands::send_message`.

### CLI-07 — param-subset contract VIOLATED: new required param with no cli bucket fails the gate  `guardrail`
- **Setup:** `send_v2` constructor now also requires `thread_id` (a NEW required
  input), but the `message/_v2/` bucket ships NO `cli/`. Active parser still
  collects only `{workspace_id, text}`.
- **Action:** Run the param-subset guardrail check at bucket-assembly time.
- **Expect:** Check FAILS: `{workspace_id, text, thread_id} ⊄ {workspace_id, text}`.
  The guardrail forbids shipping v2 without a new `send` cli bucket; this is a
  compile/registry-time error, not a runtime surprise.
- **Defends:** param-subset contract as a guardrail — a new required input MUST
  come with a cli delta; protects invariant (1) admissibility.
- **Refs:** modeled `message/_v2/` bucket missing cli; `content::message::cli::send`.

### CLI-08 — `react` reuses v1 parser when v2 reaction changes only ciphertext capacity  `guardrail`
- **Setup:** v2 `content::reaction` (tag 52) enlarges `REACTION_CIPHERTEXT_BYTES`
  but keeps inputs `react WORKSPACE_ID_HEX MESSAGE_SELECTOR EMOJI`. No `reaction`
  cli bucket (reaction has no cli.rs today; `react` lives in
  `content::message::cli`).
- **Action:** At ceiling 2, resolve `react`'s run fn and check the subset.
- **Expect:** v1 `react` parser reused; `react_v2.required_inputs =
  {workspace_id, message_selector, emoji} ⊆ collected_params`. The length guard
  (`emoji.len() > REACTION_CIPHERTEXT_BYTES - TAG_BYTES`) widens but inputs are
  identical.
- **Defends:** absent-cli reuse + param-subset for a capacity-only wire bump.
- **Refs:** `content::message::cli::react` (cli.rs:112-163), `REACT_USAGE`,
  `reaction::fact::REACTION_CIPHERTEXT_BYTES`.

### CLI-09 — above-ceiling write command is REFUSED in production (local admission)  `blackbox-cli`
- **Setup:** A modeled write command whose run fn constructs a fact at
  intro_version 3 (e.g. a v3-only `send` variant). Manifest pins ceiling = 2.
  Production (not alpha) release.
- **Action:** `con --db DB send <W_hex> "x"` resolves to the v3 run fn path that
  would emit an above-ceiling fact.
- **Expect:** Local creation of an above-ceiling fact is REFUSED — the command
  returns `Err` (no fact submitted via `Runtime::submit_fact`,
  `core/runtime.rs:268`); nothing is written to the store.
- **Defends:** ADMISSION — local creation of an above-ceiling fact is refused;
  invariant (3) ceiling monotonicity (production must not emit beyond ceiling).
- **Refs:** `Runtime::submit_fact` (runtime.rs:268), ceiling gate, `content::message::cli::send`.

### CLI-10 — above-ceiling write command is HIDDEN from production usage listing  `blackbox-cli`
- **Setup:** Same v3 modeled surface; ceiling = 2; production release. The
  registry `usage` builder (`core::cli::usage`, cli.rs:128) enumerates commands.
- **Action:** `con --db DB` with no subcommand (prints usage) at ceiling 2.
- **Expect:** Commands whose only resolvable run fn has `intro_version > ceiling`
  are NOT listed (hidden) in production; a stable name with a v1 run fn (like
  `send`) IS listed. Above-ceiling-only surfaces are unreachable.
- **Defends:** above-ceiling write hidden in production; invariants (1)/(3).
- **Refs:** `core::cli::usage` (cli.rs:128), `MATCH_COMMANDS`.

### CLI-11 — above-ceiling-only command rejected when invoked by name in production  `blackbox-cli`
- **Setup:** A modeled command `disappearing-set` variant whose only run fn is
  intro_version 3 (a future TTL field). Ceiling = 2; production.
- **Action:** `con --db DB disappearing-set <W_hex> 60` at ceiling 2.
- **Expect:** Either "unknown command" (if hidden) OR an explicit refusal that no
  ceiling-active run fn exists for this name; in NO case does it construct a v3
  retention_policy fact (tag 147).
- **Defends:** above-ceiling write command rejected in production; invariant (3).
- **Refs:** `content::retention_policy::cli` DISAPPEARING_SET_USAGE, `core::cli::run` (cli.rs:104).

### CLI-12 — above-ceiling write param ON a stable command is rejected, lower params accepted  `blackbox-cli`
- **Setup:** `disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]`
  (DISAPPEARING_SET_USAGE). Model adds a v3-only `--scope SUBSET` param that
  drives a new shared retention fact. Ceiling = 2; production.
- **Action:** (a) `con --db DB disappearing-set <W> 60`; (b) the same with
  `--scope foo`.
- **Expect:** (a) succeeds at ceiling 2 (v2 params only). (b) the above-ceiling
  param is rejected/ignored such that NO above-ceiling fact is produced (refused,
  matching DISAPPEARING_SET_USAGE error or explicit ceiling refusal).
- **Defends:** above-ceiling write PARAM rejected while the stable command keeps
  working at ceiling-active params; invariants (1)/(3).
- **Refs:** `content::retention_policy::cli::parse_disappearing_set_args` (cli.rs:26-66), DISAPPEARING_SET_USAGE.

### CLI-13 — pure-local display flag ships at head, unversioned (no new shared fact)  `blackbox-cli`
- **Setup:** `disappearing-status WORKSPACE_ID_HEX` (read-only, DISAPPEARING_STATUS_USAGE).
  Model adds a `--json` presentation flag that only reformats `status_output`
  and drives NO new shared fact. Ceiling = 2 (below any hypothetical wire bump).
- **Action:** `con --db DB disappearing-status <W> --json` at ceiling 2.
- **Expect:** The flag works at head regardless of ceiling because it changes
  only local presentation chrome; it produces no fact, no row mutation, and is
  not ceiling-gated.
- **Defends:** pure-local/display CLI flag ships at head unversioned; invariant
  (2) ("only presentation chrome is platform-local").
- **Refs:** `content::retention_policy::cli::disappearing_status`/`status_output` (cli.rs:99,109), DISAPPEARING_STATUS_USAGE.

### CLI-14 — local read command `messages`/`view` unaffected by ceiling, renders at ceiling  `blackbox-cli`
- **Setup:** Workspace `W` with v1 messages. Ceiling = 1. `messages`/`view` are
  read-only display commands (`content::message::cli::messages`, `view`).
- **Action:** `con --db DB messages <W>` and `con --db DB view <W>` at ceiling 1.
- **Expect:** Both render existing facts; no ceiling gate blocks a read command;
  output rows are produced by the same projector regardless of release. The read
  command is local and unversioned (no shared fact emitted).
- **Defends:** local-read display surface ships at head; invariant (2) rendering
  uniformity (render AT the ceiling).
- **Refs:** `content::message::cli::messages` (cli.rs:328), `view` (cli.rs:472), MESSAGES_USAGE/VIEW_USAGE.

### CLI-15 — version-tagged run-fn list picks highest intro for `grant-admin` write  `handler-unit`
- **Setup:** `grant-admin` (auth::admin, tag 139) modeled with run-fn list
  `{1 -> grant_admin_v1, 2 -> grant_admin_v2}`. Ceiling = 2.
- **Action:** Resolve `grant-admin`'s run fn.
- **Expect:** Returns `grant_admin_v2` (highest intro_version <= 2). At ceiling 1
  the same resolver returns `grant_admin_v1`.
- **Defends:** version-tagged run-fn list selects highest intro_version<=ceiling
  for an auth write command; both {v1,v2} branches enumerated.
- **Refs:** `auth::admin::cli::grant_admin`/GRANT_ADMIN_USAGE (admin/cli.rs:12,14), `MATCH_COMMANDS` grant-admin (registry.rs:478).

### CLI-16 — `grant-admin` above ceiling is refused (admin write admission)  `blackbox-cli`
- **Setup:** `grant-admin` v2 run fn would emit an admin fact at intro_version 3.
  Ceiling = 2; production.
- **Action:** `con --db DB grant-admin <W_hex> <USER_hex>` resolving to the v3 path.
- **Expect:** Refused — no `auth::admin` fact (tag 139) at version 3 is created
  locally; command returns Err; store unchanged.
- **Defends:** above-ceiling auth write refused locally; invariants (1)/(3).
- **Refs:** `auth::admin::cli::grant_admin`, GRANT_ADMIN_USAGE, ceiling admission gate.

### CLI-17 — `invite` flag surface reused when v2 invite changes only the secret wire  `guardrail`
- **Setup:** `invite [--workspace WORKSPACE_ID_HEX] --public-addr ADDR`
  (INVITE_USAGE). v2 `auth::invite` (tag 129) changes only sealed-secret bytes,
  not inputs. No `invite` cli bucket in `_v2/`.
- **Action:** At ceiling 2, resolve `invite` run fn and run the subset check.
- **Expect:** v1 `invite` parser reused; `invite_v2.required_inputs =
  {public_addr, optional workspace} ⊆ collected_params`. `--public-addr` stays
  required, `--workspace` stays optional.
- **Defends:** absent-cli reuse + param-subset for an auth command with optional
  + required flags.
- **Refs:** `auth::invite::cli::invite`/INVITE_USAGE (invite/cli.rs:14,22), `MATCH_COMMANDS` invite (registry.rs:373).

### CLI-18 — `invite` requires a NEW required flag at v2 => must ship a cli bucket  `guardrail`
- **Setup:** v2 invite constructor requires a new `--ticket TOKEN` input. No cli
  bucket shipped. Active parser collects `{public_addr, workspace?}`.
- **Action:** Param-subset guardrail at bucket assembly.
- **Expect:** FAILS: `{public_addr, ticket, workspace?} ⊄ {public_addr, workspace?}`.
  The guardrail demands an `invite` cli delta in `_v2/`.
- **Defends:** param-subset violation forces a cli bucket; invariant (1).
- **Refs:** `auth::invite::cli` INVITE_USAGE, modeled `auth::invite::_v2` bucket.

### CLI-19 — `send-file` keeps stable name and `--file`/`--mime` flags across versions  `blackbox-cli`
- **Setup:** `send-file WORKSPACE_ID_HEX TEXT --file PATH [--mime MIME]`
  (SEND_FILE_USAGE). Carrier capacity gates the file-slice ceiling. Ceiling = 2.
- **Action:** `con --db DB send-file <W> "doc" --file /tmp/f.bin --mime text/plain`.
- **Expect:** Command name `send-file` resolves; `--file` required and `--mime`
  optional are parsed by `parse_send_file_args`; emits a `content::file` (tag 54)
  descriptor + `content::file_slice` (tag 55) facts. Name and flag surface stable.
- **Defends:** stable name + flag surface for a multi-fact write command;
  invariant (1).
- **Refs:** `content::message::cli::send_file`/`parse_send_file_args` (cli.rs:178,684), SEND_FILE_USAGE.

### CLI-20 — `send-file` slice fact above carrier capacity is gated (chunk-don't-grow)  `guardrail`
- **Setup:** Model a v_next file-slice that would exceed
  `CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES` carrier capacity. Ceiling would
  cover the tag but the carrier cannot transport it.
- **Action:** Assert the ceiling-activation gate for the `send-file` slice path.
- **Expect:** The capability is NOT ceiling-active because not every still-usable
  release can transport the larger slice via the file_slice frame class; the CLI
  must chunk to the existing FILE_SLICE capacity rather than grow the frame.
- **Defends:** carrier capacity GATES ceiling activation (file_slice precedent);
  invariant (1) transportable-by-every-release.
- **Refs:** `connection_frame_wire.rs` FILE_SLICE class, `content::message::cli::send_file`, file_slice tag 55.

### CLI-21 — `delete-message` stable name + `#N`/id selector across versions  `blackbox-cli`
- **Setup:** Workspace with one visible message at `#1`. Ceiling = 1 and ceiling = 2
  in two DBs. `delete-message WORKSPACE_ID_HEX MESSAGE_SELECTOR` (DELETE_MESSAGE_USAGE).
- **Action:** `con --db DB delete-message <W> '#1'` under each ceiling.
- **Expect:** Both resolve the `delete-message` name and the `#N` selector via
  `resolve_message_selector`; both emit a `content::message_deletion` (tag 51)
  fact; output `delete_message_output` is identical in shape. Name + selector
  surface stable across versions.
- **Defends:** stable name/selector for a write command at two ceilings;
  invariant (1).
- **Refs:** `content::message::cli::delete_message`/`resolve_message_selector` (cli.rs:293,639), DELETE_MESSAGE_USAGE.

### CLI-22 — duplicate command name across version buckets is rejected at assembly  `guardrail`
- **Setup:** Model two run-fn list entries that accidentally register the NAME
  `send` twice in `MATCH_COMMANDS` (e.g. v1 and v2 both as top-level commands
  instead of one name -> list).
- **Action:** Run `core::cli::validate_command_names` (cli.rs:115) over the
  assembled command set.
- **Expect:** Returns `Err("duplicate CLI command `send`")`. Versioning must
  fold variants under ONE name -> run-fn list, never two same-named commands.
- **Defends:** stable-name invariant is structurally enforced; one name per
  command regardless of version count.
- **Refs:** `core::cli::validate_command_names` (cli.rs:115-125), `MATCH_COMMANDS`.

### CLI-23 — every MATCH_COMMANDS name still resolves to a protocol::cli run fn  `guardrail`
- **Setup:** The `cli_command!` macro forces `run: command::$run` to resolve in
  `protocol::cli` (registry.rs:356-365). After adding version buckets, all 47
  command run fns (incl. `send`, `react`, `send_file`, `delete_message`,
  `grant_admin`, `invite`, `disappearing_set`) must still resolve there.
- **Action:** Compile/registry test that `MATCH_COMMANDS` builds and each `run`
  pointer is from `protocol::cli`.
- **Expect:** Builds clean; no command's run fn escapes `protocol::cli`. (Note
  `key-rotate-recipient -> key_recipient_rotation`, not `key_rotate_recipient`.)
- **Defends:** the host-fn locality boundary survives versioning; structural
  guardrail.
- **Refs:** `cli_command!` macro (registry.rs:356), `MATCH_COMMANDS` (registry.rs:367-510).

### CLI-24 — blocked mode: write command withheld, local read command still runs  `blackbox-cli`
- **Setup:** Staleness window S exceeded (no manifest refresh) OR clock rollback
  beyond tolerance => BLOCKED MODE. Workspace `W` has existing v1 facts.
- **Action:** (a) `con --db DB send <W> "x"`; (b) `con --db DB messages <W>`.
- **Expect:** (a) the shared-production write `send` is WITHHELD (refused in
  blocked mode, no fact submitted); (b) the local read `messages` still returns
  rows. Replay-class commands also still run.
- **Defends:** BLOCKED MODE — shared production withheld; local reads + replay
  still run; invariant (3).
- **Refs:** `content::message::cli::send` vs `messages`, trusted-time/staleness gate, `Runtime::submit_fact`.

### CLI-25 — replay-class CLI command runs in blocked mode and is ceiling-independent  `replay-cli`
- **Setup:** The two real replay/deps commands `test-generate-deps` and
  `test-replay-deps-reverse` (sync::cascade_test_fact, tag 2). Blocked mode;
  ceiling lowered.
- **Action:** `con --db DB test-replay-deps-reverse <args>` after a generate.
- **Expect:** Replay rebuilds derived state from retained facts regardless of
  ceiling and regardless of blocked mode (each fact replays via the adapter
  keyed by its own tag). No shared production is emitted by the replay path.
- **Defends:** invariant (4) replay determinism + ceiling-independence; blocked
  mode still permits replay.
- **Refs:** `sync::cascade_test_fact::cli` GENERATE_DEPS_USAGE/REPLAY_DEPS_REVERSE_USAGE, `MATCH_COMMANDS`, and the replay/status commands in `src`.

### CLI-26 — alpha release may bind an above-ceiling run fn that production hides  `handler-unit`
- **Setup:** `send` run-fn list `{1 -> send_v1, 3 -> send_v3}`; manifest ceiling
  = 2. One alpha release supports v3; production releases do not.
- **Action:** Resolve `send` for an ALPHA-tagged binary vs a PRODUCTION binary at
  ceiling 2.
- **Expect:** Production resolves/exposes only `send_v1` (intro<=2); the v3 run
  fn is hidden/refused. Alpha MAY expose `send_v3` for testing but emitting its
  fact is still gated by ceiling for shared transport.
- **Defends:** invariant (3) — a production release supports every ceiling-active
  capability or the new one is alpha-only; production/alpha axis on a write command.
- **Refs:** modeled `send` run-fn list, ReleaseManifestEntry ceiling, `CliCommand`.

### CLI-27 — pending above-ceiling input has NO display command output until activation  `blackbox-cli`
- **Setup:** Peer sends a v_next `content::message` (above ceiling) that is
  retained as pending by admission. Ceiling = 2.
- **Action:** `con --db DB messages <W>` and `con --db DB content-count <W>`.
- **Expect:** `messages` does NOT list the pending input; `content-count`
  `content_messages`/`message_facts` do NOT count it. After wipe+replay with a
  raised ceiling that covers the tag, the same commands list it only if the
  pending bytes authenticate and project.
- **Defends:** ADMISSION pending (received above-ceiling input absent from
  readers until active); invariant (2) render-at-ceiling.
- **Refs:** `content::message::cli::messages`/`content_count` (cli.rs:328,371), admission gate before projector dispatch.

### CLI-28 — `react` selector + emoji length surface identical across ceilings  `blackbox-cli`
- **Setup:** Workspace with message `#1`. Ceiling = 1 then ceiling = 2.
  `react WORKSPACE_ID_HEX MESSAGE_SELECTOR EMOJI` (REACT_USAGE).
- **Action:** `con --db DB react <W> '#1' '👍'` under each ceiling.
- **Expect:** Both resolve `react`, both reject empty emoji
  ("reaction emoji must not be empty") and over-long emoji ("reaction emoji is
  too long") identically; both emit a `content::reaction` (tag 52) fact. Input
  contract stable; only ciphertext capacity (a wire concern) may differ by version.
- **Defends:** stable input surface + identical validation for a write command
  across ceilings; invariant (1).
- **Refs:** `content::message::cli::react` (cli.rs:112-163), REACT_USAGE, `reaction::fact`.

### CLI-29 — empty run-fn list / no resolvable run fn yields a clean refusal, not a panic  `property`
- **Setup:** Modeled command whose run-fn list has all entries with
  `intro_version > ceiling` (e.g. `{5 -> f}` at ceiling 2).
- **Action:** Resolve the run fn at ceiling 2 for any input.
- **Expect:** Resolver returns a typed "no ceiling-active run fn" refusal (or the
  command is absent from dispatch); it never panics, never selects an
  above-ceiling fn, and never emits an above-ceiling fact. Property holds for all
  ceilings < min(intro_version).
- **Defends:** total/​safe selection function; invariants (1)/(3) and no-regression.
- **Refs:** `core::cli::run` (cli.rs:94), modeled run-fn resolver.

### CLI-30 — `disappearing-set` reuse-vs-bucket decision keys on input change, not wire change  `guardrail`
- **Setup:** Two modeled v2 retention bumps: (A) only the retention_policy fact
  wire changes (tag 147), inputs unchanged; (B) inputs change (new required
  `RETENTION_MODE`). DISAPPEARING_SET_USAGE = `disappearing-set WORKSPACE_ID_HEX
  TTL_MINUTES [--floor MINUTE]`.
- **Action:** For each, decide whether `_v2/` needs a `cli/` bucket.
- **Expect:** (A) NO cli bucket — reuse v1 parser; subset check passes
  (`{workspace_id, ttl_minutes, floor?}` unchanged). (B) cli bucket REQUIRED —
  subset check would fail without it. The decision is driven by the input
  surface, not the wire shape.
- **Defends:** "cli ONLY if the input surface changed"; both reuse and
  new-bucket branches enumerated for one command.
- **Refs:** `content::retention_policy::cli::parse_disappearing_set_args` (cli.rs:26), DisappearingSetArgs struct (cli.rs:19-24), DISAPPEARING_SET_USAGE.
## 7. Queries & rendering uniformity

These tests defend INVARIANT (2) RENDERING UNIFORMITY: surfaced meaning =
`f(retained facts, protocol version)`. Two supported clients at the SAME
protocol version must produce IDENTICAL read-model row content from the same
facts, regardless of release/platform; clients render AT THE CEILING (not at
their head), so a new derivation of existing facts is withheld until
ceiling-active; only presentation chrome (date format, `--json`, sort, native
window decoration) is platform-local; a semantic read change does not appear
below its introducing version; a render-CORRECTNESS fix that changes a surfaced
VALUE is gated as a protocol bump while a formatting-only fix is not.

Real query surfaces under test (run fns in `protocol::cli`, output formatters
beside them): `messages`/`messages` row formatting (`content/message/cli.rs:328`),
`view` (`content/message/cli.rs:472`), `users`/`users_output`
(`auth/user/cli.rs:15,21`), `peers` (`auth/endpoint_shared/cli.rs:40`),
`files` (`content/message/cli.rs:389`), `keys`/`keys_output`
(`auth/key_wrap/cli.rs:303`), `key-access`/`key_access_status_output`
(`auth/key_wrap/cli.rs:161`), `sync-status`/`sync_status_output`
(`sync/shared_fact/cli.rs:108`), `content-count`/`content_count_output`
(`content/message/cli.rs:380`), `count` (`auth/workspace/cli.rs:158`).
Chrome helpers: `format_bytes` (`content/message/cli.rs:1155`), `short_hex`
(`:1167`), `encode_hex_32`/`encode_hex` (`core/cli.rs:156,161`), `CliOutput`
(`core/cli.rs:62`). The read-model rows come from typed tables registered in
`registry.rs:36-182` (OPENED_MESSAGES, CONTENT_MESSAGES, CONTENT_REACTIONS,
CONTENT_FILES, etc.) and the queries in `content/message/queries.rs`.

NOTE on model-vs-code: the protocol-version / ceiling / `ReleaseManifestEntry`
machinery is the TARGET model and is NOT yet wired in `src` (only
`content/file/project.rs` even contains the word "ceiling", in an unrelated
slice-count sense). Tests below split into (a) BLACKBOX/PROJECTOR proofs of the
properties that already hold today (identical rows from identical facts;
deterministic ordering; chrome is the only per-call variability) and (b)
GUARDRAIL/PROPERTY proofs that pin the model contract a versioning
implementation must satisfy. Each is labeled in **Defends**.

---

### QUERY-01 — two same-version binaries render byte-identical `messages` rows from identical facts  `blackbox-cli`
- **Setup:** Two `con` binaries A and B built from the same source at protocol version V (ceiling = V on both). Seed an identical DB into each: one workspace, two users (alice, bob), three `content::message` facts (tags 50) at distinct `created_at_ms`, one `content::reaction` (52) on message 2.
- **Action:** Run `con --db DB_A messages WORKSPACE_ID_HEX` and `con --db DB_B messages WORKSPACE_ID_HEX`; capture both `CliOutput.lines` vectors.
- **Expect:** The two line vectors are exactly equal, element-for-element, including the leader `messages: 3`, the `N. [<created_at_ms>] <author>: <text>` lines, the `   id: <hex>` lines, and the `   reactions: <emoji>` line under message 2 (ordering from `opened_messages` `ORDER BY created_at_ms, message_id`).
- **Defends:** INVARIANT (2): same protocol version + same facts => same read-model row content regardless of which binary renders.
- **Refs:** `content/message/cli.rs:328` (`messages`), `content/message/queries.rs:31` (`opened_messages`), `content/message/cli.rs:743` (`reactions_by_message`), `registry.rs` OPENED_MESSAGES/CONTENT_REACTIONS.

### QUERY-02 — two same-version binaries render identical `view` output from identical facts  `blackbox-cli`
- **Setup:** Same dual-binary, same-version setup as QUERY-01, plus a joined local endpoint and one peer so `view` passes its membership check; add one `content::file` (54) with all slices received attached to message 3.
- **Action:** Run `con view WORKSPACE_ID_HEX` against DB_A and DB_B (same DB content).
- **Expect:** Identical `lines`: the `IDENTITY:` block (endpoint_id, signing_public_key), the `WORKSPACE:` name, the `USERS:` list, the `─`x40 rule, and the message/reaction/file body including the `✔  <filename> (<bytes> B)` complete-file line. No divergence anywhere.
- **Defends:** INVARIANT (2): identical surfaced meaning for the richest read view at one version.
- **Refs:** `content/message/cli.rs:472` (`view`), `:566-578` (file/reaction rendering), `auth/workspace/queries.rs`, `auth/endpoint_shared/queries.rs`.

### QUERY-03 — `users`, `peers`, `files`, `keys`, `sync-status`, `content-count`, `count` all match across same-version binaries  `blackbox-cli`
- **Setup:** Dual same-version binaries, one shared DB image with auth + content + sync facts populated.
- **Action:** For each of `users`, `peers`, `files WORKSPACE_ID_HEX`, `keys WORKSPACE_ID_HEX`, `sync-status WORKSPACE_ID_HEX`, `content-count WORKSPACE_ID_HEX`, `count`, run it against DB_A and DB_B.
- **Expect:** Every command's `lines` vector is identical between the two binaries: e.g. `users_output` lines `<user_id_hex> <username> public_key=<hex>`; `peers` lines `<endpoint_id> user_id=<..> endpoint_role=<device|invite-server> device_name=<..>`; `sync_status_output` `indexed_facts`/`root_count`/`root_fingerprint`/`pending_purges`; `content_count_output` `content_messages`/`message_facts`/`message_payload_bytes`/`max_message_timestamp`.
- **Defends:** INVARIANT (2) across the full query surface (not just messages).
- **Refs:** `auth/user/cli.rs:21`, `auth/endpoint_shared/cli.rs:40`, `content/message/cli.rs:389,380`, `auth/key_wrap/cli.rs:303`, `sync/shared_fact/cli.rs:108`, `auth/workspace/cli.rs:158`.

### QUERY-04 — desktop and mobile at the same version surface the same MEANING with different chrome  `blackbox-cli`
- **Setup:** Two releases at the same protocol version V: a "desktop" release (text `CliOutput.lines` joined with `\n`) and a "mobile" release that wraps the SAME `CliOutput.lines` in native list chrome (its own header bar, no leading `messages: N` count line, per-row tap affordance). Both consume the identical DB.
- **Action:** Render `messages WORKSPACE_ID_HEX` on each and extract the semantic fields (author, created_at_ms, text, message id, reactions) regardless of surrounding chrome.
- **Expect:** The ordered tuple of semantic fields per message (author name, `created_at_ms`, `text`, `message_id` hex, reaction emojis) is identical on both platforms. Chrome differences (count line present/absent, native header, indentation, affordances) are allowed and do NOT carry meaning.
- **Defends:** INVARIANT (2): "only presentation chrome is platform-local"; same meaning, different chrome.
- **Refs:** `content/message/cli.rs:328`, `core/cli.rs:62` (`CliOutput` is the meaning layer; the binary owns chrome), `core/daemon.rs:192` (`lines`).

### QUERY-05 — a head>ceiling binary renders AT THE CEILING: a new derivation is withheld  `blackbox-cli`
- **Setup:** A binary whose HEAD protocol version is V+1 (it knows how to render a new derived "edited" badge computed from a pair of `content::message` (50) + a hypothetical edit fact), running in a fleet whose CEILING is still V because a still-usable old release cannot transport the edit. Facts that would feed the badge are present in the DB only via existing message facts (no above-ceiling facts admitted).
- **Action:** Run `messages WORKSPACE_ID_HEX` and `view WORKSPACE_ID_HEX` on the head binary while ceiling = V.
- **Expect:** The badge/derived column does NOT appear. Output is byte-identical to what a pure-V binary produces from the same facts. The new derivation activates only after the ceiling rises to V+1.
- **Defends:** INVARIANT (2): "clients render AT THE CEILING, not their head; withhold a new derivation of existing facts until ceiling-active."
- **Refs:** `content/message/cli.rs:328,472`; ceiling-selection model over `MATCH_COMMANDS` (`registry.rs:367`), CliCommand version buckets.

### QUERY-06 — after the ceiling rises to V+1, the same head binary surfaces the new derivation  `blackbox-cli`
- **Setup:** Continue QUERY-05: the last still-usable old release expires (past `expires_at + M`), so the fleet ceiling advances to V+1; the head binary's CliCommand bucket for the V+1 `messages` derivation becomes selectable.
- **Action:** Advance trusted_time past the blocker's `expires_at + M`, recompute ceiling, then run `messages WORKSPACE_ID_HEX`.
- **Expect:** The new derived badge/column now appears in the rows. The change is gated purely on ceiling crossing V+1, not on the binary's head (which was already V+1).
- **Defends:** INVARIANT (2) + capability activation: ceiling-active gating of derivations.
- **Refs:** ceiling = min over still-usable `supported_protocol.end()`; CliCommand "highest intro_version <= ceiling" selection; `content/message/cli.rs:328`.

### QUERY-07 — a new SURFACED COLUMN does not appear below its introducing version  `blackbox-cli`
- **Setup:** A binary capable of rendering a new surfaced column (e.g. a `delivered:` indicator derived from `connection::fact_receipt` (164)) introduced at version V+2. Two runs: ceiling = V+1 (below intro) and ceiling = V+2 (at intro). Identical facts including receipts.
- **Action:** Run `messages WORKSPACE_ID_HEX` (or `view`) under ceiling V+1, then under ceiling V+2.
- **Expect:** Under V+1 the `delivered:` column is absent (rows identical to V+1 meaning); under V+2 it appears. The intro_version of the column gates its appearance.
- **Defends:** INVARIANT (2): "a semantic read change (new surfaced column) does not appear below its introducing version."
- **Refs:** `connection::fact_receipt` tag 164 (inventory §1); `content/message/cli.rs` rows-shared-at-head model; intro_version on routes/derivations.

### QUERY-08 — a CHANGED SURFACED VALUE does not appear below its introducing version  `blackbox-cli`
- **Setup:** A correctness change that alters a surfaced VALUE — e.g. `content-count`'s `message_payload_bytes` recomputed from real per-message payload sizes instead of `content_messages * CIPHERTEXT_BYTES` (current `queries.rs:71`). This ships as protocol bump to V+3. Identical message facts; one binary at ceiling V+2, one at ceiling V+3.
- **Action:** Run `content-count WORKSPACE_ID_HEX` at ceiling V+2 and at ceiling V+3.
- **Expect:** At V+2 the value is the OLD computation (`content_messages * CIPHERTEXT_BYTES`); at V+3 it is the NEW computation. The two never diverge AT THE SAME ceiling. Below V+3 nobody sees the new value.
- **Defends:** INVARIANT (2): "a changed surfaced value does not appear below its introducing version"; render-correctness fix that changes a VALUE is gated.
- **Refs:** `content/message/queries.rs:59-77` (`count_for_workspace`, `message_payload_bytes`), `content/message/cli.rs:380` (`content_count_output`).

### QUERY-09 — a render-CORRECTNESS fix that changes a surfaced value SHIPS AS A PROTOCOL BUMP  `guardrail`
- **Setup:** Diff between two source revisions where a query/output fn changes a surfaced VALUE (not just chrome): e.g. `files` percent computation, `format_bytes` unit conversion that changes the displayed number, or `content_count_output` field math.
- **Action:** Guardrail test asserts that any change to a function whose output is part of a `CliOutput` semantic field (the value-bearing substring, not the surrounding labels/whitespace) is accompanied by a protocol version increment and an intro_version assignment for the affected derivation.
- **Expect:** A value-changing render fix without a protocol bump fails the guardrail; a formatting-only change is allowed without a bump (see QUERY-10).
- **Defends:** INVARIANT (2) + (3): correctness fixes that change meaning are gated as bumps to preserve cross-version uniformity.
- **Refs:** `content/message/queries.rs`, `content/message/cli.rs:380,389,1155`, `sync/shared_fact/cli.rs:108`; protocol-version bundle model (`registry.rs`).

### QUERY-10 — a FORMATTING-ONLY fix is NOT gated (no protocol bump)  `guardrail`
- **Setup:** A source change that only touches presentation chrome: e.g. `format_bytes` switching `"1024 B"` to `"1.0 KiB"` for display, reordering the `id:` line, changing indentation, or adding ANSI color — the underlying numeric/textual MEANING is unchanged at the same version.
- **Action:** Guardrail/property test classifies the change as formatting-only (the parsed semantic value is invariant under the change) and asserts NO protocol bump is required.
- **Expect:** The formatting-only change passes without a version increment; the classifier distinguishes it from QUERY-09's value change.
- **Defends:** INVARIANT (2): "pure formatting (date format / --json / sort / native chrome) may differ per release/platform at the same version."
- **Refs:** `content/message/cli.rs:1155` (`format_bytes`), `:1167` (`short_hex`), `core/cli.rs:156` (`encode_hex_32`).

### QUERY-11 — date-format chrome may differ per release at the same version  `blackbox-cli`
- **Setup:** Two releases at the same protocol version V. Release A renders `messages` timestamps as raw `created_at_ms` (current code, `cli.rs:346`); release B renders them as a localized human date computed from the same `created_at_ms`. Identical message facts.
- **Action:** Run `messages WORKSPACE_ID_HEX` on each.
- **Expect:** The displayed timestamp STRINGS differ, but both are pure functions of the same retained `created_at_ms` value (no new fact, no reordering). The ordered set of underlying ms values is identical, and message ordering (`ORDER BY created_at_ms, message_id`) is identical.
- **Defends:** INVARIANT (2): date format is presentation chrome, allowed to differ at the same version.
- **Refs:** `content/message/cli.rs:343-348`, `content/message/queries.rs:38` (ordering).

### QUERY-12 — `--json` output is chrome: same meaning as text at the same version  `blackbox-cli`
- **Setup:** A release at version V that adds a `--json` presentation flag to `messages`/`content-count` (a presentation-only addition, NOT a protocol change). Identical facts; one run text, one run `--json`, both at ceiling V.
- **Action:** Run `con messages WORKSPACE_ID_HEX` and `con messages WORKSPACE_ID_HEX --json`.
- **Expect:** The JSON encodes exactly the same semantic fields (message_id, created_at_ms, author, text, reactions) carried by the text `CliOutput.lines`; no field present in one is absent in the other. Adding `--json` requires no protocol bump (presentation only).
- **Defends:** INVARIANT (2): "--json ... may differ per release/platform at the same version" — different serialization, same meaning.
- **Refs:** `core/cli.rs:62` (`CliOutput` meaning layer), `content/message/cli.rs:328,380`.

### QUERY-13 — sort order is deterministic and version-independent for `messages`  `projector-unit`
- **Setup:** Insert `content::message` facts in a scrambled arrival order (out-of-timestamp order) into OPENED_MESSAGES; two ties on `created_at_ms` resolved by `message_id`.
- **Action:** Call `queries::opened_messages(store, workspace_id)` directly.
- **Expect:** Returned rows are sorted by `(created_at_ms, message_id)` regardless of insertion order; ties broken deterministically by `message_id`. The order is a property of the query, independent of arrival order, release, or ceiling.
- **Defends:** INVARIANT (2)+(4): row content (incl. ordering) is `f(facts)` only; deterministic and order-independent.
- **Refs:** `content/message/queries.rs:31-57` (`ORDER BY created_at_ms, message_id`).

### QUERY-14 — old projector at head ceiling emits ceiling-era rows for an old-tag fact  `projector-unit`
- **Setup:** A `content::message` v1 fact (tag 50) retained from an old release. The current build's shared `rows`/`queries` at head ceiling V. (Model: "rows/queries shared at head; old projectors emit ceiling-era rows.")
- **Action:** Project the v1 fact through its own kept-forever projector (keyed by tag 50) and read it via `content_message_row`/`opened_messages`.
- **Expect:** The row carries the full ceiling-era column set (all fields the V read-model exposes), populated from the v1 fact's available data; no v1-specific reduced row shape leaks into the read model.
- **Defends:** INVARIANT (2)+(5): readers forever; old facts surface through the head read-model row shape.
- **Refs:** `content/message/queries.rs:90-148` (`content_message_rows`/`content_message_row`), `content/message/project.rs` row builders, `registry.rs` `read_models::CONTENT_MESSAGES`, `core/projectors.rs:402` (FactRoute keyed by own tag).

### QUERY-15 — pending above-ceiling input is uncounted and undisplayed in queries  `blackbox-cli`
- **Setup:** A received fact whose tag's intro_version > current ceiling (e.g. a hypothetical message:2 received while ceiling is at message:1). Per the model admission keeps it pending before it becomes protocol truth.
- **Action:** After delivery, run `content-count WORKSPACE_ID_HEX`, `messages WORKSPACE_ID_HEX`, and `sync-status WORKSPACE_ID_HEX`.
- **Expect:** `content_count` does NOT include the pending input in `content_messages`/`message_payload_bytes`/`max_message_timestamp`; `messages` does NOT list it; `sync-status` may report pending bytes separately but never as active protocol rows. No projector error is surfaced to the query.
- **Defends:** INVARIANT (2) + admission model: pending input is absent from readers until active.
- **Refs:** future admission gate before `core/projectors.rs` dispatch, `content/message/queries.rs:59` (`count_for_workspace` `deleted=0` filter analog), inventory §ADMISSION.

### QUERY-16 — pending input appears in queries only after post-rise activation  `replay-cli`
- **Setup:** Continue QUERY-15: the old message:2 copy is pending. The fleet ceiling then rises to cover message:2's tag.
- **Action:** Raise ceiling, perform wipe+replay (rebuild derived state via each fact's own-tag historical adapter), then run `content-count` and `messages`.
- **Expect:** The pending copy re-enters admission and, if it authenticates, projects and appears: `content_messages` count increments, `messages` lists it, and `content-count` `max_message_timestamp` reflects it if it is newest.
- **Defends:** INVARIANT (2)+(4): replay rebuilds visible read-model rows from retained facts; convergence for wire-admitted future bytes does not require redownloading them.
- **Refs:** inventory §ADMISSION (pending tradeoff), `core/projectors.rs` RouterProjector, `content/message/queries.rs`.

### QUERY-17 — replay rebuilds byte-identical query output (ceiling-independent reads)  `replay-cli`
- **Setup:** A store with messages, reactions, files, deletions; capture `messages WORKSPACE_ID_HEX` output O1. The retained facts are all at or below ceiling.
- **Action:** Wipe derived state and replay all facts (forward), then re-run `messages WORKSPACE_ID_HEX` -> O2. Repeat with `--reverse` replay order (if/when implemented) or scrambled insertion -> O3.
- **Expect:** O1 == O2 == O3. Query output is a deterministic function of retained facts and is independent of replay order and of intermediate ceiling values used during replay (each fact replays via the adapter keyed by its OWN tag).
- **Defends:** INVARIANT (4)+(2): replay determinism; reads are ceiling-independent given the facts.
- **Refs:** `content/message/queries.rs:31`, `core/projectors.rs:489` (`project_typed`), inventory §6 (replay subcommands are planned, not shipped — exercise via wipe+replay harness, not `con replay`).

### QUERY-18 — `files` completeness/percent rendering is meaning, identical across same-version binaries  `blackbox-cli`
- **Setup:** Dual same-version binaries. One `content::file` (54) with `slices_received < total_slices` (incomplete) and one with all slices received (complete). Identical `content::file_slice` (55) facts in both stores.
- **Action:** Run `files WORKSPACE_ID_HEX` against DB_A and DB_B.
- **Expect:** Identical lines: complete file shows `✔  <name> (<bytes> B)`; incomplete shows `⏳  <name> (<bytes> B, <pct>%)` with the SAME `pct = slices_received*100/total_slices`. The status glyph, byte string, and percent are meaning (derived from facts), so they match exactly; only surrounding chrome could differ.
- **Defends:** INVARIANT (2): completeness/percent is a fact-derived value, uniform at one version.
- **Refs:** `content/message/cli.rs:389-425` (`files`, status/pct logic), `content::file`/`content::file_slice` tags 54/55.

### QUERY-19 — author-name resolution falls back identically across binaries (meaning, not chrome)  `blackbox-cli`
- **Setup:** Dual same-version binaries. A message whose `signer_id` resolves to a peer->user with a username; a second message whose signer has no peer/user row (so it falls back to `short_hex(signer_id)`).
- **Action:** Run `messages WORKSPACE_ID_HEX` on both.
- **Expect:** Both binaries resolve the first author to the SAME username and the second to the SAME `short_hex` (12-char) string. The resolution chain (peer author_name -> user_name -> short_hex) is meaning and is identical; it is not a per-platform chrome choice.
- **Defends:** INVARIANT (2): derived author label is `f(facts)` and uniform across releases at one version.
- **Refs:** `content/message/cli.rs:336-342` (`author_name`/`user_name`/`short_hex` fallback), `:595-623`.

### QUERY-20 — `keys` / `key-access` reports are uniform at one version, gated by intro_version  `blackbox-cli`
- **Setup:** Dual same-version binaries with identical `auth::key_wrap` (155) / `auth::recipient_key` (150) / frontier facts. Separately, a head binary that knows a NEW key-status field (introduced at V+1) running while ceiling = V.
- **Action:** (a) Run `keys WORKSPACE_ID_HEX` and `key-access ...` on DB_A and DB_B at version V. (b) Run `keys` on the V+1-head binary while ceiling = V.
- **Expect:** (a) `keys_output`/`key_access_status_output` lines identical between A and B. (b) The new key-status field does NOT appear while ceiling = V (renders at ceiling). 
- **Defends:** INVARIANT (2): key-report rows uniform at a version; new derived field withheld below intro/ceiling.
- **Refs:** `auth/key_wrap/cli.rs:303` (`keys_output`), `:161` (`key_access_status_output`), tags 150/154/155 (inventory §1).

### QUERY-21 — newer binary with an UNCHANGED-input CLI bucket reuses prior run fn (param-subset contract)  `guardrail`
- **Setup:** A version bump V->V+1 where the `messages` fact derivation changes but the CLI INPUT surface (collected params: just `WORKSPACE_ID_HEX`) is unchanged, so `MATCH_COMMANDS` has NO new cli bucket entry for `messages` at V+1 (absent => reuse previous).
- **Action:** Guardrail test asserts the absent-bucket reuse and checks `v_next.required_inputs (WORKSPACE_ID_HEX) ⊆ active_cli.collected_params`.
- **Expect:** The previous `messages` run fn is reused under the param-subset contract; the test fails if V+1 required an input not collected by the active cli. Rendering still happens at ceiling regardless of which run fn version executes.
- **Defends:** INVARIANT (2) + CliCommand bucket model: "absent bucket entry => reuse previous; v_next.required_inputs ⊆ active_cli.collected_params."
- **Refs:** `registry.rs:367` (`MATCH_COMMANDS`), `core/cli.rs:82` (`CliCommand`), inventory §VERSION BUCKETS.

### QUERY-22 — CliCommand selects highest intro_version <= ceiling for a versioned query  `handler-unit`
- **Setup:** A `content-count` command with a version-tagged list of run fns: intro_version V (old `message_payload_bytes` math) and intro_version V+3 (corrected math, see QUERY-08). Ceiling set to V+1, then V+3, then V+4.
- **Action:** Resolve the CliCommand for `content-count` at each ceiling.
- **Expect:** At ceiling V+1 -> the V run fn (highest intro_version <= V+1); at V+3 -> the V+3 run fn; at V+4 -> still the V+3 run fn (highest <= V+4, no higher bucket). Selection is strictly "highest intro_version <= ceiling."
- **Defends:** INVARIANT (2): ceiling selects the active render code; renders at ceiling.
- **Refs:** inventory §CliCommand selection, `registry.rs` MATCH_COMMANDS, `content/message/cli.rs:371,380`.

### QUERY-23 — query output identical for the same facts regardless of binary's HEAD when ceiling is equal  `property`
- **Setup:** Property test over a generated set of {content::message, reaction, file, deletion} facts. Two configs: binary at head V (ceiling V) and binary at head V+5 (ceiling forced to V because a blocker keeps it there).
- **Action:** For each generated fact set, render `messages`/`view`/`content-count` under both configs and compare the semantic fields.
- **Expect:** For all generated inputs, the semantic read-model content is identical between the V-head and V+5-head binaries whenever both render at ceiling V. Head version never leaks into surfaced meaning while ceiling is fixed.
- **Defends:** INVARIANT (2): surfaced meaning = `f(facts, protocol version=ceiling)`, NOT `f(head)`.
- **Refs:** `content/message/cli.rs:328,472,371`, `content/message/queries.rs`, ceiling model.

### QUERY-24 — BLOCKED MODE still serves local reads/queries identically  `blackbox-cli`
- **Setup:** A binary in BLOCKED MODE (staleness window S exceeded without a manifest refresh, or backward clock rollback beyond tolerance). Shared production is withheld, but local reads + replay run. Identical facts to a non-blocked sibling at the same effective ceiling.
- **Action:** Run `messages`, `view`, `content-count`, `files`, `users`, `keys`, `sync-status` while BLOCKED, and compare to the non-blocked sibling at the same ceiling.
- **Expect:** All query outputs are identical to the non-blocked sibling's. BLOCKED MODE affects only shared production (creation/transport), never local read rendering. No query errors due to blocked state.
- **Defends:** INVARIANT (2) + trusted-time model: "Staleness window S ... => BLOCKED MODE (shared production withheld; local reads + replay still run)."
- **Refs:** inventory §TRUSTED TIME / BLOCKED MODE; `core/clock.rs` (trusted-time lower-bound precedent, `CLOCK_USAGE` `clock.rs:18`); query fns above.

### QUERY-25 — `count` and `content-count` agree on the same facts across versions at the same ceiling  `blackbox-cli`
- **Setup:** Two binaries at the same ceiling V (different releases/platforms), identical DB. `count` (`auth/workspace/cli.rs:158`) returns the global fact count; `content-count` returns content-message specifics.
- **Action:** Run `count` and `content-count WORKSPACE_ID_HEX` on each binary.
- **Expect:** `count` returns the identical integer on both; `content-count` returns identical `content_messages`/`message_payload_bytes`/`max_message_timestamp` on both. Pending above-ceiling facts (if any) are excluded identically by both (per QUERY-15).
- **Defends:** INVARIANT (2): counting surfaces are `f(facts, ceiling)` and uniform across releases.
- **Refs:** `auth/workspace/cli.rs:158` (`count`), `content/message/cli.rs:371,380` (`content_count`/`content_count_output`), `content/message/queries.rs:59`.

### QUERY-26 — desktop vs mobile `view`: same membership/peer meaning, different chrome  `multinode-network`
- **Setup:** Two endpoints in the same workspace at the same protocol version V: a desktop release and a mobile release, fully synced (identical retained facts) over the connection-frame transport.
- **Action:** After sync converges, run `view WORKSPACE_ID_HEX` on each and extract the USERS list (peer label `username/device_name`, `(you)` marker on local), workspace name, and message body.
- **Expect:** The set of peers, their usernames/device_names, the `(you)` self-marker semantics, the workspace name, and the message/reaction/file meaning are identical on both endpoints; only window chrome/list affordances differ. The `(you)` marker correctly points at each device's own local endpoint (different rows on each device — that is meaning, not divergence).
- **Defends:** INVARIANT (2): "desktop+mobile at the same version surface the same meaning with different chrome."
- **Refs:** `content/message/cli.rs:472-533` (`view`, peer labels, `(you)` marker), `auth/endpoint_shared/queries.rs`, `connection_frame_wire.rs` transport.

### QUERY-27 — a new derived FILTER (e.g. "hide deleted") is withheld until ceiling-active  `blackbox-cli`
- **Setup:** A head binary at V+1 that adds a derived filter/view computed purely from existing `content::message_deletion` (51) facts (e.g. a `--include-deleted` toggle that surfaces tombstoned messages with a strike). Ceiling = V (below intro).
- **Action:** Run `messages WORKSPACE_ID_HEX` (and `messages ... --include-deleted` if the flag is even accepted) while ceiling = V.
- **Expect:** The new derived filter/view is NOT active: deletions are handled exactly as at V (tombstoned messages stay hidden via the existing `deleted=0`/tombstone path), and any V+1-only toggle is inert. Output equals the pure-V rendering.
- **Defends:** INVARIANT (2): a new derivation (badge/FILTER/computed column) of existing facts does not appear until ceiling-active.
- **Refs:** `content::message_deletion` tag 51; `content/message/queries.rs:59` (`deleted=0`), MESSAGE_TOMBSTONES read-model (`registry.rs:36-182`), `content/message/cli.rs:328`.
## 8. Projectors, old-meaning, ceiling-era rows, anchors, purity

Cluster PROJ. Defends the consolidated poc-10 protocol-versioning model for the
projector layer: an old fact projected by a current binary emits **ceiling-era
rows** (old fact bytes -> current read-model row shape, shared at head); an old
adapter may **tighten validation / reject malformed old facts** but must NOT
grant an old fact new authority; projectors stay **pure and replay-blind**
across versions (no store query, no IO, no fresh-time read), including future
`_vN` projectors; a v2 projector needing a v1 **anchor** (the proposed
`user_profile_v2` needing `auth_user` + `auth_endpoint_shared` context) **parks
on a context need** until the anchor is present and **rejects on mismatch**; the
only purge a projector emits is **its own fact id** (`purge_self`); cross-fact
purge is rejected at `enforce_owner_is_self`.

Verified grounding from `/home/holmes/poc-10/src`:
- `RouterProjector` reads only the first byte (`effective_tag`, projectors.rs:433),
  finds the `FactRoute` whose `tag` equals it, else `Err("no target projector
  registered for fact tag {tag}")` at projectors.rs:456. Routing is purely by
  the `u8` tag; there are NO internal version bytes for routed facts and a `_vN`
  shape would be a NEW tag + NEW `FactRoute` (registry.rs `projector_routes!`,
  593-637).
- `ProjectionContext` (projectors.rs:52) is "a snapshot of matched rows for this
  run, not a live storage handle" — `payload_for`/`matched_payloads_for`/
  `time_reached` only read pre-matched context; there is no clock, no `Store`,
  no IO handle in the projector signature
  `fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>`
  (`ProjectorFn`, projectors.rs:396). `time_reached` is "a context check, not a
  clock read" (projectors.rs:158).
- `ProjectionOutput::purge_self(id)` pushes onto `effects.purged_facts`
  (projectors.rs:356); `enforce_owner_is_self` (project_pending_facts.rs:931)
  rejects any purge/need/offer/time-wake whose owner != the projected fact id.
- Anchors: `UserProjector` offers `auth_user` (user/project.rs:91-98);
  `EndpointSharedProjector` offers `auth_endpoint_shared`
  (endpoint_shared/project.rs:87-93). A projector with an unmet need returns
  `Ok(ProjectionOutput::new().need(...))` and parks (user/project.rs:70-72,
  endpoint_shared/project.rs:71-73).
- `auth::user_profile_v2` does NOT exist yet (inventory section 1). Tests below
  that reference it are written against the model contract a future `_vN`
  family must satisfy; they are marked so the implementor knows they describe a
  to-be-added projector and its guardrails.
- NOTE for implementors: `HandlerRoute` in this checkout carries only
  `{name, intent_kind, factory}` (runtime.rs:71); the planned `runs_during_replay`
  flag is NOT present. The "replay-blind" tests below therefore assert purity of
  the projector function path that exists today; PROJ-22 calls out the absence.

---

### PROJ-01 — content::message (tag 50) old fact projects to current row shape (ceiling-era rows) `projector-unit`
- **Setup:** Current binary, full registry. A retained `content::message` fact (tag 50) authored under an older protocol version, with all decoded fields valid; ProjectionContext pre-loaded with matching `content_signer` (endpoint_shared), `auth_user` author, and `local_key_secret`/`history_node_secret` context.
- **Action:** Call `ContentMessageProjector::project(&fact, &context)` (the route `project_content_message`, registry.rs:604) directly.
- **Expect:** Output emits `RowMutation::InsertValues(content_message_row(...))` and, after decrypt, `RowMutation::InsertValues(opened_message_row(...))` into the CURRENT `CONTENT_MESSAGE_ROWS`/`OPENED_MESSAGE_ROWS` typed tables (message/project.rs:170-207) — i.e. the head row schema, not any historical row schema. No version-conditional row branch exists.
- **Defends:** Invariant 2 (rendering uniformity: head row shape) + version-bucket rule "rows/queries shared at head; old projectors emit ceiling-era rows".
- **Refs:** `content::message::project::ContentMessageProjector`, `content/message/project.rs` (`content_message_row`, `opened_message_row`), `registry.rs` `read_models`, `registry.rs:604`.

### PROJ-02 — auth::user (tag 14) old fact projects to current user_row shape `projector-unit`
- **Setup:** Current binary. A retained `auth::user` fact (tag 14, global scope) from an older era; ProjectionContext pre-loaded with the matching `auth_user_invite` payload whose workspace/public_key match the user.
- **Action:** Call `UserProjector::project(&fact, &context)` (route `project_user`, registry.rs:636).
- **Expect:** Emits `RowMutation::PutRow(user_row(fact.id, user_invite_id, &user))` (user/project.rs:99-103) into the current user row table, plus `auth_user` offer. Row content is f(retained fact, head schema) only.
- **Defends:** Invariant 2 + ceiling-era rows for the auth scope.
- **Refs:** `auth::user::project::UserProjector`, `auth/user/rows.rs::user_row`.

### PROJ-03 — auth::endpoint_shared (tag 135) old fact projects to current endpoint_shared_row `projector-unit`
- **Setup:** Current binary. A retained `auth::endpoint_shared` device-role fact (tag 135) from an older era; ProjectionContext pre-loaded with matching `auth_device_invite` payload.
- **Action:** Call `EndpointSharedProjector::project(&fact, &context)` (route `project_endpoint_shared`, registry.rs:620).
- **Expect:** Emits `RowMutation::PutRow(endpoint_shared_row(fact.id, &shared))` (endpoint_shared/project.rs:94) plus `content_signer` and `auth_endpoint_shared` offers, into head schema. No version branch.
- **Defends:** Invariant 2 + ceiling-era rows (auth scope).
- **Refs:** `auth::endpoint_shared::project::EndpointSharedProjector`, `endpoint_shared/rows.rs::endpoint_shared_row`.

### PROJ-04 — content::file_slice (tag 55) old carrier fact projects to current FILE_SLICES rows (chunk-don't-grow) `projector-unit`
- **Setup:** Current binary. A retained `content::file_slice` fact (tag 55) created under an older protocol whose slice plaintext capacity matched the old `CONTENT_FILE_SLICE_BYTES`; the file descriptor parent context available.
- **Action:** Call `ContentFileSliceProjector::project` (route `project_content_file_slice`, registry.rs:603).
- **Expect:** Emits `RowMutation` into the current `FILE_SLICES` read-model table (file_slice/rows.rs:33 `content_file_slice_row`); the row shape is head, independent of the old carrier's byte capacity. Defends the file_slice "chunk-don't-grow" precedent: capacity change would be a new carrier tag, not a wider old row.
- **Defends:** Invariant 2 + transport "carrier capacity gates ceiling activation" (file_slice precedent).
- **Refs:** `content::file_slice::project::ContentFileSliceProjector`, `content/file_slice/rows.rs`, `read_models::FILE_SLICES`.

### PROJ-05 — sync::shared_fact (tag 162) old fact projects to current shared_fact row `projector-unit`
- **Setup:** Current binary. A retained `sync::shared_fact` (tag 162) from an older era.
- **Action:** Call `SyncSharedFactProjector::project` (route `project_sync_shared_fact`, registry.rs:626).
- **Expect:** Emits current shared_fact read-model row shape (sync scope); no historical row branch. Confirms the ceiling-era-rows rule holds in the fourth scope (sync).
- **Defends:** Invariant 2 across all four scopes (auth/content/connection/sync).
- **Refs:** `sync::shared_fact::project::SyncSharedFactProjector`, `sync/shared_fact/rows.rs`.

### PROJ-06 — connection::frame_small (tag 168) old container fact opens and emits inner fact bytes (current shape) `projector-unit`
- **Setup:** Current binary. A retained `connection::frame_small` container fact (tag 168) sealed under an older frame era (TRNS v1), carrying one inner `content::message` fact; the connection's ephemeral secret / send context pre-loaded.
- **Action:** Open the carrier boundary and call `ConnectionFrameSmallProjector::project` (route `project_connection_frame_small`, registry.rs:630).
- **Expect:** Output emits the recovered inner fact bytes as durable child facts via `ProjectionOutput::fact(...)` (frame_small/project.rs MATERIALIZE step), which are then routed by their OWN tag (50) on a later pass. The container projector emits child facts, not rows of its own, and does not authenticate the child facts for their owning families.
- **Defends:** Invariant 2 + "a connection frame is a CONTAINER FACT: opening recovers inner fact bytes that re-enter authenticate/project by their own tags" (connection scope).
- **Refs:** `connection::frame_small::project::ConnectionFrameSmallProjector`, `connection_frame_wire.rs` (`open_connection_frame`, `decode_inner_bundle`).

### PROJ-07 — old message adapter may REJECT a structurally-malformed old fact (tighten validation) `projector-unit`
- **Setup:** Current binary. A retained `content::message` fact (tag 50) whose decoded `signer_public_key` does not match the matched `content_signer` endpoint_shared context (a malformed/forged-but-old fact).
- **Action:** Call `ContentMessageProjector::project` with the mismatched signer context loaded.
- **Expect:** `validate_message_signer_context` returns `Err("content message signer context public key does not match message signature key")` (message/project.rs:249-253). The adapter rejects the malformed old fact; it does not silently admit it.
- **Defends:** "an old adapter may tighten validation / reject malformed old facts" — and Invariant 4 (replay determinism: rejection is deterministic, not IO-dependent).
- **Refs:** `content::message::project::validate_message_signer_context`.

### PROJ-08 — old message adapter tightening must NOT grant the old fact new authority `projector-unit`
- **Setup:** Current binary. A retained `content::message` fact (tag 50) authored by an endpoint whose `auth_user` author context does NOT match `author_user_id` (the author is not the named user). Older binaries lacked the author check; the current adapter has it.
- **Action:** Call `ContentMessageProjector::project` with author context whose `payload.id != author_user_id`.
- **Expect:** `validate_author_user` returns `Err("message author context payload id mismatch")` (message/project.rs:269) OR `Err("message author workspace does not match message")` (message/project.rs:275). The tightened adapter does NOT promote the old fact to "authored by anyone": it can only WITHHOLD/reject, never grant authority the fact never had.
- **Defends:** "an old adapter must NOT grant an old fact new authority" + Invariant 3 (no-regression / authority-monotone downward only).
- **Refs:** `content::message::project::validate_author_user`.

### PROJ-09 — old endpoint_shared adapter rejects malformed old fact but does not grant device authority `projector-unit`
- **Setup:** Current binary. A retained `auth::endpoint_shared` device-role fact (tag 135) whose `signer_public_key` mismatches the matched `auth_device_invite` payload.
- **Action:** Call `EndpointSharedProjector::project` with the mismatched device_invite context.
- **Expect:** `has_valid_authority` returns `Err("endpoint_shared signer public key does not match device_invite")` (endpoint_shared/project.rs:145). No row is written; no `content_signer`/`auth_endpoint_shared` offer is published. The endpoint is NOT granted signing authority it lacked.
- **Defends:** Adapter tightening rejects-but-never-grants (auth scope).
- **Refs:** `auth::endpoint_shared::project::has_valid_authority`.

### PROJ-10 — old user adapter rejects user whose invite workspace/key mismatch (no new authority) `projector-unit`
- **Setup:** Current binary. A retained `auth::user` fact (tag 14) whose matched `auth_user_invite` payload has `invite.workspace_id != user.workspace_id`.
- **Action:** Call `UserProjector::project` with the mismatched invite context.
- **Expect:** `Err("user workspace does not match user_invite workspace")` (user/project.rs:80). No `auth_user` offer, no `user_row`. The old user fact is not admitted into a workspace it was never invited to.
- **Defends:** Adapter rejects-but-never-grants (auth scope, user family).
- **Refs:** `auth::user::project::UserProjector`.

### PROJ-11 — projector is pure: identical fact + identical context yields identical output `property`
- **Setup:** Current binary. Any retained fact F and a fixed `ProjectionContext` C (e.g. a fully-resolvable `content::message`).
- **Action:** Call `ContentMessageProjector::project(&F, &C)` N times in a row, comparing `ProjectionOutput` (which derives `PartialEq`, projectors.rs:314).
- **Expect:** All N outputs are byte-for-byte equal (same needs, offers, time_wakes, effects). No call observes a different clock, store snapshot, or RNG. Property holds because the signature has no IO/store/time handle.
- **Defends:** Invariant 4 (replay determinism) + "projectors stay pure".
- **Refs:** `ProjectorFn` signature (projectors.rs:396), `ProjectionOutput: PartialEq` (projectors.rs:314).

### PROJ-12 — projector reads time only from pre-matched TimeRange context, never a fresh clock `projector-unit`
- **Setup:** Current binary. A `content::message` fact with `expires_at_minute = E`. Two runs: (a) ProjectionContext with NO time_ranges; (b) same context with a `TimeRange` whose `end_inclusive >= E` on the expiration timeline.
- **Action:** Call `ContentMessageProjector::project` in each.
- **Expect:** (a) `expiry_minute_reached` returns `None` (message/project.rs:366-377 calls `context.time_reached`, which only consults `time_ranges`) -> message parks/materializes normally; (b) returns `Some(_)` -> `expired_output` with tombstone + `purge_self`. The projector NEVER calls `SystemTime::now`/`Instant`; expiry is decided purely by daemon-supplied due ranges.
- **Defends:** "no fresh time" purity + Invariant 4 (ceiling-independent, deterministic replay of expiry).
- **Refs:** `expiry_minute_reached`, `ProjectionContext::time_reached` (projectors.rs:158), `expired_output` (message/project.rs:434).

### PROJ-13 — projector performs no store query / overlap query (context is a snapshot) `guardrail`
- **Setup:** Current binary, source-level guardrail over `src/protocol/**/project.rs`.
- **Action:** Grep/AST-check that no `project.rs` file imports or calls `Store`, `rusqlite`, `write_transaction`, `read_*` storage handles, `SystemTime`/`Instant::now`, or filesystem/network IO; context access is limited to `ProjectionContext` accessors (`payload_for`, `matched_payloads_for`, `time_reached`, `offers`).
- **Expect:** Zero matches for store/IO/clock primitives in any projector module. (Doc at projectors.rs:107-109: "Projectors receive the resulting snapshot but do not query storage or run overlap queries themselves.")
- **Defends:** "no store query/IO/fresh time" purity for ALL projectors, including future `_vN` modules added under the same lint.
- **Refs:** all `src/protocol/*/*/project.rs`, `ProjectionContext` doc (projectors.rs:105-110).

### PROJ-14 — a future content::message _v2 projector is pure under the same lint (replay-blind _vN) `guardrail`
- **Setup:** A proposed `content::message_v2` family (NEW tag, e.g. an incompatible message wire shape) with its own `_v2/project.rs` and a new `FactRoute` entry, kept forever alongside tag 50.
- **Action:** Apply the PROJ-13 purity guardrail to the new `_v2/project.rs`.
- **Expect:** The `_v2` projector signature is still `fn(&Fact, &ProjectionContext) -> Result<...>` with no store/IO/clock; it routes off its OWN new tag (no internal version byte); it emits HEAD rows just like tag 50. Guardrail must cover `_vN` directories so a new version cannot smuggle in IO.
- **Defends:** "projectors stay pure and replay-blind across versions including _vN projectors" + versioning-knob = new tag + new projector, kept forever.
- **Refs:** `projector_routes!` macro (registry.rs:580-591) — adding a route is the only way to register a `_vN` projector; `ProjectorFn` purity.

### PROJ-15 — replay of an old fact uses the historical adapter keyed by its own tag (ceiling-independent) `replay-cli`
- **Setup:** Current binary, store holding facts of tags 14, 50, 135, 55 authored across several eras. Ceiling currently HIGH (covers all tags).
- **Action:** Wipe + replay (rebuild derived state). Then drop the simulated ceiling LOW and replay again.
- **Expect:** Each retained fact replays through the `FactRoute` keyed by its OWN first byte regardless of ceiling; derived rows are identical across the two ceilings for any tag that was admissible (ceiling-independent replay). Pending above-ceiling facts (if any) stay opaque/uncounted but are not dropped.
- **Defends:** Invariant 4 (replay determinism: every retained fact replays via the historical adapter keyed by its own tag; ceiling-independent).
- **Refs:** `RouterProjector::project` tag dispatch (projectors.rs:454-458), wipe+replay pipeline.

### PROJ-16 — replay is order-independent for the same fact set `replay-cli`
- **Setup:** Current binary, a fixed set of retained facts (a `content::message` plus its signer endpoint_shared, author user, secret).
- **Action:** Replay once in natural order; replay again with `--reverse`/`--scramble --seed N` (the planned replay flags) OR, since those subcommands are not yet shipped (inventory section 6), via the existing `test-replay-deps-reverse` cascade harness over `sync::cascade_test_fact`.
- **Expect:** Final read-model rows and context are identical regardless of fact ordering. The fixed-point projection loop (projectors.rs:29-33 reruns until context stabilizes) reaches the same fixed point.
- **Defends:** Invariant 4 (order-independent replay).
- **Refs:** `test-replay-deps-reverse` -> `replay_deps_reverse` (registry.rs:489-491), `sync::cascade_test_fact`; projection fixed-point note (projectors.rs:29-33).

### PROJ-17 — proposed user_profile_v2 projector PARKS on missing auth_user anchor `projector-unit`
- **Setup:** Proposed new family `auth::user_profile_v2` (does not exist yet; inventory section 1) whose projector needs both an `auth_user` anchor (offered by `UserProjector`, user/project.rs:91) and an `auth_endpoint_shared` anchor (offered by `EndpointSharedProjector`, endpoint_shared/project.rs:88). ProjectionContext has the endpoint_shared offer but NO `auth_user` payload.
- **Action:** Call the v2 projector with the `auth_user` need unsatisfied.
- **Expect:** Returns `Ok(ProjectionOutput::new().need(auth_user_need).need(auth_endpoint_shared_need))` — it PARKS (no row, no offer, no error), exactly as `UserProjector` parks on a missing `auth_user_invite` (user/project.rs:70-72). Core will rerun once the anchor matches.
- **Defends:** "a v2 projector needing a v1 anchor parks on a context need until present" + Invariant 1 (visibility deferred, not dropped).
- **Refs:** Pattern from `user/project.rs:70-72` and `endpoint_shared/project.rs:71-73`; anchors `auth_user` (user/project.rs:91), `auth_endpoint_shared` (endpoint_shared/project.rs:88).

### PROJ-18 — proposed user_profile_v2 projector PARKS on missing auth_endpoint_shared anchor `projector-unit`
- **Setup:** As PROJ-17 but reversed: ProjectionContext has the `auth_user` payload present and the `auth_endpoint_shared` payload ABSENT.
- **Action:** Call the v2 projector.
- **Expect:** Returns `Ok` with both needs re-emitted (still parked) and no row/offer; specifically the unmet `auth_endpoint_shared` need keeps the fact pending. Both v1 anchors are required before materialization.
- **Defends:** v2-needs-v1-anchor parking on the SECOND anchor too (enumerated separately from PROJ-17).
- **Refs:** `auth_endpoint_shared` anchor (endpoint_shared/project.rs:88), v2 projector contract.

### PROJ-19 — proposed user_profile_v2 projector materializes once BOTH v1 anchors present `projector-unit`
- **Setup:** As PROJ-17/18 but both `auth_user` and `auth_endpoint_shared` payloads matched and validated (ids/workspace consistent).
- **Action:** Call the v2 projector with both anchors satisfied.
- **Expect:** Emits its head read-model row + its own offer, having validated the anchors. The v2 fact gains NO authority beyond what the two v1 anchors already prove (it binds to existing user + endpoint, does not mint a new user).
- **Defends:** v2 materialization gated on v1 anchors; new version does not grant new authority.
- **Refs:** `UserProjector`/`EndpointSharedProjector` anchor offers; v2 projector contract.

### PROJ-20 — proposed user_profile_v2 projector REJECTS on anchor id/workspace mismatch `projector-unit`
- **Setup:** As PROJ-19 but the matched `auth_user` payload's id (or workspace) does NOT match the v2 fact's claimed user/workspace binding.
- **Action:** Call the v2 projector with the mismatched anchor.
- **Expect:** Returns `Err("...user profile anchor id mismatch...")` (modeled on `user/project.rs:73-74` `if invite_fact.id != user.signer_id { Err }` and `endpoint_shared/project.rs:133`). Mismatch is a hard reject, not a park and not an admit.
- **Defends:** "rejects on mismatch" — anchor binding must be exact; tightening cannot grant authority.
- **Refs:** mismatch pattern `user/project.rs:73`, `endpoint_shared/project.rs:133`.

### PROJ-21 — proposed user_profile_v2 stays pure: no store/IO/clock while resolving anchors `guardrail`
- **Setup:** The proposed `auth/user_profile_v2/project.rs` module.
- **Action:** Apply the PROJ-13 purity guardrail; confirm anchor resolution uses only `context.payload_for(&auth_user_need)` / `context.payload_for(&auth_endpoint_shared_need)`, never a store lookup of the user/endpoint facts.
- **Expect:** The v2 projector discovers anchors ONLY through pre-matched context (the same mechanism `UserProjector` uses for `auth_user_invite`), never by querying storage for the anchor fact. Anchor discovery is replay-blind.
- **Defends:** v2-anchor resolution is pure/replay-blind (combines anchor + purity charters).
- **Refs:** `ProjectionContext::payload_for` (projectors.rs:170), `user/project.rs:70`.

### PROJ-22 — projector path carries no replay-mode branch (replay-blind today) `guardrail`
- **Setup:** Current binary. The brief claims `HandlerRoute` carries `runs_during_replay`; verified ABSENT in this checkout (`HandlerRoute{name,intent_kind,factory}`, runtime.rs:71).
- **Action:** Grep `src/protocol/**/project.rs` and `src/core/projectors.rs` / `src/core/pipeline/project_pending_facts.rs` for any `replay`/`is_replay`/`during_replay` conditional reachable from a projector.
- **Expect:** No projector branches on a replay flag — projection output is identical whether the pass is live admission or wipe+replay, because the projector cannot see the mode. (If `runs_during_replay` is later added, it must live on HANDLER routes, NOT bleed into the pure projector path.)
- **Defends:** "projectors stay replay-blind across versions"; flags absence of the planned field.
- **Refs:** `HandlerRoute` (runtime.rs:71), `ProjectorFn` (projectors.rs:396).

### PROJ-23 — projector emits purge of ONLY its own fact id (self-purge) `projector-unit`
- **Setup:** Current binary. An expired `content::message` fact (tag 50) with a due expiration `TimeRange` in context.
- **Action:** Call `ContentMessageProjector::project`; inspect `output.effects.purged_facts`.
- **Expect:** `purged_facts == vec![fact.id]` exactly (from `.purge_self(message_id)` in `expired_output`, message/project.rs:456). It does NOT purge the deletion fact, the author user, the secret, or any other fact — only the message being projected.
- **Defends:** "the only purge a projector emits is its own fact id" + Invariant 5/6 (self-removal on expiry).
- **Refs:** `expired_output`/`retired_output`/`author_deletion_output` (message/project.rs:434-519), `purge_self` (projectors.rs:356).

### PROJ-24 — cross-fact purge is REJECTED by enforce_owner_is_self `handler-unit`
- **Setup:** Current binary. A test projector (like the in-tree `BadPurgeOwnerProjector`) that emits `ProjectionOutput::new().purge_self([9;32])` while projecting a fact with a different id.
- **Action:** Run the projection through `run_projection`/`run_projection_with_context` (project_pending_facts.rs:911).
- **Expect:** `enforce_owner_is_self` returns `Err("projector tried to purge fact ... while projecting ...")` (project_pending_facts.rs:932-938); the commit is rejected. Exactly the existing test `projection_run_rejects_purge_owned_by_another_fact` (project_pending_facts.rs:1008).
- **Defends:** "cross-fact purge rejected" — purge ownership invariant at the commit boundary.
- **Refs:** `enforce_owner_is_self` (project_pending_facts.rs:931), test at :1008, `BadPurgeOwnerProjector`.

### PROJ-25 — cross-fact need/offer/time-wake ownership also rejected (purge sibling guards) `handler-unit`
- **Setup:** Current binary. Three test projectors emitting a need / an offer / a time-wake whose `owner != fact.id`.
- **Action:** Run each through `run_projection`.
- **Expect:** Each yields `Err` ("projector emitted need with owner ...", "... offer with owner ...", "... time wake ...") per project_pending_facts.rs:940-963; matches existing tests at :975, :986, :997. Confirms a `_vN` projector cannot launder authority by emitting context owned by another fact.
- **Defends:** owner-is-self invariant for the whole `ProjectionOutput` (needs/offers/wakes), guarding the cross-fact-purge invariant's siblings.
- **Refs:** `enforce_owner_is_self` (project_pending_facts.rs:940-963).

### PROJ-26 — direct projector call still errors on unknown tag; admission handles above-ceiling first `projector-unit`
- **Setup:** Current binary. A received fact whose first byte is a tag with NO `FactRoute` (e.g. a future `content::message_v2` tag not yet registered, or any unregistered `u8`).
- **Action:** Call `ProtocolProjector::project` / `RouterProjector::project` on that fact.
- **Expect:** Direct projection returns `Err("no target projector registered for fact tag {tag}")` (projectors.rs). This guard remains correct for direct projector calls and truly unknown tags. The future admission path must reject/drop above-ceiling network input before projector dispatch so this error is not the user-facing network behavior for a known future tag.
- **Defends:** ADMISSION boundary + routing is strictly by registered tag.
- **Refs:** `RouterProjector::project` (projectors.rs:454-458), inventory section 5.

### PROJ-27 — a registered _vN tag activates its own NEW projector (no version byte reuse) `projector-unit`
- **Setup:** A future `content::message_v2` family registered with a NEW tag T2 and a NEW `FactRoute{tag:T2, projector:project_content_message_v2}` while tag 50 keeps `project_content_message`.
- **Action:** Project a tag-50 fact and a tag-T2 fact through `RouterProjector`.
- **Expect:** Tag 50 -> `ContentMessageProjector`; tag T2 -> the v2 projector. The two never collide; `fact_route_tags_are_globally_unique` (registry.rs:717) keeps T2 distinct. No internal version byte is consulted — the tag alone selects the projector.
- **Defends:** Versioning knob = fact tag; new wire shape => new tag + new kept-forever projector + sibling `_vN/`.
- **Refs:** `projector_routes!` (registry.rs:580), `fact_route_tags_are_globally_unique` (registry.rs:717-729).

### PROJ-28 — content::reaction (tag 52) old fact projects to current reaction row `projector-unit`
- **Setup:** Current binary. A retained `content::reaction` fact (tag 52) from an older era with valid target-message context.
- **Action:** Call `ContentReactionProjector::project` (route `project_content_reaction`, registry.rs:606).
- **Expect:** Emits the current `CONTENT_REACTIONS` read-model row shape; no version-conditional branch. Confirms ceiling-era rows for a content family that has no `cli.rs`/`queries.rs` of its own (rows shared at head only).
- **Defends:** Invariant 2 ceiling-era rows for a rows-only content family.
- **Refs:** `content::reaction::project::ContentReactionProjector`, `read_models::CONTENT_REACTIONS`.

### PROJ-29 — old fact deletion context removes ONLY its own rows + purges ONLY itself `projector-unit`
- **Setup:** Current binary. A retained `content::message` fact (tag 50, older era) plus a matching `content_purged` deletion context (a `content::message_deletion` payload that validates).
- **Action:** Call `ContentMessageProjector::project` with the deletion context matched.
- **Expect:** `author_deletion_output` (message/project.rs:493) deletes rows from `CONTENT_MESSAGE_ROWS`/`OPENED_MESSAGE_ROWS` keyed by THIS message id only, inserts a tombstone, and `purge_self(message_id)`. The deletion fact itself is not purged by the message projector (it owns its own lifecycle); the purge coordinate meets on the target's key (purge/project.rs:36-45), not by one projector reaching into another's fact.
- **Defends:** self-purge-only + the `content_purged` context-coordinate mechanism (purge is CONTEXT, not a fact family).
- **Refs:** `author_deletion_output` (message/project.rs:493), `content_purge::target_purged_need` (message/project.rs:75), `purge/project.rs`.

### PROJ-30 — replay recreates only deterministic derived facts; container-emitted inner facts re-derive identically `replay-cli`
- **Setup:** Current binary, store holding a `connection::frame_small` container fact (tag 168) whose projector emitted inner `content::message` child facts on first admission.
- **Action:** Wipe + replay.
- **Expect:** The frame projector re-decrypts and re-emits the SAME inner child facts (deterministic by fact id), and those inner facts re-project to the same rows. Replay recreates only deterministic facts; no fresh randomness/time changes the emitted inner facts.
- **Defends:** Invariant 4 (replay recreates only deterministic facts) + container-fact emit purity.
- **Refs:** `connection::frame_small::project` (emit inner facts), `connection_frame_wire.rs` deterministic nonce derivation (`connection_send_nonce`), wipe+replay pipeline.
## 9. Replay x versioning

Cluster REPLAY defends INVARIANT (4) REPLAY DETERMINISM (wipe+replay rebuilds
derived state; order-independent; ceiling-independent; recreates only
deterministic facts) and its intersections with VERSIONING (mixed fact-tag
versions present at replay), ADMISSION pending (wire-admitted above-ceiling
input is syncable but not active replay input until the ceiling/context admits
it), the
deterministic `create_key_wrap` / `unwrap_key_wrap` handlers (idempotent,
respect purge/retirement, do not resurrect opened secrets), the `content_purged`
CONTEXT (re-derived from retained deletion/expiry/retention facts), and the
replay barrier (full replay + purge complete before any network activity
resumes; `runs_during_replay` gates which handlers dispatch before the barrier).

Replay CLI surface under test (from `docs/research/poc10-replay-intent-shape.md`,
the planned verbs this cluster validates): `replay [--reverse | --scramble
--seed N]`, `state-summary` (emits `state_hash` + per-area hashes/counts),
`replay-check` (snapshots the DB, runs canonical + idempotent + `--reverse` +
several `--scramble --seed N` passes, compares `state_hash`), `intent-registry`
(lists `runs_during_replay` / recurrence / network-IO per `HandlerRoute`), and
`recurring-intents`. The existing in-tree harness that exercises the replay path
today is `con test-generate-deps` (-> `generate_deps`) + `con
test-replay-deps-reverse` (-> `replay_deps_reverse`) in
`sync::cascade_test_fact::commands`. Where a test names `con replay` / `con
state-summary` etc. it targets the planned replay entry point described in the
runtime-changes section of that doc; per the inventory these verbs are not yet
shipped, so those tests are RED until the replay entry point lands and assert the
documented behavior. Tests that can run today against shipped code are marked as
such in their Refs.

Per the charter, the `{new version}/{old version}` axis is enumerated as
separate tests for the representative versioned families (`content::message`,
`content::file`/`content::file_slice`), and the per-scope axis (auth, content,
connection, sync) is enumerated as separate tests where it changes the assertion.

---

### REPLAY-01 — Wipe+replay rebuilds all read-model rows from retained facts only `replay-cli`
- **Setup:** Single `con` node, protocol ceiling covers `content:1` (message tag 50). Create a workspace, send N messages, react, send a file (`content::file` 54 + `content::file_slice` 55). Capture `con state-summary` -> baseline `state_hash` H0 and per-area counts (CONTENT_MESSAGES, CONTENT_REACTIONS, CONTENT_FILES, FILE_SLICES).
- **Action:** Run `con replay` (canonical pass: drops queued intents, wipes derived state — read-model rows, sync indexes, context edges, time_wakes, pending projection rows, ephemeral projection inputs, temp network queues — marks all retained facts pending, drains fact projection to fixpoint).
- **Expect:** `con state-summary` after replay returns the SAME `state_hash` H0 and identical per-area counts; every read-model row is reconstructed solely from retained facts (no queued intent contributed). Replay counters report `dropped_intents>=0`, `projected_facts == retained fact count`, `blocked network/live-only work == 0`.
- **Defends:** Invariant (4) — wipe+replay rebuilds derived state from retained facts.
- **Refs:** `con replay`/`state-summary`; `core::runtime` replay entry point (doc runtime-changes 1-9); read_models OPENED_MESSAGES/CONTENT_MESSAGES/CONTENT_REACTIONS/CONTENT_FILES/FILE_SLICES (registry.rs 36-182); shipped analog `replay_deps_reverse` (`sync/cascade_test_fact/commands.rs`).

### REPLAY-02 — Replay rebuilds with MIXED fact versions present (message v1 + message v2 facts) `replay-cli`
- **Setup:** Node at a ceiling that covers BOTH `message:1` (tag 50) and a hypothetical `message:2` (new tag, sibling `content/message_v2/`, kept-forever projector). Retained store holds some v1 message facts (tag 50) AND some v2 message facts (new tag), all ceiling-active. Capture baseline `state_hash` H0.
- **Action:** `con replay` canonical.
- **Expect:** Each retained fact replays via the historical adapter keyed by its OWN tag (tag 50 -> v1 projector, new tag -> v2 projector); CONTENT_MESSAGES rows for both versions render at the ceiling; post-replay `state_hash == H0`. No fact is mis-routed (v2 fact never hits the v1 projector and vice versa).
- **Defends:** Invariant (4) — every retained fact replays via the adapter keyed by its own tag; mixed versions coexist.
- **Refs:** RouterProjector tag dispatch (`core/projectors.rs:423`, effective_tag@433); FACT_ROUTES per-tag entries; `con replay`; content::message layout const TYPE_CONTENT_MESSAGE=50.

### REPLAY-03 — Replay is ceiling-INDEPENDENT: all retained facts replay regardless of current ceiling `replay-cli`
- **Setup:** Node retains v1 (tag 50) and v2 (new tag) message facts that WERE ceiling-active when admitted. Now lower the effective ceiling (e.g. a manifest entry that supports only `message:1`) so v2 is below... no: keep all retained tags within historical admission but set the CURRENT ceiling so it would NOT newly admit v2. The retained v2 facts are already in the store.
- **Action:** `con replay` canonical, then `con state-summary`.
- **Expect:** Replay projects EVERY retained fact through its own-tag adapter irrespective of the current ceiling — the v2 facts still rebuild their rows because they are retained. Ceiling gates ADMISSION of new/received facts, not REPLAY of already-retained ones. `state_hash` matches the pre-replay summary.
- **Defends:** Invariant (4) — ceiling-independent replay (retained facts replay via own-tag adapter regardless of ceiling).
- **Refs:** doc invariant "ceiling-independent (every retained fact replays via the historical adapter keyed by its OWN tag)"; `con replay`/`state-summary`; RouterProjector `core/projectors.rs`.

### REPLAY-04 — Order-independent: canonical vs --reverse yield identical state_hash with mixed versions `replay-cli`
- **Setup:** Node retains mixed v1 (tag 50) + v2 (new tag) message facts plus reactions, file, slices. Run `con replay` canonical, capture `state_hash` Hc.
- **Action:** `con replay --reverse` (admit retained facts newest-first), then `con state-summary`.
- **Expect:** `state_hash == Hc`. Reverse admission order produces byte-identical derived state across all per-area hashes; the dependency cascade (reactions need their target message; file_slice needs its file) resolves via context match wakeups regardless of admission order.
- **Defends:** Invariant (4) — order-independent rebuild with mixed versions.
- **Refs:** planned `con replay --reverse`; shipped precedent `replay_deps_reverse` (reverse staged-dep replay, `sync/cascade_test_fact/commands.rs:84`); context match wakeups (`core::pipeline::context`).

### REPLAY-05 — Order-independent: scramble seeds yield same state_hash (replay-check) with mixed versions `replay-cli`
- **Setup:** Node retains mixed v1+v2 message facts + reactions + file + slices. 
- **Action:** `con replay-check` (snapshots DB to scratch; runs canonical, idempotent, `--reverse`, and several `--scramble --seed N` passes for distinct N; compares `state_hash` across all passes).
- **Expect:** `replay-check` reports ONE identical `state_hash` for every pass (canonical == idempotent == reverse == scramble seed1 == scramble seed2 ...) and zero per-area hash/count divergence; reports zero network/live-only side effects during every pass.
- **Defends:** Invariant (4) — order- and interleaving-independence proven across seeds with mixed versions.
- **Refs:** planned `con replay-check`, `con replay --scramble --seed N`; doc Test Plan "Replay CLI test" / "Replay order test".

### REPLAY-06 — Scramble seed determinism: same seed twice -> same state_hash; different seeds -> still same final state `replay-cli`
- **Setup:** Node with mixed-version content facts.
- **Action:** Run `con replay --scramble --seed 7` twice and `con replay --scramble --seed 99` once; capture `con state-summary` after each.
- **Expect:** `--scramble --seed 7` admits facts in a deterministic shuffled order that is identical across the two seed-7 runs (same intermediate ordering), and the FINAL `state_hash` is identical for all three runs (seed-7 run A, seed-7 run B, seed-99 run). Seed only changes the admission interleaving, never the converged state.
- **Defends:** Invariant (4) — deterministic shuffle is reproducible per seed; final state is seed-independent.
- **Refs:** planned `con replay --scramble --seed N`; `state-summary` `state_hash`.

### REPLAY-07 — Pending above-ceiling input survives the wipe but stays inert below ceiling `replay-cli`
- **Setup:** Node at ceiling covering only `message:1`. Node RECEIVES an above-ceiling fact (a `message:2` new-tag fact) over sync. Per ADMISSION it is retained as pending ingress, not active protocol truth. Capture `con content-count` and `con state-summary`.
- **Action:** `con replay` canonical (which wipes derived state then re-marks retained facts pending).
- **Expect:** The pending bytes are retained and syncable by id/bytes, but replay at the old ceiling does not dispatch them to the projector. No CONTENT_MESSAGES row appears, `con content-count` is unchanged, `con messages` does not show it, and `con state-summary` reports it only as pending ingress, not as an active fact.
- **Defends:** ADMISSION pending — wire-admitted future bytes survive replay without becoming active.
- **Refs:** future admission gate; `con replay`/`content-count`/`messages`; pending ingress tradeoff.

### REPLAY-08 — Pending input activates after a post-rise replay `replay-cli`
- **Setup:** Continue from REPLAY-07: the original `message:2` copy is retained as pending. Now a fleet-wide signed manifest raises the ceiling so `message:2` is ceiling-active (its new tag is now routed/active). The v2 projector + sibling `content/message_v2/` exist (kept-forever).
- **Action:** `con replay` canonical at the higher ceiling.
- **Expect:** Replay re-runs admission for the pending copy, authenticates it, dispatches it via its OWN-tag adapter (the v2 projector), and produces its CONTENT_MESSAGES row; `con content-count` increases by one; `con messages` now shows it.
- **Defends:** ADMISSION pending activation — no redownload is required for retained pending bytes; retained facts replay normally once active.
- **Refs:** pending ingress tradeoff; `con replay`/`content-count`/`messages`; FACT_ROUTES new v2 entry.

### REPLAY-09 — Replay separates pending ingress from projector-pending facts `guardrail`
- **Setup:** Store was exposed to above-ceiling input before the replay, and admission retained it as pending ingress.
- **Action:** Drive the replay projection drain (`drain_pending_projection` over the retained set, the path `con replay` invokes).
- **Expect:** The replay completes without routing the pending-ingress tag while it remains above ceiling. It is not inserted into the ordinary projector-pending queue until it authenticates and becomes an active fact.
- **Defends:** ADMISSION pending + Invariant (4) — replay operates over active retained facts and keeps pending ingress separate until admission succeeds.
- **Refs:** `core/pipeline/project_pending_facts.rs:248` `drain_pending_projection`.

### REPLAY-10 — create_key_wrap dispatch during replay is idempotent (no duplicate key_wrap fact) `handler-unit`
- **Setup:** Runtime opened from `MATCH_RUNTIME` retains the recipient_key (tag 150), source secret (local_key_secret 152 or local_history_node_secret 153), and signer secret (local_signer_secret 133) facts, plus an already-created `key_wrap` fact (tag 155) produced by an earlier `create_key_wrap` dispatch.
- **Action:** Replay re-emits the `create_key_wrap` intent (it has `runs_during_replay = true`) and the `CreateKeyWrapHandler` runs again over the same retained inputs.
- **Expect:** `create::create_validated_key_wrap_fact` produces the SAME deterministic `key_wrap` fact (same fact id via deterministic raw wrap + idempotence key); submitting it is a no-op dedupe — exactly one `key_wrap` fact remains, KEY_WRAPS rows unchanged. `create_key_wrap_key` over identical inputs equals the prior intent key (idempotence).
- **Defends:** Invariant (4) recreates only deterministic facts; doc Key-wrap test "idempotent, creates no duplicate meaning when the same wrap already exists".
- **Refs:** `auth/create_key_wrap.rs` (`CreateKeyWrapHandler`, `create_key_wrap_key`); `auth/key_wrap/create.rs` `create_validated_key_wrap_fact`; HANDLER_ROUTES `create_key_wrap`; planned `runs_during_replay=true` for it.

### REPLAY-11 — create_key_wrap recreated wrap is bit-identical across canonical/reverse/scramble passes `handler-unit`
- **Setup:** Runtime retains recipient/source/signer facts for a FrontierRoot wrap source AND a HistoryNode wrap source (both WrapSourceKind variants), no pre-existing key_wrap facts.
- **Action:** Run replay canonical, then reverse, then `--scramble --seed N`, dispatching `create_key_wrap` in each pass.
- **Expect:** The resulting `key_wrap` fact bytes (tag 155) are identical across all passes for each source kind; the deterministic raw wrap does not depend on admission order or which pass created it. State_hash over KEY_WRAPS is equal across passes.
- **Defends:** Invariant (4) — deterministic fact recreation is order-independent.
- **Refs:** `auth/create_key_wrap.rs` WrapSourceKind::{FrontierRoot,HistoryNode}; `auth/key_wrap/create.rs`; `con replay`/`--reverse`/`--scramble`.

### REPLAY-12 — create_key_wrap respects a PURGED source secret: no wrap recreated for purged source `handler-unit`
- **Setup:** Runtime previously created a `key_wrap` from a local source secret that has since been removed by a purge context (the source local secret fact was self-purged after a `local_secret_retirement` 157 / removal_frontier 151 covered it; the source fact is no longer retained).
- **Action:** Replay re-derives the purge context from retained retirement/removal facts; the `create_key_wrap` intent (if re-emitted) runs its handler.
- **Expect:** `CreateKeyWrapHandler::handle` calls `context.require_fact(source_fact_id)` which FAILS (source purged/absent) -> handler returns Err / produces no fact; replay creates NO new wrap from the purged source. Purge context defines absence; the wrap is not resurrected from a removed source.
- **Defends:** Deterministic key_wrap respects purge/retirement; Invariant (4) recreates only facts whose deterministic inputs are still retained.
- **Refs:** `auth/create_key_wrap.rs` `require_fact`; `auth/local_secret_retirement/project.rs` (self-purge offer); `auth/removal_frontier/project.rs`; `content/purge/project.rs` context.

### REPLAY-13 — create_key_wrap respects RETIREMENT: a retired signer secret yields no recreated wrap `handler-unit`
- **Setup:** Runtime retains a `local_secret_retirement` (tag 157) targeting the signer secret (`local_signer_secret` 133); on replay the retirement projector publishes the `secret_retired` exact context and the target signer-secret projector self-purges, so the signer fact is absent after the purge phase.
- **Action:** Replay drains the purge/retirement context to fixpoint, then dispatches `create_key_wrap`.
- **Expect:** `require_fact(signer_secret_fact_id)` fails -> no wrap fact recreated; the retirement removes the signer material before the wrap-creation handler runs. (Ordering: purge/retirement context settled before replay-allowed `create_key_wrap` is permitted to materialize.)
- **Defends:** Deterministic key_wrap respects retirement facts; replay applies purge before recreating dependent facts.
- **Refs:** `auth/local_secret_retirement/project.rs` `secret_retired_offer`; `auth/create_key_wrap.rs`; doc runtime-changes step ordering (project facts -> drain replay-allowed work).

### REPLAY-14 — unwrap_key_wrap dispatch during replay is idempotent and recreates a deterministic local secret `handler-unit`
- **Setup:** Runtime retains the `key_wrap` (155), `local_recipient_key` (156), `recipient_key` (150), and `removal_frontier` (151) facts that an earlier `unwrap_key_wrap` consumed to produce a local opened secret (local_key_secret 152 or local_history_node_secret 153). The opened secret is still retained (not purged).
- **Action:** Replay re-emits the `unwrap_key_wrap` intent (`runs_during_replay = true`) and `UnwrapKeyWrapHandler` runs again over the same retained inputs.
- **Expect:** `create::unwrap_key_wrap_fact` produces the SAME deterministic local secret fact (same id); re-submission dedupes to exactly one; no duplicate local secret rows. `unwrap_key` over identical inputs equals the prior intent key.
- **Defends:** Invariant (4) recreates only deterministic facts; doc Unwrap test "idempotent, creates deterministic local secret facts".
- **Refs:** `auth/unwrap_key_wrap.rs` (`UnwrapKeyWrapHandler`, `unwrap_key`); `auth/key_wrap/create.rs` `unwrap_key_wrap_fact`; HANDLER_ROUTES `unwrap_key_wrap`; planned `runs_during_replay=true`.

### REPLAY-15 — unwrap_key_wrap does NOT resurrect an opened secret that purge/retirement removed `handler-unit`
- **Setup:** Runtime previously opened a wrap to a local secret, then that local secret was REMOVED by a `local_secret_retirement` (157) (or removal_frontier 151) — the opened secret fact is no longer retained. The `key_wrap` (155), `local_recipient_key` (156), `recipient_key` (150), `removal_frontier` (151) inputs are still retained, and the retirement fact is retained.
- **Action:** Replay re-derives purge/retirement context from the retained retirement fact; if the `unwrap_key_wrap` intent is re-emitted, its handler would deterministically rebuild the same secret bytes.
- **Expect:** Ordinary purge/retirement rules decide survival: the re-derived purge context marks the opened secret absent, so the rebuilt secret is NOT re-admitted/retained (it is dropped per the same rules an offline-then-catch-up endpoint applies). Replay must NOT leave a resurrected opened secret in the store. `con keys` shows the secret as retired/absent.
- **Defends:** unwrap_key_wrap respects purge/retirement; does not resurrect opened secrets.
- **Refs:** `auth/unwrap_key_wrap.rs`; `auth/local_secret_retirement/project.rs`; doc "Ordinary purge/retirement rules decide whether those local secret facts survive"; planned `con keys`.

### REPLAY-16 — unwrap_key_wrap matches the offline-then-catch-up endpoint behavior (replay uses the same purge rules) `handler-unit`
- **Setup:** Two runtimes from the SAME retained fact set: runtime A reached its state by live operation (open + later retire); runtime B is built by `con replay` from A's retained facts only (wipe + replay). Both have the retirement fact retained.
- **Action:** Compare `con state-summary` `state_hash` (local key-material area) of A (after a quiescent settle) and B (after replay).
- **Expect:** Identical local key-material state_hash: replay applies the exact same purge/retirement rules as the live endpoint, so an opened-then-retired secret is absent in both. Upgrade replay == catch-up endpoint.
- **Defends:** Invariant (4) + doc "Upgrade replay uses the same purge and retirement rules as an endpoint that was offline and later catches up".
- **Refs:** planned `con state-summary`/`con replay`; `auth/local_secret_retirement/project.rs`; `auth/key_wrap/create.rs`.

### REPLAY-17 — Purge CONTEXT re-derived from retained message_deletion facts across versions `projector-unit`
- **Setup:** Retained facts: a `content::message` (tag 50, v1) plus a `content::message_deletion` (tag 51) that purges it; ALSO a v2 message fact (new tag) plus a deletion targeting it. Capture baseline (MESSAGE_TOMBSTONES rows, CONTENT_MESSAGES absence for purged ids).
- **Action:** `con replay` canonical — the deletion projector re-emits the `content_purged` offer; the target message projector exact-matches its own `target_purge_key` and self-purges.
- **Expect:** Purge context is re-derived ONLY from retained deletion facts (no surviving derived state). Both the v1-purged and v2-purged messages are absent from CONTENT_MESSAGES after replay; MESSAGE_TOMBSTONES rebuilt for both; `state_hash` matches pre-replay. Purge absence holds across versions.
- **Defends:** Purge context re-derived from retained deletion facts defines absence across versions; Invariant (4).
- **Refs:** `content/purge/project.rs` `target_purged_offer`/`target_purge_key`/`content_purged_role`; content::message_deletion (tag 51); read_models MESSAGE_TOMBSTONES/CONTENT_MESSAGES (registry.rs 36-182); `con replay`.

### REPLAY-18 — Purge context re-derived from retained file_deletion facts (file + file_slice across versions) `projector-unit`
- **Setup:** Retained: a `content::file` (54) with `content::file_slice` facts (55, v1), a `content::file_deletion` (53) purging them; AND a v2 file/file_slice (new tags) with its deletion. Baseline FILE_DELETIONS / CONTENT_FILES / FILE_SLICES rows.
- **Action:** `con replay` canonical.
- **Expect:** File-purge context re-derived from retained `content::file_deletion` facts; purged file + slices absent from CONTENT_FILES/FILE_SLICES for BOTH versions; FILE_DELETIONS rebuilt; `state_hash` matches. The file_slice carrier-capacity precedent does not affect purge re-derivation.
- **Defends:** Purge re-derivation across content versions (file family); Invariant (4).
- **Refs:** `content/purge/project.rs`; content::file_deletion (53), content::file (54), content::file_slice (55); read_models FILE_DELETIONS/CONTENT_FILES/FILE_SLICES.

### REPLAY-19 — Purge context re-derived from retained retention_policy + expiry (disappearing messages) `projector-unit`
- **Setup:** Retained: messages, a `content::retention_policy` (tag 147) set via `disappearing-set`, and the trusted-time observations needed to drive expiry. Some messages are past their expiry window; replayable semantic time wakes will fire.
- **Action:** `con replay` (which admits replayable semantic time wakes to fixpoint, doc step 6), then `con disappearing-status` / `con messages`.
- **Expect:** Expiry-driven purge context is re-derived from the retained retention_policy fact + retained time observations via replayable semantic time wakes (NOT wall-clock operational decisions); expired messages absent post-replay exactly as before; non-expired messages present; `state_hash` matches a quiescent live node with the same retained facts.
- **Defends:** Purge context re-derived from retained expiry/retention facts; replay uses replayable semantic time wakes only.
- **Refs:** content::retention_policy (147), `disappearing-set`/`disappearing-status`; `content/purge/project.rs`; doc runtime-changes step 6 "Admit replayable semantic time wakes to fixpoint".

### REPLAY-20 — Retention TIGHTEN/COMPACT purge survives replay (disappearing-tighten / disappearing-compact) `projector-unit`
- **Setup:** Retained: messages, an initial retention_policy, then a `disappearing-tighten` (tighter policy fact) and a `disappearing-compact` outcome; some messages purged by the tightened window.
- **Action:** `con replay` canonical, then `con disappearing-status`.
- **Expect:** The tightened-then-compacted purge absence is re-derived from the retained policy/tighten/compact facts; the messages purged under the tighter window stay absent after replay; `state_hash` matches pre-replay. Tightening is monotonic and replay-stable.
- **Defends:** Purge re-derivation honors retention-tighten/compact facts; Invariant (4).
- **Refs:** `disappearing-tighten`/`disappearing-compact` (content::retention_policy::cli); `content/purge/project.rs`; content::retention_policy (147).

### REPLAY-21 — Full replay + purge complete BEFORE any network activity resumes (barrier) `guardrail`
- **Setup:** Node with retained facts including content + connection request/response history. `con replay` invoked with network and recurring schedules disabled (per the verb contract).
- **Action:** Inspect the replay sequence: drop intents -> wipe -> mark pending -> drain fact projection -> admit replayable time wakes -> drain replay-allowed work to fixpoint -> (barrier) -> only then start daemon / install recurring intents / resume dispatch.
- **Expect:** No network send, no connection maintenance, no bootstrap retry, no presence refresh, no sync poll occurs before the replay barrier; replay counter "blocked network/live-only work" is reported; if any network/live-only work were attempted pre-barrier, `con replay` reports an ERROR (per doc "A replay command that causes network rows... should report an error").
- **Defends:** Full replay + purge complete before network activity resumes; Invariant (4) barrier.
- **Refs:** doc runtime-changes steps 1-9 (esp. step 8 "Finish all replay-required work before network activity resumes"); `con replay`.

### REPLAY-22 — Network/connection-send handlers are NOT dispatched before the barrier (runs_during_replay=false) `guardrail`
- **Setup:** `intent-registry` declares `runs_during_replay` per HANDLER_ROUTE. The four network/IO intents (`send_bootstrap_connection_request`, `send_facts_on_connection`, `send_network_frame`, `receive_network_frame`) plus `create_connection_response` and sync compare/have/need/send are `runs_during_replay = false`.
- **Action:** Run `con intent-registry` and a `con replay` that would, if naive, re-emit these intents from retained connection/sync facts.
- **Expect:** `intent-registry` lists `runs_during_replay=false` and network-IO=true for the four IO intents and `create_connection_response`; during `con replay` none of these handlers dispatch before the barrier; the replay drains only replay-allowed intents (`share_fact_with_sync`, `create_key_wrap`, `unwrap_key_wrap`, connection-candidate registration).
- **Defends:** Invariant (4) barrier — replay-blind handler gating; doc Replay test "network and connection-send handlers are not dispatched before the replay barrier completes".
- **Refs:** planned `HandlerRoute.runs_during_replay` (doc Intent Registry); HANDLER_ROUTES 17 routes; COMMAND_EXCLUDED_HANDLER_ROUTES (registry.rs 512-517); planned `con intent-registry`.

### REPLAY-23 — create_connection_response does NOT run during replay; rebuilt after barrier from request/response facts `guardrail`
- **Setup:** Retained `connection::request` (42) + `connection::response` (44) facts. `con replay`.
- **Action:** Observe whether `CreateConnectionResponseHandler` (`create_connection_response`) dispatches during the replay drain.
- **Expect:** It does NOT dispatch before the barrier (`runs_during_replay=false`); network-visible response work is rebuilt only AFTER replay from the committed request/response facts via normal post-barrier dispatch. No connection::response side effect emitted pre-barrier.
- **Defends:** Invariant (4) barrier; doc table `create_connection_response` "Does not run during replay".
- **Refs:** HANDLER_ROUTES `create_connection_response` (CreateConnectionResponseHandler, connection::create_connection_response); planned `runs_during_replay=false`.

### REPLAY-24 — Connections retired (connection::close) before replay; no resurrected live session `replay-cli`
- **Setup:** Retained `connection::close` (45) facts retire prior connections; retained `connection::request`/`response` for closed connections. Per TRANSPORT, connections are retired before replay.
- **Action:** `con replay` canonical, then inspect connection-maintenance/connection rows via `con state-summary`.
- **Expect:** Replay rebuilds connection rows reflecting the retained `connection::close` facts — closed connections stay closed; replay does NOT recreate an active live session or a bootstrap send from old `connection_request` history alone (bootstrap retries come only from post-barrier recurring `maintain_connections`). `state_hash` for the connection area matches pre-replay.
- **Defends:** Invariant (4) + TRANSPORT "retire connections before replay"; doc Connection test "replay no longer recreates bootstrap retries from old connection_request history alone".
- **Refs:** connection::close (45); connection::request (42)/response (44); `con replay`/`state-summary`; doc Connection/Bootstrap tests.

### REPLAY-25 — share_fact_with_sync runs during replay to rebuild sync-derived state across versions `handler-unit`
- **Setup:** Retained mixed v1+v2 content facts plus `sync::shared_fact` (162) / `sync::compare` (165) / `sync::have_id` (166) / `sync::need_id` (167) derived state from prior operation. Wipe clears the sync indexes.
- **Action:** `con replay` — `share_fact_with_sync` (`runs_during_replay=true`) rebuilds shareable-fact rows and sync summaries from retained facts.
- **Expect:** Shareable-fact rows and negentropy summaries are wiped then rebuilt from retained facts (both versions shareable at the ceiling); `con sync-status` after replay matches pre-replay; `state_hash` sync area unchanged. No network send accompanies the rebuild (it is derived-state recreation, not transport).
- **Defends:** Invariant (4); doc Sync test "shareable-fact rows and negentropy summaries are wiped and rebuilt from retained facts".
- **Refs:** HANDLER_ROUTES `share_fact_with_sync` (ShareFactWithSyncHandler); sync::shared_fact (162); `con sync-status`/`sync-range`; planned `runs_during_replay=true`.

### REPLAY-26 — Old-version (v1) facts replay via the kept-forever v1 reader even after v2 introduced `replay-cli`
- **Setup:** Ceiling covers v2; store retains ONLY v1 message facts (tag 50) created before v2 existed; the v1 projector (kept forever) and v2 projector both registered.
- **Action:** `con replay` canonical.
- **Expect:** Each v1 fact replays through the v1 reader keyed by tag 50 (NOT the v2 projector); CONTENT_MESSAGES rows render at the ceiling (Invariant 2 rendering uniformity — old projectors emit ceiling-era rows); `state_hash` matches a v1-only baseline. Old fact readers are kept forever.
- **Defends:** Invariant (4) own-tag adapter + Invariant (5) readers forever; rendering at ceiling.
- **Refs:** doc Invariant 5 "old fact readers kept forever"; RouterProjector tag 50 route; `con replay`/`state-summary`.

### REPLAY-27 — New-version (v2-only) store replays correctly when ceiling covers v2 `replay-cli`
- **Setup:** Ceiling covers v2; store retains ONLY v2 message facts (new tag), no v1 facts; v2 projector registered, sibling `content/message_v2/`.
- **Action:** `con replay` canonical.
- **Expect:** Each v2 fact replays via the v2 projector keyed by its own new tag; CONTENT_MESSAGES rows built; `state_hash` matches a v2-only baseline. No v1 projector is invoked.
- **Defends:** Invariant (4) own-tag adapter for the new version.
- **Refs:** FACT_ROUTES v2 entry; RouterProjector; `con replay`/`state-summary`.

### REPLAY-28 — Idempotent replay: replay twice in a row yields identical state_hash (no drift) `replay-cli`
- **Setup:** Node with mixed-version content + key_wrap + purge facts. Run `con replay` once, capture `state_hash` H1.
- **Action:** Run `con replay` AGAIN immediately, capture `state_hash` H2.
- **Expect:** `H1 == H2` exactly; the second wipe+replay drops the same intents, rebuilds the same rows, recreates the same deterministic key_wrap/unwrap facts (idempotent dedupe), and re-derives the same purge absence. No accumulation of duplicate rows or facts.
- **Defends:** Invariant (4) — replay idempotence; doc `replay-check` "idempotent replay" pass.
- **Refs:** `con replay`/`state-summary`/`replay-check`; deterministic handlers `create_key_wrap`/`unwrap_key_wrap`.

### REPLAY-29 — recurring-intents/intent-registry expose maintain_connections as live-only (no durable replay state) `guardrail`
- **Setup:** Node with retained connection/endpoint facts. Recurring operational work (`maintain_connections`, presence refresh, sync polling, bootstrap retry) is registry metadata, not durable rows.
- **Action:** Run `con recurring-intents` and `con intent-registry`; then `con replay` and re-inspect.
- **Expect:** `recurring-intents` lists `maintain_connections` from STATIC registry metadata (no persisted job rows); `intent-registry` shows recurrence/network-IO flags; `con replay` does NOT fire any recurring intent (they do not fire until replay completes and the daemon runs normally) and does not wipe/replay any persisted recurring-job row (there are none). `state-summary` excludes volatile scheduler state.
- **Defends:** Invariant (4) barrier — recurring operational work is not durable replay state; doc Recurring-intent test.
- **Refs:** planned `con recurring-intents`/`con intent-registry`; doc Recurring Intents section (`RecurringIntentSpec`, no persisted rows); HandlerRoute recurrence metadata.

### REPLAY-30 — Cascade-dep reverse replay (shipped) rebuilds applied set order-independently `replay-cli`
- **Setup:** Open a runtime from `MATCH_RUNTIME`. `con test-generate-deps COUNT DEPS_PER_FACT` stages a dependency graph of `sync::cascade_test_fact` (tag 2) facts in CASCADE_STAGED_FACT_ROWS without submitting.
- **Action:** `con test-replay-deps-reverse` submits the staged graph newest-first (reverse) and materializes the context offers that appear only after each dependency completes.
- **Expect:** `ReplayDepsReceipt { replayed_facts == COUNT, applied_facts == COUNT }` when all deps present; applied set is independent of the reverse admission order (a fact applies only once all declared deps have offered completion). Deleting one staged dependency row -> that fact is not replayed and dependents are not applied (`applied_facts == 0`).
- **Defends:** Invariant (4) order-independence — the SHIPPED replay precedent runnable today.
- **Refs:** SHIPPED `con test-generate-deps`/`test-replay-deps-reverse` (`sync/cascade_test_fact/commands.rs` `generate_deps`/`replay_deps_reverse`); CASCADE_STAGED_FACT_ROWS; sync::cascade_test_fact (tag 2); `Runtime::submit_facts` (`core/runtime.rs:274`).

### REPLAY-31 — Replay drops queued intents but rebuilds required work from retained facts `replay-cli`
- **Setup:** Node has durable + local queued intents pending (e.g. a `share_fact_with_sync` and a `create_key_wrap` queued) plus retained facts that justify them. `con state-summary` baseline.
- **Action:** `con replay` (step 2 drops durable + local queued intents; later steps recreate replay-allowed work from retained facts).
- **Expect:** Replay counter reports `dropped_intents > 0`; after replay the required sync/key-wrap work is recreated from retained facts/rows/context (replay-allowed intents re-emitted and drained to fixpoint); no live-only intent (network/bootstrap/receive) is recreated; final `state_hash` matches the converged operational state. Queued intents are NOT protocol truth.
- **Defends:** Invariant (4); doc target invariant "Every poc-10 queued intent is droppable on upgrade".
- **Refs:** `con replay`/`state-summary`; doc Target Invariants + runtime-changes step 2; `Runtime::pending_intent_count` (`core/runtime.rs:246`); `runs_during_replay` table.

### REPLAY-32 — Per-scope replay parity: each scope's read-model rebuilds to identical state_hash (auth/content/connection/sync) `replay-cli`
- **Setup:** Node exercising all four scopes: auth (workspace 131/user 14/admin 139/key_wrap 155), content (message 50/reaction 52/file 54/slice 55/deletions 51,53/retention 147), connection (request 42/response 44/close 45/frame* 168-170,173), sync (shared_fact 162/compare 165/have 166/need 167). Capture per-area `state-summary` hashes.
- **Action:** `con replay --reverse` and `con replay --scramble --seed 3`.
- **Expect:** EACH scope's per-area `state_hash` is identical to the canonical baseline across reverse and scramble passes — auth rows, content rows, connection rows, and sync indexes all rebuild order-independently. No scope diverges; `replay-check` reports zero per-area divergence for all four scopes.
- **Defends:** Invariant (4) order-independence holds per scope, not just globally.
- **Refs:** all four scopes' read_models/rows; `con replay`/`state-summary`/`replay-check`; registry.rs ROW_MUTATION_TABLES (521-553).
## 10. Connection transport version: negotiate / floor / expired-out / carrier-gate / retire

Grounding notes for this cluster (verified against `/home/holmes/poc-10/src`):
- The on-wire transport surfaces that carry an explicit version byte are: the
  sealed bootstrap request (`TYPE_SEALED_CONNECTION_REQUEST = 46`, internal
  `VERSION = 1`, header `[46, 1, ephemeral_pubkey(32), nonce(24)]`,
  `bootstrap_request/layout.rs:88` rejects unless `frame[0]==46 && frame[1]==1`),
  the sealed bootstrap response (`TYPE_SEALED_CONNECTION_RESPONSE = 47`, internal
  `VERSION = 1`, `bootstrap_response/layout.rs:88`), and the established frame
  (`CONNECTION_FRAME_TAG = b"TRNS"`, `CONNECTION_FRAME_VERSION = 1` at
  `VERSION_OFFSET=4`, rejected at `connection_frame_wire.rs:301` and `:412` unless
  `version == CONNECTION_FRAME_VERSION`).
- Per the consolidated model the VERSIONING KNOB is the fact tag, NOT the internal
  version byte: an incompatible established-frame wire shape is a NEW frame tag +
  NEW kept-forever projector + sibling `_vN/` dir (the four `connection::frame_*`
  families: small 168, file_slice 169, bundle 170, observation 173 are the
  precedent for "one tag per size class"). The TRNS magic + internal version byte
  are a socket-level stream recognizer only.
- "Negotiate UP / floor / answer-in-request-version" is realized as: which frame
  TAG (size class today; a future `_v2` tag tomorrow) the sender chooses, gated by
  the fleet ceiling and by carrier capacity (`frame_size_class_for_facts`,
  `fact_batches`). The CEILING-FILTERED router only activates routes whose
  `intro_version <= ceiling`.
- A SUB-FLOOR/EXPIRED peer is OUT: there is NO recovery responder. The only
  responder path is `create_connection_response` (handler
  `CreateConnectionResponseHandler`), reached only by a request fact that opened
  cleanly from a sealed bootstrap-request frame whose `[tag, version]` matched the
  in-floor recognizer. A sub-floor/expired sealed frame fails
  `validate_sealed_connection_request_frame` and is dropped — no response is sent.
- Retire-before-replay = `connection::close` (tag 45, `close.rs`) which offers
  `connection_closed` / `connection_ephemeral_secret_closed` context so the
  response (tag 44) and ephemeral_secret (tag 43) projectors delete/purge their
  rows before a wipe+replay rebuilds sync indexes.

---

### CONN-01 — Two in-floor capable peers negotiate UP to the highest common frame tag for a multi-fact batch  `multinode-network`
- **Setup:** Two `con` daemons A and B, both built at the same protocol version whose ceiling activates `connection::frame_bundle` (tag 170) AND `connection::frame_small` (tag 168). A established connection-response (tag 44) exists between them (full bootstrap handshake completed). Sync selects 5 small `content::message` facts (tag 50) to ship A->B.
- **Action:** Drive the established transfer: sync queues `send_facts_on_connection` for the 5 message fact ids on the connection id; the handler batches them via `fact_batches` and `frame_size_class_for_facts`.
- **Expect:** Because the 5 messages pack within `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` (4 KiB), the negotiated frame TAG is `frame_small` (168) — the smallest carrier that fits, i.e. the most efficient common shape, not bundle. B's `receive_network_frame` classifies it `ConnectionFrameKind::Small`, opens it, and emits 5 child `content::message` facts + 5 `connection::fact_receipt` (tag 164). `con messages` on B shows all 5.
- **Defends:** (1) VISIBILITY (ceiling-active fact transportable by both releases); TRANSPORT negotiate-up between capable peers.
- **Refs:** `connection/send_facts_on_connection.rs` (`fact_batches`:356, `frame_size_class_for_facts`), `connection_frame_wire.rs` (`CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES`), `connection/receive_network_frame.rs` (`classify_frame`), `connection::frame_small` tag 168.

### CONN-02 — In-floor peers negotiate UP to bundle when the small carrier cannot hold the batch  `multinode-network`
- **Setup:** Same two daemons A, B at a ceiling activating both `frame_small` (168) and `frame_bundle` (170). Sync selects enough small facts that `packed_len` exceeds `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` but each fact `<= CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES` and `count <= CONNECTION_FRAME_BUNDLE_FACT_SLOTS`.
- **Action:** Drive `send_facts_on_connection` for the over-4KiB batch.
- **Expect:** `frame_size_class_for_facts` returns `CONNECTION_FRAME_SIZE_CLASS_BUNDLE`; A ships a `frame_bundle` (tag 170) frame; B classifies `ConnectionFrameKind::Bundle`, opens the inner bundle, admits each contained fact with one receipt each. The carrier was negotiated UP to bundle ONLY because small was too small — capacity, not preference, drove the choice.
- **Defends:** (1) VISIBILITY; carrier-capacity gates the carrier choice (chunk-don't-grow precedent).
- **Refs:** `connection_frame_wire.rs` (`frame_size_class_for_facts`:659, `CONNECTION_FRAME_BUNDLE_FACT_SLOTS`, `CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES`), `connection::frame_bundle` tag 170.

### CONN-03 — Initiator with NO peer metadata bootstraps at the operational floor (sealed request v1)  `blackbox-cli`
- **Setup:** Fresh `con` initiator A holding an invite to responder B; A has never contacted B and has no `connection_response` row, no negotiated frame version for B — peer is UNKNOWN.
- **Action:** Trigger the outbound handshake: the request projector emits `send_bootstrap_connection_request`; `SendBootstrapConnectionRequestHandler::handle` seals the request via `bootstrap_request::seal_connection_request` and writes one TCP frame.
- **Expect:** The bytes written start with `[46, 1, ...]` — `TYPE_SEALED_CONNECTION_REQUEST=46` then internal `VERSION=1` (the oldest still-safe bootstrap recognizer). No attempt is made to bootstrap at a newer/unknown shape against an unknown peer.
- **Defends:** TRANSPORT "initiate at the operational floor when the peer is unknown"; (5) transport in `[floor, head]`.
- **Refs:** `connection/send_bootstrap_request.rs` (`SendBootstrapConnectionRequestHandler::handle`), `bootstrap_request/layout.rs` (`seal_connection_request`, `request_header` emits `TYPE_SEALED_CONNECTION_REQUEST` then `VERSION`), test `sends_sealed_bootstrap_request_bytes` asserts `sent[0]==46`.

### CONN-04 — Responder answers a floor (v1) bootstrap request in the SAME request version (v1 sealed response)  `multinode-network`
- **Setup:** Responder B receives the floor-version sealed bootstrap request from CONN-03 (`[46,1,...]`). B's local endpoint context (`auth_daemon_endpoint`) is present.
- **Action:** B's daemon submits `receive_network_frame`; `is_bootstrap_request_frame` is true; the `bootstrap_request` wrapper (tag 171) projects, opens the request, emits global `request` (tag 42) + `fact_receipt` (164); the request projector queues `create_connection_response`; `CreateConnectionResponseHandler::handle` seals a response and sends it.
- **Expect:** The sealed response B writes begins `[47, 1, ...]` — `TYPE_SEALED_CONNECTION_RESPONSE=47` then internal `VERSION=1`, i.e. answered in the request's (floor) version. A `connection::response` (tag 44) and responder `ephemeral_secret` (tag 43) are produced locally on B.
- **Defends:** TRANSPORT "answer in the request's version for a still-usable older peer".
- **Refs:** `connection/create_connection_response.rs` (`CreateConnectionResponseHandler::handle`, `bootstrap_response::seal_connection_response`), `bootstrap_response/layout.rs` (`VERSION`, `TYPE_SEALED_CONNECTION_RESPONSE`), `connection/receive_network_frame.rs`.

### CONN-05 — Still-usable older peer's vN bootstrap request answered vN (request-version mirroring across the wire layer)  `handler-unit`
- **Setup:** Construct a `connection::request` fact and matching initiator `ephemeral_secret`; seal at the in-floor recognizer (`frame[0]=46, frame[1]=1`). Build a `HandlerContext::with_facts([request_fact, ephemeral_fact])`. Open path validated by an `EndpointFact` for the responder.
- **Action:** Run `CreateConnectionResponseHandler::handle` on the resulting `create_connection_response` intent (request_id, invite_secret_id, receive_id).
- **Expect:** The handler returns `PipelineEffects` carrying exactly the responder `ephemeral_secret` fact (tag 43) and the built `response` fact (tag 44); the sealed response staged through `network::send` has header `[47, 1]`. The responder NEVER upgrades the answer version above the request version it opened.
- **Defends:** TRANSPORT request-version mirroring; (5) READERS/responders honor the peer's in-floor version.
- **Refs:** `connection/create_connection_response.rs` (handler body :187-265, `build_responder_response`), `bootstrap_response::seal_connection_response`.

### CONN-06 — Sub-floor sealed bootstrap request is OUT: no request fact, no response (regression: no recovery responder)  `handler-unit`
- **Setup:** A daemon B with full local endpoint context. Craft a sealed bootstrap-request frame whose first two bytes are a sub-floor/retired shape, e.g. `frame[0]=46, frame[1]=0` (a pre-floor internal version) — length otherwise `SEALED_CONNECTION_REQUEST_BYTES`.
- **Action:** Submit it via `receive_network_frame`; the handler calls `is_bootstrap_request_frame` then `received_bootstrap_request_frame_effect`, which opens through `validate_sealed_connection_request_frame`.
- **Expect:** `validate_sealed_connection_request_frame` returns `Err("sealed connection request has unsupported header")` (`frame[1] != VERSION`); the frame is NOT staged as a `bootstrap_request` (tag 171) wrapper, NO `request` (tag 42) fact is created, and crucially NO `create_connection_response` is queued — the peer gets NO answer. The sealed bytes are dropped, not error-recovered.
- **Defends:** (5) EXPIRED/SUB-FLOOR PEERS ARE OUT — no recovery responder; (6) SAFETY FLOOR.
- **Refs:** `bootstrap_request/layout.rs:84-92` (`validate_sealed_connection_request_frame`), `connection/receive_network_frame.rs:124-132`, `bootstrap_request::create::received_bootstrap_request_frame_effect`.

### CONN-07 — Sub-floor sealed bootstrap RESPONSE is OUT: dropped, no connection materialized  `handler-unit`
- **Setup:** Initiator A with a pending local `request` row awaiting `connection_response_for_request`. Craft a sealed bootstrap-response frame with a sub-floor header `frame[0]=47, frame[1]=0`.
- **Action:** Submit via `receive_network_frame`; `is_bootstrap_response_frame` then `received_bootstrap_response_frame_effect` -> `validate_sealed_connection_response_frame`.
- **Expect:** Validation errs (`frame[1] != VERSION`); no `bootstrap_response` (tag 172) wrapper, no `response` (tag 44) fact, no `seed_connection_sync`. A's pending request stays unanswered (retries continue at the floor recognizer, per CONN-03), it does not "downgrade-accept" a sub-floor response.
- **Defends:** (5) sub-floor peer OUT on the response leg too; (6) SAFETY FLOOR.
- **Refs:** `bootstrap_response/layout.rs:84-90` (`validate_sealed_connection_response_frame`), `connection/receive_network_frame.rs:133-141`.

### CONN-08 — Sub-floor / unknown ESTABLISHED frame version byte is OUT: classify yields no child facts  `handler-unit`
- **Setup:** An established connection exists. Craft a TRNS frame with a wrong internal version: `tag=b"TRNS"`, byte at `VERSION_OFFSET=4` set to `2` (not `CONNECTION_FRAME_VERSION=1`), valid `SIZE_CLASS_SMALL=0`.
- **Action:** Submit via `receive_network_frame`; handler reaches `connection_frame::classify_frame` then the per-class `fact_from_wire` open.
- **Expect:** The open path rejects at `connection_frame_wire.rs:301` / `:412` (`version != CONNECTION_FRAME_VERSION`); no child facts and no receipts are emitted; the handler returns empty `PipelineEffects` (the `None` arm or an open error that does not admit facts). An out-of-version established frame is OUT.
- **Defends:** (5) transport in `[floor,head]`; (1) only in-floor frame versions are projectable.
- **Refs:** `connection_frame_wire.rs:300-304` & `:411-414` (version check), `connection/receive_network_frame.rs:142-159`, `connection_frame.rs` (`classify_frame`:95).

### CONN-09 — Established frame with an unknown SIZE-CLASS byte (future carrier tag) classifies to None and admits nothing  `handler-unit`
- **Setup:** Established connection. Craft a TRNS frame with `version=1` but `size_class=3` (none of SMALL=0 / FILE_SLICE=1 / BUNDLE=2 — simulating a not-yet-active future carrier tag).
- **Action:** Submit via `receive_network_frame`.
- **Expect:** `connection_frame::classify_frame` returns `None` (the match on `header.size_class` has no arm for 3); handler hits the `None => PipelineEffects::new()` arm: no child facts, no receipts, frame retained as opaque local-receive bytes only. A peer's above-ceiling carrier is NOT projected (pending-shaped behavior at the carrier-class level).
- **Defends:** ADMISSION (received above-ceiling carrier not projected, not error-cascaded); (3) CEILING MONOTONICITY.
- **Refs:** `connection_frame.rs:95-102` (`classify_frame` match), `connection/receive_network_frame.rs:142-159` (`None` arm).

### CONN-10 — Carrier capacity GATES ceiling activation: a fact too big for the in-floor bundle slot is REFUSED, not grown  `handler-unit`
- **Setup:** Established connection. A non-file-slice fact whose encoded length `> CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES` (e.g. a hypothetical fat fact) is selected by sync.
- **Action:** Run `SendFactsOnConnectionHandler` so `fact_batches` processes it.
- **Expect:** `fact_batches` returns `Err("send_facts_on_connection fact exceeds connection frame bundle slot")` — the sender refuses to "grow the frame". The capability of shipping that fat fact cannot go ceiling-active over the in-floor frame; it must wait for a chunking path (the `file_slice` precedent) or a new larger frame tag. No oversized frame is built.
- **Defends:** CARRIER CAPACITY GATES CEILING (chunk-don't-grow); (3) CEILING MONOTONICITY.
- **Refs:** `connection/send_facts_on_connection.rs:370-374`, `connection_frame_wire.rs` (`CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES`).

### CONN-11 — The file_slice carrier precedent: an exactly-slice-sized fact takes the dedicated file_slice frame, not a grown small/bundle  `handler-unit`
- **Setup:** Established connection. Sync selects a single `content::file_slice` fact (tag 55) of exactly `CONTENT_FILE_SLICE_BYTES`, plus separately a batch of small facts.
- **Action:** Run `SendFactsOnConnectionHandler`; observe batching in `fact_batches` and `frame_size_class_for_facts`.
- **Expect:** The file_slice fact is split into its own batch (`fact_batches:362-368` flushes the current batch and pushes `vec![fact]`); that batch seals as `frame_file_slice` (tag 169, `CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE`). Large file payloads ride the chunked file_slice carrier rather than forcing a bigger frame — the precedent that lets oversized content go ceiling-active via chunking.
- **Defends:** CARRIER CAPACITY GATES CEILING (chunk-don't-grow precedent); (1) VISIBILITY of large content via chunking.
- **Refs:** `connection/send_facts_on_connection.rs:362-368`, `connection_frame_wire.rs:659-682` (`frame_size_class_for_facts` file-slice arm), `content::file_slice` tag 55, `frame_file_slice` tag 169.

### CONN-12 — Each established carrier size class is a SEPARATE kept-forever tag (knob = tag, not version byte)  `guardrail`
- **Setup:** Read `FACT_ROUTES` in `registry.rs` and the four `connection::frame_*` family dirs.
- **Action:** Assert that `frame_small` (168), `frame_file_slice` (169), `frame_bundle` (170), `frame_observation` (173) each have a distinct `FactRoute.tag` and a distinct projector, and that the established wire carries no routed-fact internal version byte beyond the socket-level TRNS recognizer.
- **Expect:** All four tags present and distinct in `FACT_ROUTES`; `fact_route_tags_are_globally_unique` passes; an incompatible future carrier shape would require adding a NEW tag + projector (e.g. a `frame_small_v2`), not bumping `CONNECTION_FRAME_VERSION`. The single `CONNECTION_FRAME_VERSION=1` byte is shared across all three encrypted carriers (it is the stream recognizer, not the routing knob).
- **Defends:** VERSIONING KNOB = fact tag; (4) REPLAY DETERMINISM (each tag keeps its own historical adapter forever).
- **Refs:** `registry.rs` (`FACT_ROUTES`, `fact_route_tags_are_globally_unique`:717-729), `connection/frame_small`/`frame_file_slice`/`frame_bundle`/`frame_observation`, `connection_frame_wire.rs:30` (`CONNECTION_FRAME_VERSION`).

### CONN-13 — A transport format is kept while a still-usable release speaks it (frame_small projector live at current ceiling)  `projector-unit`
- **Setup:** Ceiling activates the carriers used by every still-usable release. The `frame_small` (168) projector is registered in `FACT_ROUTES`.
- **Action:** Project a valid in-version `frame_small` frame fact through `RouterProjector` (route present, `intro_version <= ceiling`).
- **Expect:** `RouterProjector::project` finds the `frame_small` route, the carrier opens and the projector emits recovered inner fact bytes — i.e. the format is retained and active because at least one still-usable release speaks it. No "no target projector registered" error.
- **Defends:** (5) old transport formats kept while a still-usable release speaks them; (1) VISIBILITY.
- **Refs:** `core/projectors.rs` (`RouterProjector::project`, `FactRoute`:402), `registry.rs` `FACT_ROUTES`, `connection::frame_small` tag 168.

### CONN-14 — A transport format is dropped once SUB-FLOOR: deactivated when no still-usable release speaks it  `guardrail`
- **Setup:** A hypothetical retired carrier tag (model a `frame_small_v1` superseded by `frame_small_v2` once every still-usable release ships v2 and v1 is below the floor). The route's `intro_version` is below the floor / its speaking release expired.
- **Action:** Check the ceiling-filtered router: only routes whose `intro_version <= ceiling` AND whose format is still spoken by a still-usable release are active.
- **Expect:** Once the v1 carrier is sub-floor (no still-usable release speaks it, all such releases past `expires_at + M`), it is no longer offered as a SEND target (sender will not negotiate down to it) — but its READER projector is kept forever for replay. Dropping is by no-longer-selecting the format for transmit, not by deleting the projector.
- **Defends:** (5) transport dropped sub-floor BUT readers kept forever; (4) REPLAY DETERMINISM.
- **Refs:** ceiling-filtered `RouterProjector` (`registry.rs` `FACT_ROUTES`), model: `ReleaseManifestEntry.expires_at`/skew-margin M; `connection_frame_wire.rs` (carrier selection `frame_size_class_for_facts`).

### CONN-15 — An UNSAFE transport format is dropped EARLY via security-deprecation, before natural expiry  `guardrail`
- **Setup:** A carrier/sealed format flagged security-deprecated (model: a release marked security-deprecated so its `supported_protocol.end()` no longer counts toward ceiling even though `trusted_time < expires_at`).
- **Action:** Recompute ceiling = min over still-usable (NOT security-deprecated, not expired) releases.
- **Expect:** The unsafe format's carrier is removed from the active SEND set immediately (does not wait for `expires_at + M`); a peer presenting only that unsafe sealed shape is OUT (its request fails the in-floor recognizer just like CONN-06). Removal-before-expiry happens ONLY because it is unsafe.
- **Defends:** (6) SAFETY FLOOR (removed before natural expiry only when unsafe); (5).
- **Refs:** model `ReleaseManifestEntry` security-deprecation -> ceiling recompute; `bootstrap_request/layout.rs` recognizer (`validate_sealed_connection_request_frame`), `connection_frame_wire.rs` version/size-class gates.

### CONN-16 — A safe-but-old in-floor carrier is NOT dropped early (no premature retirement)  `guardrail`
- **Setup:** An in-floor carrier (e.g. `frame_small` tag 168) whose oldest speaking release is past `warn_after` but NOT past `expires_at + M` and NOT security-deprecated.
- **Action:** Recompute ceiling and the active send set at `trusted_time` within the skew window.
- **Expect:** The carrier remains active for both send and receive; it is NOT removed merely for being old. Removal requires expiry+M or an unsafe flag. (Contrast with CONN-15.)
- **Defends:** (6) SAFETY FLOOR; (5) transport kept in `[floor,head]` while still-usable.
- **Refs:** model `ReleaseManifestEntry.warn_after` vs `expires_at`, skew margin M; `connection::frame_small` tag 168.

### CONN-17 — Ceiling does not advance until trusted_time exceeds blocker.expires_at + M (skew-gated transport upgrade)  `guardrail`
- **Setup:** A blocking release (lowest `supported_protocol.end()`) with `expires_at = T`. A newer frame carrier tag would become ceiling-active only when the blocker drops out. `trusted_time` = monotonic max of signed observations.
- **Action:** Advance `trusted_time` to `T + M/2` (inside the skew margin), then attempt to negotiate the newer carrier.
- **Expect:** Ceiling stays at the old value (blocker still counts); the newer carrier is NOT yet selected for transmit. Only at `trusted_time > T + M` does the carrier go ceiling-active. Prevents a clock-skewed node from retiring a peer too early.
- **Defends:** TRUSTED TIME + skew margin M gating ceiling advance; (3) CEILING MONOTONICITY.
- **Refs:** model TRUSTED TIME / M; ceiling-filtered router (`registry.rs` `FACT_ROUTES`).

### CONN-18 — BLOCKED MODE: stale trusted-time or clock rollback withholds the negotiated-up carrier but keeps local reads/replay  `guardrail`
- **Setup:** A node whose trusted-time refresh is older than staleness window S (or trusted_time rolled back beyond tolerance). It otherwise would speak a higher carrier.
- **Action:** Trigger an established `send_facts_on_connection` and a local `con messages` read and a wipe+replay.
- **Expect:** Shared production (outbound frames at the would-be-higher carrier) is WITHHELD — the node falls back to / refuses to advance the ceiling; but `con messages` (local read) and wipe+replay both still run. Blocked mode does not block local reads or replay.
- **Defends:** BLOCKED MODE (staleness S / rollback -> withhold shared production, keep local reads + replay); (4) REPLAY DETERMINISM under blocked mode.
- **Refs:** model staleness window S / rollback tolerance; `connection/send_facts_on_connection.rs`; replay path.

### CONN-19 — Pre-upgrade connection_response is RETIRED via connection::close before replay  `blackbox-cli`
- **Setup:** An established connection: local `connection::response` (tag 44), initiator + responder `ephemeral_secret` facts (tag 43), `connection_response_rows` populated, sync index live-tailing this session.
- **Action:** Create a `connection::close` (tag 45) fact naming the response fact id (`close { connection_id, closed_at_ms }`).
- **Expect:** The close projector offers `connection_closed` (for the response) and `connection_ephemeral_secret_closed` (for both ephemeral ids); the response projector and ephemeral_secret projectors consume that context and DELETE their rows and PURGE their fact bytes. The connection is retired so a subsequent rebuilt sync index will not live-tail it.
- **Defends:** RETIRE CONNECTIONS before replay (upgrade-retirement); (4) REPLAY DETERMINISM (clean pre-replay state).
- **Refs:** `connection/close.rs` (`connection_closed_offer`, `ephemeral_secret_closed_offer`), `connection/close/project.rs`, `connection::response` (tag 44) & `ephemeral_secret` (tag 43) projectors, README "Close is also target-owned".

### CONN-20 — After close+wipe+replay, the rebuilt sync index does NOT live-tail the retired session  `replay-cli`
- **Setup:** From CONN-19's post-close state (response row + ephemeral facts deleted/purged, a `connection::close` fact retained). Then wipe + replay.
- **Action:** Run a wipe+replay pass; afterward inspect `sync-status` and connection rows.
- **Expect:** Replay reconstructs derived state from RETAINED facts only; the purged response/ephemeral bytes are gone, so no `connection_response_rows` row reappears for the retired session and the rebuilt sync index has nothing to tail for it. The `connection::close` fact replays via its own tag-45 historical adapter deterministically. No phantom live connection.
- **Defends:** (4) REPLAY DETERMINISM (ceiling-independent, replays via each fact's own tag); RETIRE-before-replay correctness.
- **Refs:** `connection/close.rs`, `core/projectors.rs` (`RouterProjector` keyed by tag), `sync::compare`/`sync-status` (`sync::shared_fact::cli`), wipe+replay path.

### CONN-21 — Retiring the response purges both ephemeral_secret facts (handshake secret hygiene before upgrade)  `projector-unit`
- **Setup:** A `connection::response` (tag 44) referencing initiator `ephemeral_secret` id E1 and responder id E2, both present as local tag-43 facts. A `connection::close` (tag 45) names the response.
- **Action:** Project the close fact, then re-project E1 and E2 with the `connection_ephemeral_secret_closed` context now offered.
- **Expect:** The `ephemeral_secret` projector, seeing `connection_ephemeral_secret_closed` keyed by its own id, deletes its row and purges its bytes for BOTH E1 and E2 (close offers the role for both secrets named by the response). Neither ephemeral secret survives into the post-upgrade replay.
- **Defends:** RETIRE-before-replay; (6) SAFETY FLOOR (secret hygiene); (4).
- **Refs:** `connection/close.rs:33-39` (`ephemeral_secret_closed_need/offer`), `connection/ephemeral_secret.rs` projector, README `ephemeral_secret` "deletes/purges itself when close context names it".

### CONN-22 — connection::close requires local scope + connection_response context (a forged/global close cannot retire a session)  `projector-unit`
- **Setup:** A `connection::close` fact submitted with `FactScope::Global` (or with no matching `connection_response` context for its named connection id).
- **Action:** Project it.
- **Expect:** Projection does NOT offer `connection_closed` (close requires local scope + `connection_response` context per README "Projection requires local scope and `connection_response` context"); the targeted response is NOT retired. Retirement is gated, so a peer cannot remotely tear down a session by injecting a close.
- **Defends:** (6) SAFETY FLOOR (retirement authority is local + context-gated); RETIRE-before-replay integrity.
- **Refs:** `connection/close.rs` (`exact_local_need`/`exact_local_offer` use `FactScope::Local`), `connection/close/project.rs`, README close section :189-201.

### CONN-23 — Local creation of an above-ceiling frame carrier is REFUSED at send time  `handler-unit`
- **Setup:** A node whose head supports a future carrier tag whose `intro_version > ceiling` (not yet ceiling-active because a still-usable release cannot transport it).
- **Action:** Attempt `send_facts_on_connection` selecting that future carrier (or selecting a batch that would only fit a not-yet-active carrier shape).
- **Expect:** The send is refused / falls back to an in-floor carrier — an above-ceiling fact/carrier is never locally produced for transmit (admission refuses local creation of above-ceiling facts). The peer never receives an above-ceiling frame.
- **Defends:** ADMISSION (local creation of above-ceiling fact refused); (1) VISIBILITY; (3) CEILING MONOTONICITY.
- **Refs:** model ADMISSION; `connection/send_facts_on_connection.rs` (`frame_size_class_for_facts` only yields the three active classes), ceiling-filtered router.

### CONN-24 — A still-usable older peer that lacks a newer carrier is answered at the carrier IT can transport (negotiate down for transmit)  `multinode-network`
- **Setup:** Two daemons: A at a higher head, B a still-usable older release whose `supported_protocol` does not include the `frame_bundle` (170) capability (model B as ceiling-blocking). The fleet ceiling is therefore below bundle activation.
- **Action:** A selects facts for B that would otherwise prefer bundle; drive `send_facts_on_connection`.
- **Expect:** Because the ceiling (min over still-usable releases including B) does not activate bundle, A negotiates DOWN to a carrier B can transport (`frame_small`, splitting into multiple small frames if needed) rather than shipping a frame B cannot open. B opens every frame and surfaces all facts.
- **Defends:** (1) VISIBILITY (ceiling-active fact transportable by EVERY still-usable release); (3) CEILING MONOTONICITY; TRANSPORT negotiate to the common floor for a still-usable older peer.
- **Refs:** model ceiling = min over still-usable releases; `connection/send_facts_on_connection.rs` (`fact_batches` small-frame splitting :376-379), `connection::frame_small` 168.

### CONN-25 — Idempotent floor bootstrap: duplicate send_bootstrap intents for the same target collapse (no double-handshake during retry)  `handler-unit`
- **Setup:** A pending floor-version bootstrap to peer addr X. The request projector's retry time wake re-emits `send_bootstrap_connection_request` with the same `(request_id, initiator_ephemeral_secret_id, addr)`.
- **Action:** Submit the intent twice with identical inputs.
- **Expect:** Both produce the same idempotence key (`send_bootstrap_connection_request_key` = blake3 over request_id + ephemeral id + addr string), so duplicate attempts are idempotent for the same bootstrap target; at most one sealed `[46,1,...]` frame's worth of work per distinct target+ephemeral. Retry at the floor does not fork the handshake.
- **Defends:** TRANSPORT floor-bootstrap retry stability; (5) deterministic transport.
- **Refs:** `connection/send_bootstrap_request.rs:131-138` (`send_bootstrap_connection_request_key`), header doc "intent key is `(request_id, initiator_ephemeral_secret_id, addr)`".

### CONN-26 — Truncated / wrong-length sealed bootstrap frame is OUT (length-floor guard, not a recovery path)  `handler-unit`
- **Setup:** A sealed bootstrap-request frame whose length `!= SEALED_CONNECTION_REQUEST_BYTES` (e.g. a legacy shorter frame from a long-retired build), even if `frame[0]==46, frame[1]==1`.
- **Action:** Submit via `receive_network_frame` -> `received_bootstrap_request_frame_effect` -> `validate_sealed_connection_request_frame`.
- **Expect:** Validation errs `"sealed connection request has wrong length"` (`frame.len()` mismatch checked before the header bytes); frame dropped, no request fact, no response. A wrong-shape legacy peer is OUT with no recovery responder.
- **Defends:** (5) sub-floor/legacy peer OUT; (6) SAFETY FLOOR.
- **Refs:** `bootstrap_request/layout.rs:84-92` (length check precedes byte check), `connection/receive_network_frame.rs`.

### CONN-27 — Empty TCP frame is a heartbeat, never a transport-version input (core stream layer, not a fact)  `handler-unit`
- **Setup:** An open connection where the peer writes a zero-length length-prefixed frame.
- **Action:** Core `read_frame` returns the empty frame; daemon does NOT turn it into a `receive_network_frame` protocol intent.
- **Expect:** The empty frame is treated as a TCP heartbeat (core/network), not protocol input; no classification, no version check, no fact. Confirms the only non-fact layer (TCP framing + heartbeat) sits below the versioned transport facts and never participates in negotiation.
- **Defends:** SUBSTANCE (only non-fact layer = core TCP framing/heartbeat); (5).
- **Refs:** `core/network.rs:678` test `empty_frame_is_tcp_heartbeat_not_protocol_input`, `read_frame`:577.

### CONN-28 — Pending above-ceiling established frame ACTIVATES on the next wipe+replay after the ceiling rises  `replay-cli`
- **Setup:** A node received (CONN-09-style) a frame with a future carrier/size-class it could not classify; it retained the opaque local-receive bytes. Later a fleet manifest update raises the ceiling to activate that carrier tag (the relevant release drops out / a release adds support).
- **Action:** Wipe + replay after the ceiling rises (and after the new carrier projector/route is active).
- **Expect:** On replay the previously-uncounted frame is now projected via its (now-active) tag's projector, emitting its child facts + receipts; the connection content surfaces. Pending transport facts activate on wipe+replay once the ceiling covers their tag — they were retained, not dropped.
- **Defends:** ADMISSION (pending -> activate on replay); (4) REPLAY DETERMINISM; (1) eventual VISIBILITY.
- **Refs:** model ADMISSION/pending; `core/projectors.rs` (`RouterProjector::project` per-tag), ceiling-filtered `FACT_ROUTES`, wipe+replay path.
## 11. Container frame facts, TRNS magic, sealed bootstrap, chunking

Cluster scope: the connection-frame **container fact** pipeline. A received TCP
frame becomes a local-scope `receive_network_frame` intent; its handler
(`ReceiveNetworkFrameHandler::handle`, `connection/receive_network_frame.rs`)
either (a) stages a sealed bootstrap request/response fact, or (b) classifies the
TRNS frame into one of three size classes and emits a `frame_*` container fact
plus a `frame_observation`. The container fact's projector
(`connection_frame::project_observed_frame`) decrypts via the key hint
(`connection_id` from header + `connection_response` secret + derived `nonce`) and
EMITS the inner content/auth/sync facts plus per-fact `connection::fact_receipt`.
Real entities throughout: `connection_frame_wire.rs` (TRNS magic, AEAD AAD, size
classes, inner bundle), `connection_frame.rs` (classify/open/admit),
`connection/frame_small|frame_file_slice|frame_bundle|frame_observation`,
`connection/bootstrap_request` (sealed 46 / fact 171), `core/network.rs`
(length-prefix + heartbeat), `send_facts_on_connection.rs::fact_batches`
(chunk-don't-grow). The versioning model: each frame container shape is its own
fact tag (168/169/170) with its own kept-forever projector; an incompatible new
frame shape would be a NEW tag + NEW projector, never an internal version bump on
a routed fact. The TRNS 4-byte tag and `CONNECTION_FRAME_VERSION:u8=1` are the
socket/stream recognizer only, NOT a routed-fact version byte.

### FRAME-01 — TRNS small frame round-trips to inner content fact via key hint  `projector-unit`
- **Setup:** A local `connection::response` fact (the established connection,
  scope Local) with a known `connection_secret`, matching `from_endpoint`/
  `to_endpoint`, plus the small frame's `connection::frame_observation` context.
  Seal one `content::message` (tag 50) with `seal_connection_send_frame` so it
  lands in the SMALL size class (packed_len <= `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES`).
- **Action:** Build the `connection::frame_small` fact via
  `frame_small::create::fact_from_wire(frame, ts)` and run
  `ConnectionFrameSmallProjector::project` with a `ProjectionContext` carrying the
  observation + connection_response matches.
- **Expect:** Output contains the decrypted inner `content::message` fact (bytes
  byte-for-byte equal to the sealed message) plus a `connection::fact_receipt`
  with `receive_path == RECEIVE_PATH_CONNECTION_FRAME`. No `need`s remain.
- **Defends:** Container-fact-emits-inner mechanism; invariant (1) transportable/
  projectable by the receiver.
- **Refs:** `connection_frame.rs::project_observed_frame`/`open_received_frame`,
  `connection_frame_wire.rs::open_connection_frame`, `frame_small/project.rs`.

### FRAME-02 — Small size class selected for sub-4KiB single fact  `projector-unit`
- **Setup:** A single sendable fact whose packed inner length
  (`INNER_BUNDLE_HEADER_BYTES + INNER_FACT_LEN_BYTES + fact_len`) is
  `<= CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` (4096), e.g. one `content::message`.
- **Action:** Call `seal_connection_send_frame` and `peek_frame_header` on the
  produced bytes.
- **Expect:** `header.size_class == CONNECTION_FRAME_SIZE_CLASS_SMALL (0)`; outer
  length `== CONNECTION_FRAME_SMALL_WIRE_BYTES`; `classify_frame` returns
  `Some(Small)`.
- **Defends:** Size-class selection (`frame_size_class_for_facts`, small branch).
- **Refs:** `connection_frame_wire.rs::frame_size_class_for_facts`,
  `peek_frame_header`, `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES`.

### FRAME-03 — File-slice size class selected for exactly one CONTENT_FILE_SLICE fact  `projector-unit`
- **Setup:** A `ConnectionFrameFactBundle` of exactly ONE fact whose length is
  exactly `content::file_slice::layout::CONTENT_FILE_SLICE_BYTES`.
- **Action:** `seal_connection_send_frame` then `peek_frame_header`.
- **Expect:** `header.size_class == CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE (1)`;
  outer length `== CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES`; `classify_frame`
  returns `Some(FileSlice)`. (Note: a file_slice is larger than SMALL so it does
  not fall into the small branch.)
- **Defends:** Size-class selection (`frame_size_class_for_facts`, file_slice
  branch keyed on `facts.len()==1 && fact.len()==CONTENT_FILE_SLICE_BYTES`).
- **Refs:** `connection_frame_wire.rs` file_slice branch, `frame_file_slice`.

### FRAME-04 — Bundle size class selected for many sub-slot facts  `projector-unit`
- **Setup:** A bundle of N facts (2 <= N <= `CONNECTION_FRAME_BUNDLE_FACT_SLOTS`),
  each `<= CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES`, total packed length exceeding
  the 4KiB small budget but fitting `CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES`
  (< 64 KiB).
- **Action:** `seal_connection_send_frame` then `peek_frame_header`.
- **Expect:** `header.size_class == CONNECTION_FRAME_SIZE_CLASS_BUNDLE (2)`; outer
  length `== CONNECTION_FRAME_BUNDLE_WIRE_BYTES`; `classify_frame` returns
  `Some(Bundle)`; decrypted plaintext length `== CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES`.
- **Defends:** Size-class selection (bundle branch); the three classes select
  correctly and disjointly.
- **Refs:** `connection_frame_wire.rs::frame_size_class_for_facts` bundle branch,
  `CONNECTION_FRAME_BUNDLE_FACT_SLOTS`, `frame_bundle`.

### FRAME-05 — Bundle frame opens to all inner facts in order with one receipt each  `projector-unit`
- **Setup:** Local `connection::response` + `frame_observation` context as in
  FRAME-01; a BUNDLE frame sealing K distinct facts (mixed
  `content::reaction`, `content::message_deletion`, `auth::user`).
- **Action:** Run `ConnectionFrameBundleProjector::project` with full context.
- **Expect:** Output emits exactly 2*K facts: K admitted inner facts (each via its
  own `admit_received_fact_bytes` codec, correct scope) and K
  `connection::fact_receipt` facts. Inner fact order preserved (bundle iteration
  order from `decode_fixed_slot_inner_bundle`).
- **Defends:** Container projector emits ALL inner facts; invariant (1).
- **Refs:** `connection_frame.rs::open_received_frame`/`admit_received_fact_bytes`,
  `connection_frame_wire.rs::decode_fixed_slot_inner_bundle`, `frame_bundle/project.rs`.

### FRAME-06 — AAD binds size_class+connection_id+nonce: tampered size-class byte fails AEAD  `projector-unit`
- **Setup:** A valid sealed SMALL frame and its `connection_secret`.
- **Action:** Flip the `SIZE_CLASS_OFFSET` byte (offset 5) to BUNDLE (2) and the
  outer length is now wrong for bundle, OR re-pad to bundle wire length keeping the
  small ciphertext; then call `open_connection_frame` with the original secret.
- **Expect:** Open fails. If the length/slot mismatch is caught first, it errors at
  the wire-length / ciphertext-slot check; if reframed to a valid bundle shape, the
  AEAD decrypt fails because `frame_associated_data` includes `size_class` —
  `xchacha20poly1305_decrypt` returns an auth error. Either way no inner facts are
  emitted.
- **Defends:** "AEAD associated data binds tag+version+size_class+connection_id+
  nonce" — tag/version are implied by the TRNS+VERSION header gate, size_class is
  inside the AAD.
- **Refs:** `connection_frame_wire.rs::frame_associated_data` (line 706),
  `open_connection_frame`, `decode_frame_parts`.

### FRAME-07 — AAD binds connection_id: tampered header connection_id fails AEAD  `projector-unit`
- **Setup:** A valid sealed frame for connection C, secret S.
- **Action:** Overwrite the header `CONNECTION_OFFSET..NONCE_OFFSET` (32 bytes)
  with a different id, leave ciphertext intact, call `open_connection_frame(_, &S)`.
- **Expect:** AEAD decrypt fails (connection_id is in the AAD via
  `frame_associated_data`). `project_observed_frame` swallows the open error and
  emits NO durable facts (`Err(_) => Ok(ProjectionOutput::new())`).
- **Defends:** AAD binds connection_id; key-hint integrity.
- **Refs:** `connection_frame.rs::project_observed_frame` (Err arm),
  `frame_associated_data`, `open_connection_frame`.

### FRAME-08 — AAD binds nonce: tampered header nonce fails AEAD  `projector-unit`
- **Setup:** A valid sealed frame, secret S.
- **Action:** Overwrite the header `NONCE_OFFSET..CIPHERTEXT_OFFSET` (24 bytes)
  with a different nonce, call `open_connection_frame`.
- **Expect:** Decrypt fails — `frame_associated_data` includes the nonce AND the
  nonce is the AEAD nonce, so a mismatch breaks both. No inner facts emitted.
- **Defends:** AAD/key-hint binds nonce; nonce derivation integrity.
- **Refs:** `frame_associated_data`, `connection_send_nonce`, `open_connection_frame`.

### FRAME-09 — TRNS magic rejects garbage stream pre-routing (handler drops, no fact)  `handler-unit`
- **Setup:** A `receive_network_frame` intent whose `frame` is 200 bytes of
  random non-protocol data (frame[0] != 46, != 47, and bytes are not a TRNS
  header — `peek_frame_header` would return `WireError::NonZeroPadding{index:0}`).
- **Action:** `ReceiveNetworkFrameHandler::handle` on that intent.
- **Expect:** `is_bootstrap_request_frame` false, `is_bootstrap_response_frame`
  false, `classify_frame` returns `None` -> handler returns an EMPTY
  `PipelineEffects`. No `frame_*` fact, no observation, no fact routing at all.
- **Defends:** "TRNS 4-byte magic rejects a garbage/non-protocol stream before any
  fact routing" — the stream recognizer is the size-class/`decode_frame_parts`
  gate, not a routed-fact path.
- **Refs:** `receive_network_frame.rs::handle` (None arm),
  `connection_frame.rs::classify_frame`, `connection_frame_wire.rs::peek_frame_header`.

### FRAME-10 — TRNS magic guard: correct length but wrong 4-byte tag classifies as None  `projector-unit`
- **Setup:** A buffer exactly `CONNECTION_FRAME_SMALL_WIRE_BYTES` long whose first
  4 bytes are `b"XXXX"` instead of `b"TRNS"`, version byte = 1, size_class = 0.
- **Action:** Call `classify_frame` / `peek_frame_header` on it.
- **Expect:** `peek_frame_header` returns `Err(WireError::NonZeroPadding{index:0})`
  (the tag != `CONNECTION_FRAME_TAG`); `classify_frame` returns `None`. Frame is
  not recognized as protocol input.
- **Defends:** TRNS magic is a hard stream recognizer independent of size class.
- **Refs:** `connection_frame_wire.rs::peek_frame_header` tag check (line ~297),
  `CONNECTION_FRAME_TAG = fixed_tag(b"TRNS")`.

### FRAME-11 — Frame VERSION byte mismatch rejected (socket recognizer, not routed-fact version)  `projector-unit`
- **Setup:** A well-formed TRNS small frame but with the VERSION byte at offset 4
  set to 2 (not `CONNECTION_FRAME_VERSION = 1`).
- **Action:** `peek_frame_header` and `classify_frame`.
- **Expect:** `peek_frame_header` returns `Err(WireError::InvalidBool{actual:2})`;
  `classify_frame` returns `None`. The frame is rejected at the stream-recognizer
  level — there is NO `_v2` routing, because the frame VERSION byte is part of the
  TRNS recognizer, not a routed-fact version knob.
- **Defends:** Confirms the versioning model: an incompatible frame shape becomes a
  NEW fact tag (168->new tag), NOT an internal version-byte bump. The version byte
  here is purely the stream recognizer.
- **Refs:** `connection_frame_wire.rs::peek_frame_header` version check (~301),
  `CONNECTION_FRAME_VERSION`.

### FRAME-12 — Empty TCP frame is a heartbeat, not protocol input  `handler-unit`
- **Setup:** A listening `core::network::Listener`; a peer that calls
  `write_frame_with_budget(stream, b"", ...)` (zero-length body, valid 4-byte
  length prefix = 0) then shuts down.
- **Action:** `Listener::accept_available(&store, 1)`.
- **Expect:** `report.accepted_connections == 1`, `report.value.received_frames == 0`,
  `claim_inbound(&store, 10).len() == 0`. The empty frame is dropped in
  `read_inbound_frames` (`if bytes.is_empty() { continue; }`), never becomes a
  `receive_network_frame` intent.
- **Defends:** "An empty TCP frame is a heartbeat not protocol input." Confirms the
  only non-fact layer is the length-prefix + heartbeat in `core/network.rs`.
- **Refs:** `core/network.rs::read_inbound_frames` (empty continue), existing test
  `empty_frame_is_tcp_heartbeat_not_protocol_input` (line 678).

### FRAME-13 — Sealed bootstrap request at unsupported VERSION byte rejected cleanly pre-session  `handler-unit`
- **Setup:** A sealed-request frame of length `SEALED_CONNECTION_REQUEST_BYTES`
  with `frame[0] == TYPE_SEALED_CONNECTION_REQUEST (46)` but `frame[1] == 2`
  (unsupported, valid VERSION is 1). No established connection exists.
- **Action:** Feed it through `received_bootstrap_request_frame_effect` (or
  `ReceiveNetworkFrameHandler::handle`).
- **Expect:** `is_bootstrap_request_frame` is true (frame[0]==46), but
  `copy_sealed_connection_request_frame` -> `validate_sealed_connection_request_frame`
  fails the `frame[1] == VERSION` check ("sealed connection request has unsupported
  header"). The `Ok(None)`/`Err` path yields an EMPTY `PipelineEffects`: no
  bootstrap_request fact (171) is staged, no error propagates to the socket. Clean
  rejection pre-session.
- **Defends:** "A sealed bootstrap request at an unsupported VERSION byte rejected
  cleanly pre-session"; invariant (5) transport floor — old/unknown sealed versions
  are not honored.
- **Refs:** `bootstrap_request/layout.rs::validate_sealed_connection_request_frame`
  (`frame[1] != VERSION`), `bootstrap_request/create.rs`, `receive_network_frame.rs`.

### FRAME-14 — Sealed bootstrap request wrong tag byte (not 46) is not treated as bootstrap  `handler-unit`
- **Setup:** A frame with `frame[0] == 47` (`TYPE_SEALED_CONNECTION_RESPONSE`) of
  request length, then a frame with `frame[0] == 99` (garbage).
- **Action:** `is_bootstrap_request_frame` and the receive handler for each.
- **Expect:** For frame[0]==47: `is_bootstrap_request_frame` false but
  `is_bootstrap_response_frame` true -> response path; for frame[0]==99: both
  false, `classify_frame` None -> empty effects. Confirms the first-byte tag (46
  vs 47 vs TRNS) routes the sealed envelope correctly.
- **Defends:** Sealed-envelope tag discrimination (46 request / 47 response are
  NOT in FACT_ROUTES; they are the first byte of the sealed frame).
- **Refs:** `bootstrap_request/create.rs::is_bootstrap_request_frame`,
  `bootstrap_response/create.rs::is_bootstrap_response_frame`, inventory section 4.

### FRAME-15 — bootstrap_request fact (171) wraps the sealed frame for the pipeline  `projector-unit`
- **Setup:** A valid sealed-request frame (frame[0]==46, frame[1]==1) and a peer
  origin address + receive timestamp.
- **Action:** Call `received_bootstrap_request_frame_effect(frame, origin, ts)`.
- **Expect:** Returns `Some(PipelineEffects)` containing one EPHEMERAL local fact
  whose first byte is `TYPE_CONNECTION_BOOTSTRAP_REQUEST (171)`, encoded by
  `bootstrap_request::layout::encode_fact`: tag(171) + u64be received_at +
  OriginAddr slot + the sealed frame. `decode_fact` round-trips it back to the
  same `ConnectionBootstrapRequestFact`.
- **Defends:** "bootstrap_request fact (171) wraps the sealed frame for the
  pipeline." The durable/local fact 171 is the routed pipeline entry; 46 is the
  wire byte it carries.
- **Refs:** `bootstrap_request/create.rs::received_bootstrap_request_frame_effect`,
  `bootstrap_request/layout.rs::{encode_fact,decode_fact}`, registry route 595.

### FRAME-16 — bootstrap_request fact 171 projects to durable connection_request + receipt  `projector-unit`
- **Setup:** A bootstrap_request fact (171) wrapping a valid sealed request
  addressed to the local daemon endpoint; `ProjectionContext` carrying the daemon
  endpoint via `endpoint::daemon_endpoint_need`.
- **Action:** `ConnectionBootstrapRequestProjector::project`.
- **Expect:** Output emits exactly 2 facts — the canonical `connection::request`
  (global) with bytes equal to the opened request, plus a `connection::fact_receipt`
  whose `receive_path == RECEIVE_PATH_CONNECTION_REQUEST`. No needs/offers/intents.
  (Mirrors existing test `sealed_request_projects_to_request_and_receipt_facts`.)
- **Defends:** Sealed bootstrap fact is the receive-side bridge to the durable
  handshake; invariant (1)/(2) the request fact is reproduced identically.
- **Refs:** `bootstrap_request/project.rs`, `connection_frame.rs::received_connection_request_fact_effect`,
  `bootstrap_request/layout.rs::open_connection_request`.

### FRAME-17 — bootstrap_request fact projects with no durable output when endpoint context absent  `projector-unit`
- **Setup:** Same bootstrap_request fact but an EMPTY `ProjectionContext` (no
  daemon endpoint match available in the fixed-point pass).
- **Action:** `ConnectionBootstrapRequestProjector::project`.
- **Expect:** Output has a single `need` for `endpoint::daemon_endpoint_need(fact.id)`
  and NO durable facts (the projector returns `ProjectionOutput::new().need(...)`).
- **Defends:** Replay determinism / context-gated materialization (invariant 4) —
  no durable fact created without context.
- **Refs:** `bootstrap_request/project.rs` step 2 (Context), `endpoint::daemon_endpoint_need`.

### FRAME-18 — bootstrap_request frame addressed to another endpoint yields no request fact  `projector-unit`
- **Setup:** A sealed request whose inner `to_endpoint` is a DIFFERENT endpoint;
  `ProjectionContext` carries the local daemon endpoint.
- **Action:** Project the wrapping bootstrap_request fact (171).
- **Expect:** `open_connection_request` returns `Err` ("addressed to another
  endpoint"); the projector's `let Ok(request_bytes) = ... else` branch returns
  `ProjectionOutput::new()` with no durable facts. Clean, undisplayed.
- **Defends:** Pre-session admission safety — undecryptable/misaddressed sealed
  frames produce no output; invariant (5)/(6).
- **Refs:** `bootstrap_request/layout.rs::open_connection_request` (to_endpoint
  check), `bootstrap_request/project.rs` (Ok-else arm).

### FRAME-19 — Large new content fact rides existing frames via file_slice chunking, not a grown frame  `handler-unit`
- **Setup:** `send_facts_on_connection` handler with a connection and a payload
  list containing one `content::file` plus several `content::file_slice` facts
  (each exactly `CONTENT_FILE_SLICE_BYTES`) representing a large file.
- **Action:** Invoke the batcher `fact_batches(facts)`.
- **Expect:** Each file_slice fact is emitted as its OWN single-fact batch (the
  `fact_len == CONTENT_FILE_SLICE_BYTES` branch flushes the running batch and
  pushes `vec![fact]`), which seals to a FILE_SLICE size-class frame. No frame is
  enlarged beyond the three fixed size classes; the large content is carried by
  chunking into multiple `frame_file_slice` (169) frames.
- **Defends:** "Carrier capacity GATES ceiling activation (chunk-don't-grow; the
  file_slice precedent)." A big fact does not grow the frame; it chunks.
- **Refs:** `send_facts_on_connection.rs::fact_batches` (file_slice branch, lines
  362-368), `frame_file_slice`, `CONTENT_FILE_SLICE_BYTES`.

### FRAME-20 — Oversize non-slice fact is REFUSED by the batcher (chunk-don't-grow guard)  `handler-unit`
- **Setup:** `send_facts_on_connection` with a single non-file-slice fact whose
  body length exceeds `CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES`
  (= `file::layout::CONTENT_FILE_BYTES`) and is not exactly
  `CONTENT_FILE_SLICE_BYTES`.
- **Action:** `fact_batches(facts)`.
- **Expect:** `Err("send_facts_on_connection fact exceeds connection frame bundle
  slot")`. The system refuses to grow a frame for an oversize fact — it must be
  modeled as a chunked/file_slice family instead.
- **Defends:** "chunk, do not grow the frame"; invariant (1) — a fact must be
  transportable within an existing carrier shape or it cannot ride.
- **Refs:** `send_facts_on_connection.rs::fact_batches` (line 370 oversize check),
  `CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES`.

### FRAME-21 — Bundle batch caps at CONNECTION_FRAME_BUNDLE_FACT_SLOTS (rolls to a new frame)  `handler-unit`
- **Setup:** `send_facts_on_connection` with `CONNECTION_FRAME_BUNDLE_FACT_SLOTS + 1`
  small sub-slot facts that exceed the small budget collectively.
- **Action:** `fact_batches(facts)`.
- **Expect:** At least 2 batches; the first batch has at most
  `CONNECTION_FRAME_BUNDLE_FACT_SLOTS` facts (the `would_fit_bundle = batch.len() <
  CONNECTION_FRAME_BUNDLE_FACT_SLOTS` gate flushes when full). No single frame
  carries more than `CONNECTION_FRAME_BUNDLE_FACT_SLOTS` facts — capacity gate, not
  frame growth.
- **Defends:** Carrier capacity gate; chunk-don't-grow at the slot-count boundary.
- **Refs:** `send_facts_on_connection.rs::fact_batches` (would_fit_bundle),
  `CONNECTION_FRAME_BUNDLE_FACT_SLOTS`.

### FRAME-22 — Sealed send refuses local/private fact tags as frame payload  `handler-unit`
- **Setup:** A fact list including a `connection::close` (tag 45) or a
  `auth::local_signer_secret` (133), or any local-scope fact.
- **Action:** `frame_policy::require_sendable_fact(&fact)` (called inside batching
  and sealing).
- **Expect:** `Err` — local scope yields "send refused local fact"; a
  private/local tag (per `is_private_local_fact_tag`) yields "send refused
  private/local fact tag N". The frame_* tags (168/169/170/173), receipt (164),
  bootstrap (171/46/172/47), connection request/response/ephemeral/close are all
  refused as inner payload.
- **Defends:** Invariant (1)/(6) — only globally-shareable facts ride a frame;
  container facts never nest inside container facts.
- **Refs:** `connection_frame.rs::require_sendable_fact`, `is_private_local_fact_tag`.

### FRAME-23 — frame_observation references the frame fact id (not the ciphertext)  `projector-unit`
- **Setup:** Receive a TRNS small frame through the handler.
- **Action:** Inspect the emitted `connection::frame_observation` fact (tag 173).
- **Expect:** `observed_frame_effect` emits an observation whose `frame_fact_id`
  equals the ephemeral frame fact's id, plus the ephemeral frame fact itself. The
  observation carries `origin_addr` + `received_at_local_ms` but NO ciphertext
  (layout = tag + frame_fact_id(32) + OriginAddr + u64be).
- **Defends:** Receive-metadata separation; the frame fact is ephemeral, the
  observation is the durable receive record keyed by frame id.
- **Refs:** `connection_frame.rs::observed_frame_effect`,
  `frame_observation/layout.rs` (CONNECTION_FRAME_OBSERVATION_FACT_BYTES).

### FRAME-24 — Frame projector emits nothing if observation context is missing  `projector-unit`
- **Setup:** A `connection::frame_small` fact with a `connection::response`
  context but WITHOUT the `connection_frame_observation` context match.
- **Action:** `ConnectionFrameSmallProjector::project`.
- **Expect:** Output is a single transient `need` for the
  `connection_frame_observation` role and NO durable inner facts. (The projector
  returns `ProjectionOutput::new().need(observation_need)`.)
- **Defends:** Invariant (4) replay determinism — inner facts only materialize once
  both observation + connection context are present in the fixed-point pass.
- **Refs:** `connection_frame.rs::project_observed_frame` (observation_need branch).

### FRAME-25 — Frame projector emits nothing if connection_response context is missing  `projector-unit`
- **Setup:** A `connection::frame_small` fact WITH observation context but WITHOUT
  the `connection_response` (key-hint) context.
- **Action:** Project.
- **Expect:** Output is a single transient `need` for `connection_response` keyed
  by the header `connection_id`, and NO durable facts. The key hint
  (connection_id) drives the context lookup; without the secret, no decrypt.
- **Defends:** Key-hint-driven decryption: connection_id from the cleartext header
  selects the connection secret; missing => no inner facts. Invariant (4).
- **Refs:** `connection_frame.rs::project_observed_frame` (connection_need branch),
  `connection_frame_wire.rs::received_connection_fact_id`.

### FRAME-26 — Frame endpoints must match connection fact (forward or reverse)  `projector-unit`
- **Setup:** Open a frame whose inner-bundle `sender_endpoint_id`/
  `receiver_endpoint_id` do NOT match either direction of the
  `connection::response` endpoints.
- **Action:** `open_received_frame` (via projector).
- **Expect:** `require_connection_endpoints` returns
  `Err("...endpoints do not match connection fact")`; the projector swallows the
  error (`Err(_) => Ok(ProjectionOutput::new())`) -> no durable facts.
- **Defends:** Inner-bundle endpoint binding; frames are bound to the negotiated
  connection's endpoints.
- **Refs:** `connection_frame.rs::require_connection_endpoints`, `open_received_frame`.

### FRAME-27 — Unsupported inner fact tag inside an opened frame aborts admission for that frame  `projector-unit`
- **Setup:** Hand-craft an inner bundle containing a fact whose first byte is a tag
  NOT handled by `admit_received_fact_bytes` (e.g. an unmapped/above-ceiling tag),
  sealed into a valid small frame with valid context.
- **Action:** Project the frame fact.
- **Expect:** `admit_received_fact_bytes` returns
  `Err("unsupported received connection::frame fact type N")`; `open_received_frame`
  propagates Err; the projector's `Err(_) => Ok(ProjectionOutput::new())` arm emits
  NO durable facts for the whole frame.
- **Defends:** Receive-side admission boundary; an unknown inner tag is not routed
  blindly. (Contrast with the durable-pending path: this is the connection-frame
  child admission allowlist, distinct from the router's no-target-projector error.)
- **Refs:** `connection_frame.rs::admit_received_fact_bytes` (default arm, line 470),
  `project_observed_frame` (Err arm).

### FRAME-28 — Inner bundle must contain at least one fact (empty bundle rejected)  `projector-unit`
- **Setup:** Attempt to seal an empty `ConnectionFrameFactBundle`.
- **Action:** `seal_connection_frame` / `inner_bundle_packed_len`.
- **Expect:** `Err("connection::frame inner bundle must contain at least one
  fact")`. On the decode side, a `count == 0` inner header is also rejected in both
  `decode_packed_inner_bundle` and `decode_fixed_slot_inner_bundle`.
- **Defends:** Container framing well-formedness; an empty frame is never a valid
  carrier (distinct from the TCP heartbeat which is the empty TCP frame).
- **Refs:** `connection_frame_wire.rs::inner_bundle_packed_len`,
  `decode_packed_inner_bundle`, `decode_fixed_slot_inner_bundle` (count==0 checks).

### FRAME-29 — Bundle slot nonzero padding is rejected on decode  `projector-unit`
- **Setup:** Encode a valid bundle, then corrupt the padding bytes of a used slot
  (`slot[len..]`) to nonzero, re-encrypt with the same key/nonce/AAD.
- **Action:** `open_connection_frame` -> `decode_fixed_slot_inner_bundle`.
- **Expect:** `Err("connection::frame inner bundle slot has nonzero padding")`
  (used slot) or `Err("...unused bundle slot is nonzero")` (unused slot). No inner
  facts emitted.
- **Defends:** Deterministic fixed-width framing (canonical bytes) — invariant (4)
  replay determinism relies on byte-canonical frames.
- **Refs:** `connection_frame_wire.rs::decode_fixed_slot_inner_bundle` padding checks.

### FRAME-30 — frame fact decode rejects size-class mismatch between fact tag and inner header  `projector-unit`
- **Setup:** Take a valid BUNDLE wire frame (size_class byte = 2) and wrap it with
  the `frame_small` fact tag (168) via `encode_frame_fact(TYPE_CONNECTION_FRAME_SMALL,
  CONNECTION_FRAME_SIZE_CLASS_SMALL, frame)`.
- **Action:** `frame_small::layout::encode_fact` / `decode_fact`.
- **Expect:** `require_frame_size_class` detects `parts.header.size_class (2) !=
  expected_size_class (0)` and returns "connection frame fact size class mismatch:
  expected 0 got 2". The frame_small fact family cannot smuggle a bundle frame.
- **Defends:** Each frame size class is its own fact tag with a matching inner
  size-class byte — the tag IS the version knob; no cross-class smuggling.
- **Refs:** `connection_frame_wire.rs::require_frame_size_class`,
  `encode_frame_fact`/`decode_frame_fact`, `frame_small/layout.rs`.

### FRAME-31 — Each frame container family has a distinct kept-forever route (tag uniqueness)  `guardrail`
- **Setup:** The registry `FACT_ROUTES` and the `fact_route_tags_are_globally_unique`
  test.
- **Action:** Inspect routes for tags 168/169/170/171/172/173 plus the sealed
  envelope tags 46/47.
- **Expect:** `FACT_ROUTES` contains exactly one route each for 168
  (`ConnectionFrameSmallProjector`), 169, 170, 173, 171, 172 — all distinct;
  `fact_route_tags_are_globally_unique` passes. Sealed tags 46/47 are NOT in
  `FACT_ROUTES` (they are sealed wire bytes, not routed facts).
- **Defends:** Versioning knob = the fact tag; a new frame shape => a new tag + new
  projector. Structural guardrail for invariants (4)/(5) (readers forever).
- **Refs:** `registry.rs` FACT_ROUTES (lines 595-596, 630-633),
  `fact_route_tags_are_globally_unique` (717-729), inventory section 1.

### FRAME-32 — End-to-end: peer-sent small frame round-trips a message over the socket  `multinode-network`
- **Setup:** Two `con` daemons A and B with an established connection (completed
  bootstrap handshake -> matched `connection::response` on both). A runs
  `con send` to put a `content::message` on the connection.
- **Action:** Let A's `send_facts_on_connection` -> `send_network_frame` write the
  TRNS frame; B's listener accepts it, queues `receive_network_frame`, projects the
  frame_small fact.
- **Expect:** B's `con messages` shows the message; B has a
  `connection::fact_receipt` with `RECEIVE_PATH_CONNECTION_FRAME`. The frame never
  appears as a durable global fact (frame facts are ephemeral/Local); only the
  inner message + receipt persist.
- **Defends:** Full container-fact pipeline; invariant (1) transportable by a peer
  release; invariant (2) B renders the same row content A intended.
- **Refs:** `send_facts_on_connection.rs`, `send_network_frame.rs`,
  `receive_network_frame.rs`, `frame_small`, `content::message::cli` (`send`/`messages`).

### FRAME-33 — Replay: ephemeral frame facts are not replayed; inner facts replay by own tag  `replay-cli`
- **Setup:** A store that received frames and materialized inner facts (messages,
  reactions). Frame facts are `ephemeral_fact` (Local, non-durable); inner facts
  and receipts are durable.
- **Action:** Wipe derived state and replay all retained facts.
- **Expect:** Replay rebuilds read-models from the durable INNER facts (each via its
  own tag's historical projector) and from `frame_observation` records — it does
  NOT replay the ciphertext frames (they were ephemeral and not retained). Result
  is identical and ceiling-independent.
- **Defends:** Invariant (4) replay determinism + (5) readers-forever — the frame
  container is a transport-time artifact; the retained facts are the inner ones.
- **Refs:** `connection_frame.rs::observed_frame_effect` (`ephemeral_fact`),
  `project_observed_frame`, inventory section 5, `con replay`.
## 12. Sync x versioning

These tests defend that the sync subsystem treats every routed fact as OPAQUE
bytes keyed by id, ships current-ceiling facts when the carrier can carry them,
closes cross-version dependency context (or falls back to have/need rounds when
the envelope cannot), holds above-ceiling facts pending without breaking the
closure of in-range facts, ships old retained facts inside the CURRENT
transport, runs negentropy range/summary over ids across mixed fact versions,
and rebuilds shareable rows + negentropy from retained facts on replay while
suppressing the live-tail. Real entities exercised: `sync::compare` (165),
`sync::have_id` (166), `sync::need_id` (167), `sync::shared_fact` (162),
`sync::range_request` (160); handlers `SendSyncCompareResponseHandler`,
`SendNeededFactIdHandler`, `SendRequestedFactHandler`, `ShareFactWithSyncHandler`,
`SeedConnectionSyncHandler`; intents `send_sync_compare_response`,
`send_needed_fact_id`, `send_requested_fact`, `share_fact_with_sync`,
`seed_connection_sync`, `send_facts_on_connection`. Where the cluster has a
{new version}/{old version} axis or a per-scope axis it is enumerated as
separate tests.

Reference files:
`src/protocol/sync/send_compare_response.rs`,
`src/protocol/sync/send_needed_fact_id.rs`,
`src/protocol/sync/send_requested_fact.rs`,
`src/protocol/sync/share_fact_with_sync.rs`,
`src/protocol/sync/seed_connection.rs`,
`src/protocol/sync/compare/{layout,create}.rs`,
`src/protocol/sync/shared_fact/{rows,project,cli}.rs`,
`src/protocol/connection_frame.rs` (`require_sendable_fact`, `admit_received_fact_bytes`),
`src/core/projectors.rs` (RouterProjector unknown-tag Err@456).

---

### SYNC-01 — shared_fact projector treats owner body as opaque, keys offer by fact id only  `projector-unit`
- **Setup:** In-memory store with `CORE_SCHEMA_SOURCE + FACTS_SCHEMA_SOURCE`. Build a `sync::shared_fact` fact (tag 162) whose `SharedFact { workspace_id, fact_id }` names an owner fact id, where the owner fact body is arbitrary opaque bytes (e.g. a tag the projector has never seen). Owner fact is workspace-scoped to `workspace_id`.
- **Action:** Run `SyncSharedFactProjector::project_typed` (via `project_typed::<Codec,_>`) on the shared_fact fact.
- **Expect:** `ProjectionOutput` carries exactly one `ContextOffer::range(fact.id, "sync_exact_fact", workspace_scope(workspace_id), shared.fact_id, shared.fact_id)`. The projector never decodes nor inspects the owner fact's body; the only validation is `require_fact_scope(fact, &workspace_scope(shared.workspace_id))` (a scope check on the shared_fact itself, not the referenced content).
- **Defends:** Invariant 4 / mechanism: sync carries opaque ids and does not reinterpret content. SUBSTANCE: everything is a fact, but sync routes by tag+id, not by content version.
- **Refs:** `sync/shared_fact/project.rs` `SyncSharedFactProjector`, `ContextOffer::range`, `sync_exact_fact`, `auth::workspace::scope`.

### SYNC-02 — shared_fact projector rejects scope/workspace mismatch but still does not parse content  `projector-unit`
- **Setup:** Same store. Build a `sync::shared_fact` fact whose decoded `SharedFact.workspace_id` is `W1` but whose outer `Fact.scope` is workspace `W2` (mismatch).
- **Action:** Run `SyncSharedFactProjector::project_typed`.
- **Expect:** `Err("sync context fact scope does not match body workspace")` from `require_fact_scope`. Failure is purely structural (outer scope vs body workspace); no attempt to decode the referenced owner fact bytes. Confirms admission of the *index* fact is independent of the *content* fact's version.
- **Defends:** Mechanism: opaque content; structural-only validation in sync.
- **Refs:** `sync/shared_fact/project.rs` `require_fact_scope`.

### SYNC-03 — ShareFactWithSync upsert records a shareable row from current-ceiling content fact  `handler-unit`
- **Setup:** Store seeded as in the existing `share_fact_with_sync_suppresses_live_tail_to_origin_connection` test (endpoint, endpoint_shared, a connection_response row). Owner fact = a `content::message` (tag 50) workspace-scoped to `W`, timestamp `T`. This message tag is CEILING-ACTIVE (intro_version <= ceiling). Provide it via `HandlerContext::with_facts([owner]).with_store`.
- **Action:** Submit `share_fact_with_sync_intent_for_fact(W, owner.id, T, vec![])` to `ShareFactWithSyncHandler::handle`.
- **Expect:** `record_sync_contribution` upserts: a `ShareableFactRow{ workspace_id:W, fact_id:owner.id, timestamp_ms:T }` and a `NegentropyLeafRow` keyed by `(W, owner.id)` with `timestamp_ms=T`. `changed == true`. Handler then queues a `send_facts_on_connection` live-tail intent (since no origin connection excludes it). The row stores only `(workspace_id, fact_id, timestamp_ms)` — no content version byte.
- **Defends:** Invariant 1 (a ceiling-active fact is transportable). Mechanism: a v1 sync envelope carries current-ceiling facts.
- **Refs:** `share_fact_with_sync.rs` `ShareFactWithSyncHandler::handle` upsert branch; `shared_fact/rows.rs` `record_sync_contribution`/`upsert_sync_contribution`, `ShareableFactRow`, `NegentropyLeafRow`.

### SYNC-04 — ShareFactWithSync upsert refuses a local-only owner fact (not transportable)  `handler-unit`
- **Setup:** Store as above but owner fact has `FactScope::Local` (e.g. an `auth::endpoint` / `local_*` secret).
- **Action:** Submit `share_fact_with_sync_intent_for_fact(W, owner.id, T, vec![])`.
- **Expect:** `context.require_non_local_fact_bytes(&owner_fact_id)` returns `HandlerError` ("...local fact..."); handler returns `Err`. No `ShareableFactRow` written. Local facts never enter the sync surface regardless of version.
- **Defends:** Invariant 5 / privacy floor: only non-local facts are shareable.
- **Refs:** `share_fact_with_sync.rs` `context.require_non_local_fact_bytes`; `core/intents.rs:362` `require_non_local_fact_bytes` (`FactScope::Local` check).

### SYNC-05 — dependency closure: a {new version} v2 content fact ships with its {old version} v1 anchor as context_have  `handler-unit`
- **Setup:** Store seeded with a connection. Owner = a hypothetical NEW `content::message:2` fact (tag still 50, new wire shape) workspace-scoped `W` at `T2`; anchor = an `content::message:1` v1 fact at `T1 < T2`, both retained. The owner's projector advertised the v1 anchor as a validated `context_have`.
- **Action:** Submit `share_fact_with_sync_intent_for_fact(W, owner_v2.id, T2, vec![anchor_v1.id])`.
- **Expect:** `upsert_sync_contribution` writes `NegentropyContextHaveRow{ workspace_id:W, owner_fact_id:owner_v2.id, context_fact_id:anchor_v1.id }`. The contribution fingerprint mixes the anchor id. Later `negentropy_context_have_for_leaf(store,W,owner_v2.id)` returns `[anchor_v1.id]`. Cross-version anchor recorded with no version interpretation — both ids are opaque.
- **Defends:** Mechanism: dependency closure includes cross-version context.
- **Refs:** `shared_fact/rows.rs` `upsert_sync_contribution` (`context_have` merge), `NegentropyContextHaveRow`, `negentropy_context_have_for_leaf`.

### SYNC-06 — dependency closure: a {old version} v1 fact's context (also v1) records identically  `handler-unit`
- **Setup:** Same as SYNC-05 but owner = a v1 `content::message:1` fact at `T2` whose context_have = another v1 fact at `T1`.
- **Action:** Submit `share_fact_with_sync_intent_for_fact(W, owner_v1.id, T2, vec![anchor_v1.id])`.
- **Expect:** Identical row shape: `NegentropyContextHaveRow{W, owner_v1.id, anchor_v1.id}`; same fingerprint algorithm (`contribution_fingerprint`). Proves the closure machinery is version-agnostic — old-version and new-version owners use the same code path.
- **Defends:** Invariant 4 (closure recorded the same regardless of fact version); mechanism: closure is over ids.
- **Refs:** `shared_fact/rows.rs` `upsert_sync_contribution`, `contribution_fingerprint`.

### SYNC-07 — compare response expands send list to the cross-version dependency closure  `handler-unit`
- **Setup:** Store with a connection `C`. Shareable index holds owner `O` (v2 content, `T2`) whose `negentropy_context_have` = anchor `A` (v1 content, `T1`), and both `O` and `A` are shareable on `C`. Build an incoming `sync::compare` fact whose summary mismatches so the plan selects `O` via `send_fact_ids`.
- **Action:** Submit the compare to `SendSyncCompareResponseHandler::handle` (store path, so it calls `shareable_facts_for_connection` + `response_plan_with_summaries` + `expand_fact_ids_with_context_for_connection`).
- **Expect:** The emitted `send_facts_on_connection` intent's `fact_ids` contains BOTH `O` and `A` (closure expanded by `expand_fact_ids_with_context_for_connection` over the `[T1,T2]` window with `include_deps=true`). The v1 anchor ships in the same response as the v2 owner.
- **Defends:** Mechanism: a v2 fact ships with its v1 anchor when the envelope can carry it.
- **Refs:** `send_compare_response.rs` `SendSyncCompareResponseHandler::handle`; `shared_fact/rows.rs` `expand_fact_ids_with_context_for_connection` -> `shareable_facts_for_connection_range(...,true)`.

### SYNC-08 — closure falls back to have/need rounds when the carrier cannot bundle the v1 anchor  `multinode-network`
- **Setup:** Two `con` daemons connected over a `connection::frame_*` carrier. Peer A holds v2 owner `O` plus its v1 anchor `A`. The total closure exceeds the SMALL frame plaintext budget (4 KiB) and `A` is not co-resident in the same response window the compare selected (or the bundle slot count cannot hold both).
- **Action:** A responds to B's `sync::compare`; the plan emits exact have/need traffic instead of a single bundled send.
- **Expect:** B receives `sync::have_id` (166) advertising `O` and/or `A`; B's `SendNeededFactIdHandler` issues `sync::need_id` (167) for whichever id it lacks; A's `SendRequestedFactHandler` then sends each fact id individually. Convergence still reaches both `O` and `A`. No single oversized frame is produced; the carrier capacity gates how much closure ships per round, not whether it ships.
- **Defends:** Mechanism: dependency closure falls back to have/need rounds when the envelope cannot carry it. Invariant 5 (transport in [floor,head]; chunk-don't-grow).
- **Refs:** `send_needed_fact_id.rs`, `send_requested_fact.rs`, `sync::have_id`/`sync::need_id` layouts; `connection_frame_wire.rs` size classes.

### SYNC-09 — above-ceiling fact received via sync becomes PENDING without erroring the in-range closure  `multinode-network`
- **Setup:** Peer A at protocol HEAD that introduced `content::message:2` (above B's ceiling — B is an older still-usable release). A sends, in one converge, an in-range v1 fact `A1` AND an above-ceiling v2 fact `U` that `A1` does NOT depend on.
- **Action:** B receives both facts via `send_facts_on_connection` -> connection frame -> `receive_network_frame`.
- **Expect:** `A1` is admitted, projected, displayed, indexed in the shareable rows. `U` is retained as pending ingress by id/bytes, not projected, not displayed, and not counted. The presence of `U` does NOT cause B's projection of `A1` (or any in-range fact) to error.
- **Defends:** ADMISSION invariant: received above-ceiling input is pending; in-range closure intact.
- **Refs:** future admission gate before projector dispatch; `connection_frame.rs` receive path.

### SYNC-10 — pending future input does NOT break the closure when an in-range fact depends ONLY on in-range facts  `multinode-network`
- **Setup:** Peer A sends a converge batch: in-range v1 fact `A1` whose context_have = in-range v1 fact `A0`, plus an unrelated above-ceiling v2 fact `U`. B is the older release (ceiling below v2).
- **Action:** B converges and replays.
- **Expect:** B materializes `A0` and `A1` fully (closure `{A0, A1}` satisfied); `U` remains pending and inactive. The dependency-closure computation (`negentropy_context_have_for_leaf` -> `shareable_facts_for_connection_range(...,true)`) for `A1` resolves to `{A0, A1}` and never requires `U` as active context. No closure stall, no error on `A1`.
- **Defends:** ADMISSION invariant: pending future input does not break dependency closure of in-range facts.
- **Refs:** `shared_fact/rows.rs` `shareable_facts_for_connection_range`/`expand_fact_ids_with_context_for_connection`.

### SYNC-11 — pending future fact converges after post-rise replay, without re-sync  `replay-cli`
- **Setup:** B previously retained an above-ceiling fact `U` as pending ingress. B is updated so its ceiling now covers `U`'s tag version (the v2 projector + sibling `_v2/` dir are present and ceiling-active). Peer A still retains `U`, but does not need to resend it.
- **Action:** Run a wipe + full replay of B's retained fact log.
- **Expect:** The replay re-runs admission for `U`, routes it to its now-registered projector, and materializes it into the read model exactly like any freshly admitted fact; `content-count` / `messages` now include it.
- **Defends:** ADMISSION pending tradeoff. Invariant 4 (replay via the adapter keyed by the fact's own tag once the fact is active).
- **Refs:** `core/projectors.rs` RouterProjector tag routing; ADMISSION pending model.

### SYNC-12 — an OLD retained v1 fact syncs inside the CURRENT transport (fact age independent of carrier version)  `multinode-network`
- **Setup:** Peer A retains a very old v1 `content::message:1` fact `Old` created long before the current transport (frame v1 / TRNS magic). A and B negotiate UP to the current carrier (`CONNECTION_FRAME_VERSION = 1`, `frame_small`/`frame_bundle`).
- **Action:** B's compare names a range covering `Old`; A's `SendRequestedFactHandler` / compare-response ships `Old`.
- **Expect:** `Old` travels inside a current `connection::frame_*` fact (tag 168/169/170) with `TRNS` header v1 — NOT a legacy carrier. `require_sendable_fact(Old)` passes (non-local, non-private tag). B admits and projects `Old` via the v1 message projector. The carrier version is decoupled from the carried fact's age/version.
- **Defends:** Mechanism: old retained fact syncs inside the current transport; fact age independent of carrier version. Invariant 5.
- **Refs:** `send_requested_fact.rs` `require_sendable_fact`; `connection_frame_wire.rs` `CONNECTION_FRAME_TAG`/`CONNECTION_FRAME_VERSION`; `connection::frame_small`/`frame_bundle`.

### SYNC-13 — negentropy range summary fingerprint is computed over (timestamp,id) across mixed fact versions  `projector-unit`
- **Setup:** A set of available facts at distinct timestamps mixing versions: v1 `content::message:1` at `T1`, v2 `content::message:2` at `T2`, v1 `content::reaction` (tag 52) at `T3`.
- **Action:** Call `sync::compare::create::summarize_range(&facts)` (via `start_compare_fact`).
- **Expect:** `RangeSummary.count == 3` and `fingerprint` = XOR of `blake3("topo:sync-range-summary:v1:" || timestamp_be || fact.id)` over all three. The summary mixes ONLY `(timestamp, id)` — never the fact body/version. Two clients at different fact-version heads but holding the same id set produce the SAME fingerprint.
- **Defends:** Invariant 2 (rendering/summary uniformity is f(ids), version-independent); mechanism: negentropy over ids across mixed versions.
- **Refs:** `compare/create.rs` `summarize_range`, `RangeSummary`.

### SYNC-14 — compare response planning splits/batches by timestamp only, ignoring mixed fact versions  `handler-unit`
- **Setup:** 65 facts in a mismatched root range, interleaving v1 and v2 content tags at increasing timestamps.
- **Action:** Run `response_plan` on a `sync::compare` whose summary mismatches.
- **Expect:** Because `range_facts.len() > MAX_HAVE_IDS_PER_RANGE (64)` and timestamps differ, the plan emits CHILD `sync::compare` facts split by `TimestampRange::split()` on `(min,max)` timestamps; `send_fact_ids` is empty at this level. The split decision is driven purely by count and timestamp bounds — fact version is irrelevant. `local_range_facts` filters only by `id != compare_fact_id`, non-Local scope, timestamp range, and `is_sync_control_fact` (tags 165/166/167) — never by content tag.
- **Defends:** Invariant 2/4: range planning is version-agnostic; works across mixed fact versions.
- **Refs:** `compare/create.rs` `response_plan_inner`, `MAX_HAVE_IDS_PER_RANGE`, `local_range_facts`, `is_sync_control_fact`, `TimestampRange::split`.

### SYNC-15 — compare planning excludes only sync-control fact tags (165/166/167), treats all content/auth tags as syncable opaque facts  `projector-unit`
- **Setup:** Available set includes a `sync::compare` (165), a `sync::have_id` (166), a `sync::need_id` (167), plus content facts (50/52/54) and auth facts.
- **Action:** Call `local_range_facts(available, compare_id, range)`.
- **Expect:** The three sync-control facts are filtered out via `is_sync_control_fact`; ALL other tags (content/auth, any version) survive into the summarized set. Confirms the only version-aware special-case is the control-fact exclusion — every other fact is opaque syncable bytes regardless of version.
- **Defends:** Mechanism: sync carries opaque facts; control facts are not re-synced.
- **Refs:** `compare/create.rs` `local_range_facts`, `is_sync_control_fact` matching `TYPE_SYNC_COMPARE`/`TYPE_SYNC_HAVE_ID`/`TYPE_SYNC_NEED_ID`.

### SYNC-16 — send_needed_fact_id requests a peer's advertised fact id without inspecting its version  `handler-unit`
- **Setup:** Store (`CORE_SCHEMA_SOURCE`). A `sync::have_id` fact advertising `connection_id=C`, `fact_id=X` (where `X` is a v2 fact the local store lacks). Local store does NOT hold `X`.
- **Action:** Submit `send_needed_fact_id_intent(SendNeededFactId{ have_fact_id })` to `SendNeededFactIdHandler::handle`.
- **Expect:** Handler creates a `sync::need_id` (167) fact `{connection_id:C, fact_id:X}` and queues `send_facts_on_connection{ connection_id:C, fact_ids:[need.id] }`. The decision is purely "do I have id X?" via `persisted_fact` — the requested fact's version is never examined.
- **Defends:** Mechanism: have/need rounds operate on ids, not content versions.
- **Refs:** `send_needed_fact_id.rs` `SendNeededFactIdHandler::handle`; `need_id::create::fact`; `core/fact_store::persisted_fact`.

### SYNC-17 — send_needed_fact_id is a no-op when the advertised id is already retained (any version)  `handler-unit`
- **Setup:** Store already holds fact `X` (retained and ceiling-active when admitted). A `sync::have_id` advertising `X` arrives.
- **Action:** Submit to `SendNeededFactIdHandler::handle`.
- **Expect:** `persisted_fact(store, &have.fact_id)?.is_some()` is true -> returns empty `PipelineEffects::new()`; no `need_id` emitted. Retention suppresses re-request because we already hold the bytes.
- **Defends:** ADMISSION/idempotence: retained facts are not re-fetched.
- **Refs:** `send_needed_fact_id.rs` early-return on `persisted_fact(...).is_some()`.

### SYNC-18 — send_requested_fact ships a need-id's target as opaque bytes only if shareable+sendable  `handler-unit`
- **Setup:** Store with connection `C`, shareable index holds fact `X` (a v2 content fact) for `C`. A `sync::need_id` naming `{C, X}`.
- **Action:** Submit `send_requested_fact_intent(SendRequestedFact{ need_fact_id })` to `SendRequestedFactHandler::handle`.
- **Expect:** Handler loads `X` via `persisted_fact`, confirms `shareable_fact_for_connection(store,C,X).is_some()`, calls `require_sendable_fact(&fact)` (passes; non-local, non-private tag — version irrelevant), and queues `send_facts_on_connection{C,[X]}`. The fact body is forwarded verbatim; no re-encode.
- **Defends:** Mechanism: send_requested_fact ships opaque bytes; authorization is in the shareable index, not the content version.
- **Refs:** `send_requested_fact.rs` `SendRequestedFactHandler::handle`; `shared_fact::shareable_fact_for_connection`; `connection_frame::require_sendable_fact`.

### SYNC-19 — send_requested_fact refuses a private/local tag even when requested by id  `handler-unit`
- **Setup:** Store with connection `C`. A `sync::need_id` naming `{C, S}` where `S` is a retained private/local fact (e.g. tag `TYPE_CONNECTION_CLOSE=45` or a `local_*` secret), AND (contrived) an entry exists making it appear shareable.
- **Action:** Submit to `SendRequestedFactHandler::handle`.
- **Expect:** If `shareable_fact_for_connection` returns None -> empty effects (no send). If it returns Some, `require_sendable_fact` returns `Err("...refused private/local fact tag {tag}...")` -> handler `Err`, no send. Private/local tags are never sent regardless of an explicit id request.
- **Defends:** Invariant 5/6 + privacy floor: private/local facts excluded from transport.
- **Refs:** `send_requested_fact.rs`; `connection_frame.rs` `require_sendable_fact`/`is_private_local_fact_tag`.

### SYNC-20 — send_requested_fact is a no-op when the requested id is not retained locally  `handler-unit`
- **Setup:** Store with connection `C`. `sync::need_id{C, Z}` where local store does NOT hold `Z`.
- **Action:** Submit to `SendRequestedFactHandler::handle`.
- **Expect:** `persisted_fact(store,&Z)?` is None -> `Ok(PipelineEffects::new())` (empty). No error, no send. Missing-id is silently skipped (it may be a fact a peer needs from a third node).
- **Defends:** Invariant 4/5: graceful absence; no responder for facts we lack.
- **Refs:** `send_requested_fact.rs` early `else { return Ok(PipelineEffects::new()) }`.

### SYNC-21 — share_fact_with_sync REBUILDS shareable + negentropy rows from retained facts during replay  `replay-cli`
- **Setup:** A store that previously indexed several mixed-version facts (v1 + v2 content). Wipe the derived state (shareable rows, negentropy leaves/context-have, read models) leaving only the retained fact log.
- **Action:** Full replay: each retained content/auth fact re-projects, re-emitting `share_fact_with_sync` upsert intents which the `ShareFactWithSyncHandler` re-applies via `record_sync_contribution`.
- **Expect:** After replay, `SHAREABLE_FACT_ROWS`, `NEGENTROPY_LEAF_ROWS`, `NEGENTROPY_CONTEXT_HAVE_ROWS` are reconstructed identically (same `contribution_fingerprint` per leaf, same root `sync-status` fingerprint) regardless of replay order. The rebuild uses each fact's OWN tag/version via its projector. Idempotence holds: re-running yields `changed=false` for unchanged leaves.
- **Defends:** Invariant 4 (replay determinism; order-independent rebuild of derived sync state). Mechanism: share_fact_with_sync rebuilds shareable rows/negentropy from retained facts.
- **Refs:** `shared_fact/rows.rs` `record_sync_contribution`/`upsert_sync_contribution`/`contribution_fingerprint`; `cli.rs` `sync_status_output`; `share_fact_with_sync.rs`.

### SYNC-22 — share_fact_with_sync SUPPRESSES live-tail sends during replay (only rebuilds, no network)  `replay-cli`
- **Setup:** Store with an active connection row `C` and a retained shareable content fact `O`. Run the rebuild pass under replay (a context with no live connection processing — the COMMAND/replay path excludes `send_facts_on_connection` per `COMMAND_EXCLUDED_HANDLER_ROUTES`).
- **Action:** Replay re-applies the `share_fact_with_sync` upsert for `O`.
- **Expect:** Rows are rebuilt, but NO `send_facts_on_connection` live-tail intent reaches the network: the live-tail send is gated behind `changed` AND, in replay/command processing, `send_facts_on_connection` / `send_network_frame` / `receive_network_frame` are in `COMMAND_EXCLUDED_HANDLER_ROUTES` so the queued send produces no socket traffic. (Also: on a no-change re-apply `changed=false`, the handler returns empty effects with no live-tail at all.)
- **Defends:** Invariant 4: replay rebuilds derived state without re-emitting historical network effects. Mechanism: suppress live-tail sends during replay.
- **Refs:** `share_fact_with_sync.rs` `if changed { ... advertise_indexed_fact_to_connections_except ... } else { empty }`; `registry.rs` `COMMAND_EXCLUDED_HANDLER_ROUTES` (`send_facts_on_connection`/`send_network_frame`/`receive_network_frame`).

### SYNC-23 — live-tail send is suppressed to the ORIGIN connection (no echo) but sent to other connections  `handler-unit`
- **Setup:** The existing `share_fact_with_sync_suppresses_live_tail_to_origin_connection` scenario: two connections (`origin`, `other`), a `connection::fact_receipt` recording that `owner` arrived on `origin`.
- **Action:** Submit `share_fact_with_sync_intent_for_fact(W, owner.id, T, vec![])` to `ShareFactWithSyncHandler::handle`.
- **Expect:** Exactly one `send_facts_on_connection` intent, to `other_connection_id` only, `fact_ids == [owner.id]`. Origin is excluded via `origin_connection_ids_for_fact`. Confirms version-agnostic anti-echo: the carrier the fact arrived on is excluded regardless of the fact's version.
- **Defends:** Mechanism: live-tail correctness independent of fact version; no echo to source.
- **Refs:** `share_fact_with_sync.rs` `origin_connection_ids_for_fact` + `advertise_indexed_fact_to_connections_except`.

### SYNC-24 — seed_connection compare uses range_summary_for_connection over the shareable index across versions  `handler-unit`
- **Setup:** Store with connection `C` and a shareable index containing both v1 and v2 facts.
- **Action:** Run `seed_connection::advertise_connection_shareable_facts(store, C)` (the `SeedConnectionSyncHandler` path).
- **Expect:** Emits exactly one root `sync::compare` fact (`TimestampRange::ROOT`, `response_requested=true`) whose summary = `range_summary_for_connection(store, C, ROOT)` computed over ALL shareable ids (mixed versions) plus one `send_facts_on_connection{C,[compare.id]}`. The summary is over the id index, not over content versions.
- **Defends:** Invariant 2: seed summary is version-uniform. Mechanism: negentropy over ids across mixed versions.
- **Refs:** `seed_connection.rs` `advertise_connection_shareable_facts`; `shared_fact/rows.rs` `range_summary_for_connection`.

### SYNC-25 — sync-range CLI builds the cross-version dependency closure (--with-deps) over retained facts  `blackbox-cli`
- **Setup:** A `con` node with a connection to peer `P` and a shareable index holding a v2 owner `O` (timestamp in `[start,end]`) whose context_have is a v1 anchor `A` (timestamp `< start`).
- **Action:** `con sync-range <P_hex> --workspace <W_hex> --start-ms START --end-ms END --with-deps`.
- **Expect:** Dispatched output reports `deps: with`, `queued: yes`, and the queued send (via `shareable_facts_for_connection_range(..., include_deps=true)`) carries BOTH `O` and `A` even though `A` falls before `start` — the BFS closure over `negentropy_context_have_for_leaf` pulls the older-version anchor in. With `--without-deps` the same command sends only `O`.
- **Defends:** Mechanism: dependency closure includes cross-version context; CLI surface for explicit range sync.
- **Refs:** `shared_fact/cli.rs` `parse_sync_range_args`/`SYNC_RANGE_USAGE`; `shared_fact/rows.rs` `shareable_facts_for_connection_range` (the `--with-deps` BFS).

### SYNC-26 — sync-status root fingerprint is identical across two clients at different fact-version heads holding the same ids  `blackbox-cli`
- **Setup:** Two `con` nodes that have converged to the SAME common in-range fact ids. Node A is at a head that wrote some facts as v2; node B is an older release that drops above-ceiling v2 inputs, so the assertion restricts to the common in-range id set.
- **Action:** Run `con sync-status` on both for the common shareable set.
- **Expect:** `root_count` and `root_fingerprint` MATCH for the common id set (fingerprint = XOR over `(timestamp,id)`; version-independent). Above-ceiling facts present only on A are outside this assertion until B's ceiling rises and A re-syncs them. Documents that fingerprint convergence is over ids, not content.
- **Defends:** Invariant 2 (uniform sync read-model over ids); mechanism: negentropy across mixed versions.
- **Refs:** `shared_fact/cli.rs` `sync_status_output`; `shared_fact/rows.rs` `sync_status`, `range_summary` fingerprinting.

### SYNC-27 — negentropy context-have is keyed (workspace_id, owner_fact_id, context_fact_id) with no version field  `guardrail`
- **Setup:** Inspect the `NEGENTROPY_CONTEXT_HAVE_ROWS` / `NEGENTROPY_LEAF_ROWS` / `SHAREABLE_FACT_ROWS` schema and key layouts.
- **Action:** Static/structural assertion over `shared_fact/rows.rs` row encoders (`negentropy_context_have_key`, `negentropy_leaf_key`, `shareable_fact_row`).
- **Expect:** Keys contain only ids/workspace/timestamp — NO content-version byte. Adding a new content fact version (a new tag + `_vN/` dir) requires ZERO change to these sync row keys. Proves the version knob is the fact tag, not a sync-row field.
- **Defends:** VERSIONING KNOB = fact tag; sync index is version-stable. Invariant 4.
- **Refs:** `shared_fact/rows.rs` `negentropy_context_have_key`, `negentropy_leaf_key`, `shareable_fact_row`, the row constants exported from `shared_fact.rs`.

### SYNC-28 — compare/have/need fact tags (165/166/167) are globally unique and unchanged by a new content version  `guardrail`
- **Setup:** Registry-level boundary test.
- **Action:** Run/extend `fact_route_tags_are_globally_unique` (registry.rs:717-729) and assert the sync tags `sync::compare=165`, `sync::have_id=166`, `sync::need_id=167`, `sync::shared_fact=162`, `sync::range_request=160`, `sync::cascade_test_fact=2` are present and distinct.
- **Expect:** All 43 `FactRoute.tag` values distinct; sync's six tags stable. Introducing `content::message:2` adds a NEW content tag (or reuses 50 under the kept-forever-projector contract) but never collides with or mutates the sync envelope tags.
- **Defends:** Mechanism: a new wire shape = new tag in every scope; sync envelope tags are independent of content versions.
- **Refs:** `registry.rs` `fact_route_tags_are_globally_unique`, `FACT_ROUTES`.

### SYNC-29 — shared_fact INDEX (162) can name an owner id whose bytes are pending or absent locally  `handler-unit`
- **Setup:** Store where the referenced owner `U` is above-ceiling and either pending locally or absent because it never made it through the wire/opening boundary. An incoming `sync::shared_fact` (tag 162, a ceiling-active envelope) names `U`.
- **Action:** Project the `sync::shared_fact` via `SyncSharedFactProjector`.
- **Expect:** The shared_fact index fact projects fine (its own tag 162 is ceiling-active) and emits a `sync_exact_fact` range offer for `U`'s id — because the projector never decodes `U`'s body. The envelope/index layer is decoupled from whether the owner bytes are currently active, pending, or absent. If `U` is already pending locally, a later `need_id` for the same id is a no-op; if it is absent, normal sync can still request it.
- **Defends:** SUBSTANCE/ADMISSION: the sync envelope is a current-ceiling fact even while it references a content id whose bytes are not active locally.
- **Refs:** `sync/shared_fact/project.rs` `SyncSharedFactProjector::project_typed` (no body decode); `ContextOffer::range`.

### SYNC-30 — compare-response no-store fallback path plans purely over context facts (version-agnostic)  `handler-unit`
- **Setup:** `SendSyncCompareResponseHandler::handle` invoked with a `HandlerContext` that has NO store (the `else` branch), `with_facts` carrying mixed v1/v2 facts and a mismatching `sync::compare`.
- **Action:** Run the handler.
- **Expect:** It uses `response_plan(compare_fact, context.facts())` with `expanded = plan.send_fact_ids.clone()` (no DB-backed closure expansion). The plan/summary still operate over `(timestamp,id)` only; mixed versions are handled identically. Confirms both code paths (store and no-store) are version-agnostic.
- **Defends:** Invariant 4: deterministic, version-independent planning in both paths.
- **Refs:** `send_compare_response.rs` `else` branch (`context.facts()`, `response_plan`).

### SYNC-31 — range/summary is order-independent across mixed-version fact arrival  `property`
- **Setup:** Property test: a random multiset of facts with random tags (v1/v2/auth/content) and random distinct timestamps.
- **Action:** Compute `summarize_range` and `response_plan` over the set in many random insertion orders.
- **Expect:** `RangeSummary` (count + XOR fingerprint) is invariant under permutation; `response_plan.send_fact_ids` and child-compare ranges are stable (the planner sorts via `local_range_facts` `sort_by_key((timestamp,id))`). Fact version never affects the result. XOR-fold + sort give order-independence.
- **Defends:** Invariant 4 (order-independent replay/sync); mechanism: negentropy over ids across mixed versions.
- **Refs:** `compare/create.rs` `summarize_range` (XOR fold), `local_range_facts` (sort), `response_plan_inner`.
## 13. Content scope cross-version (new x old)

Scope under test: `src/protocol/content` — the 7 routed fact families
(`message` tag 50, `message_deletion` 51, `reaction` 52, `file_deletion` 53,
`file` 54, `file_slice` 55, `retention_policy` 147) plus the context-only
`purge`. Each family today is ONE tag with ONE fixed-width `layout.rs`
(`encode_fact`/`decode_fact`) and ONE projector registered in `FACT_ROUTES`
(`projector_routes!`, registry.rs 593-624). For every family the charter
proposes a v2 with an incompatible wire shape (new body encoding/mentions/
edits/threads for message; custom emoji/deletion for reaction; new descriptor/
chunking/BAO/metadata-encryption for file+file_slice; disappearing-set/tighten/
compact/status changes for retention; in-band unfurl as a ceiling-gated shared
snapshot fact). Per the model a v2 = a NEW tag + a NEW kept-forever projector +
a sibling `_v2/` directory + (only if the input surface changed) a new cli
bucket; rows/queries shared at head. These tests assert, per family and per
{new,old} axis: (a) v1 facts replay under the v1 adapter keyed by their OWN tag
into current rows; (b) v2 is dormant below ceiling (refused on local create,
pending on receipt) and producible at/after; (c) old meaning is preserved
by the v1 projector forever; (d) unsafe encodings are handled by
suppress/tighten/reissue, never mass conversion.

Reference anchors used throughout: `RouterProjector::project` unknown-tag
`Err("no target projector registered for fact tag {tag}")` (projectors.rs:456);
`fact_route_tags_are_globally_unique` (registry.rs 717-729); read-model tables
`CONTENT_MESSAGES`, `OPENED_MESSAGES`, `MESSAGE_TOMBSTONES`, `CONTENT_REACTIONS`,
`CONTENT_FILES`, `FILE_SLICES`, `MESSAGE_DELETIONS`, `FILE_DELETIONS`
(registry.rs 36-182).

---

### CONTENT-01 — message v1 (tag 50) replays under its own adapter into current rows  `replay-cli`
- **Setup:** A store seeded by a current-head `con` build holding `content::message` facts created via `con send WORKSPACE_ID_HEX TEXT` (tag 50, `CONTENT_MESSAGE_BYTES` fixed-width, fields workspace_id/created_at_ms/author_user_id/signer_id/signer_public_key/frontier_id/local_history_node_secret_id/expires_at_minute/retention_policy_id/minute/nonce/ciphertext(128)/signature). Protocol version = head; ceiling = head.
- **Action:** Wipe derived state and replay all retained facts (`test-replay-deps-reverse` style full wipe+replay over the fact log).
- **Expect:** Every tag-50 fact routes to `content::message::project::ContentMessageProjector` via `FACT_ROUTES` and rebuilds identical `CONTENT_MESSAGES` + `OPENED_MESSAGES` rows; `con messages WORKSPACE_ID_HEX` and `con view` produce byte-identical output to pre-wipe. No "no target projector" error.
- **Defends:** Invariant 4 (replay determinism, adapter keyed by own tag); invariant 2 (rendering uniformity).
- **Refs:** `content/message/encode.rs` TYPE_CONTENT_MESSAGE=50, `content/message/project.rs` ContentMessageProjector and row builders, registry.rs `read_models`, registry.rs:604.

### CONTENT-02 — message v2 (new body encoding + mentions) is REFUSED on local create below ceiling  `blackbox-cli`
- **Setup:** Build whose head defines proposed `content::message_v2` (tag e.g. 56, sibling `content/message_v2/`) carrying the richer body (length-prefixed body blob + mention list) with intro_version = N+1. Fleet manifest ceiling pinned at N (an older still-usable release does not transport message_v2).
- **Action:** Run a `con send` variant that would emit the v2 fact while ceiling = N.
- **Expect:** Local creation of the above-ceiling fact is REFUSED (admission rejects; no message_v2 fact written to the log). `con send` still emits the v1 tag-50 fact, and `con messages` shows the message rendered at the ceiling (v1 plain body).
- **Defends:** Invariant 1 (visibility — only ceiling-active facts are admissible); admission "local creation above ceiling refused".
- **Refs:** registry.rs FACT_ROUTES, `content/message/cli.rs` SEND_USAGE, app.rs MATCH_PROTOCOL, runtime.rs submit_fact:268.

### CONTENT-03 — message v2 received below ceiling is PENDING, not errored/dropped  `handler-unit`
- **Setup:** Head build with message_v2 tag registered in a sibling dir; ceiling = N (below message_v2.intro_version). A peer delivers a wire frame carrying a message_v2 fact (tag 56).
- **Action:** Receive the fact through the connection-frame projector path (frame decrypts and emits the inner content fact) and attempt projection.
- **Expect:** The fact is retained as opaque bytes (present in the fact log), unprojected, undisplayed, uncounted — NOT dropped and NOT surfaced as an error to the user. (Contrast: today an unrouted tag hits `RouterProjector::project` Err at projectors.rs:456 — the pending path must intercept above-ceiling tags before that error.)
- **Defends:** Admission "received above-ceiling fact pending"; invariant 5 (readers forever — fact kept).
- **Refs:** projectors.rs:456 unknown-tag Err, RouterProjector@423, runtime.rs submit_facts:274, connection_frame_wire.rs inner-bundle decode.

### CONTENT-04 — pending message v2 ACTIVATES on wipe+replay once ceiling rises  `replay-cli`
- **Setup:** Store from CONTENT-03 holding the pending message_v2 fact. Fleet manifest updated so the oldest still-usable release supports protocol N+1; trusted_time advances past blocker.expires_at + M so ceiling rises to >= message_v2.intro_version.
- **Action:** Wipe derived state and replay.
- **Expect:** The previously-pending tag-56 fact now routes to `ContentMessageV2Projector` (the new kept-forever projector) and materializes a `CONTENT_MESSAGES`/`OPENED_MESSAGES` row with the richer body. v1 tag-50 facts still route to the v1 projector. Both render at the (now higher) ceiling.
- **Defends:** Admission "pending facts activate on next wipe+replay once ceiling covers tag"; invariant 4 (ceiling-independent replay by own tag); invariant 2.
- **Refs:** registry.rs FACT_ROUTES (sibling v2 route), projectors.rs RouterProjector, ceiling-activation rule.

### CONTENT-05 — two clients at the same protocol version render the SAME message row regardless of release  `multinode-network`
- **Setup:** Two `con` daemons — release A (head) and release B (one prior, both still-usable) — connected, ceiling = N where message_v2 is NOT yet ceiling-active. A authored both a v1 message and (locally) holds a pending message_v2.
- **Action:** Sync facts between A and B; on each, run `con messages` and `con view` for the shared message.
- **Expect:** Both A and B produce identical read-model row content for the v1 message (rendered at the ceiling, not at A's head). The pending v2 is invisible on both. Only presentation chrome (if any) may differ.
- **Defends:** Invariant 2 (rendering uniformity — same protocol version => same row); invariant 3 (no-regression — B must support every ceiling-active capability).
- **Refs:** sync::share_fact_with_sync handler, `content/message/queries.rs`, registry.rs read_models CONTENT_MESSAGES/OPENED_MESSAGES.

### CONTENT-06 — message edit (proposed v2 edit fact) preserves original v1 meaning under v1-only replay  `replay-cli`
- **Setup:** Store with a v1 tag-50 message and a proposed `content::message_edit` v2 fact (new tag) that supersedes the body. Replay performed on a still-usable release whose ceiling does NOT cover the edit tag.
- **Action:** Wipe+replay.
- **Expect:** The original message renders with its ORIGINAL v1 body (the edit fact is pending/inert below ceiling); the v1 projector's meaning is unchanged. No mass-conversion of the original message into an edited form.
- **Defends:** Invariant 5 (old fact readers kept forever; old meaning preserved); "dormant handled by pending, unsafe handled by suppression, not mass conversion."
- **Refs:** `content/message/project.rs`, FACT_ROUTES, ceiling-active capability rule.

### CONTENT-07 — message threads (proposed v2 thread-parent field) dormant below ceiling, producible at/after  `blackbox-cli`
- **Setup:** Head build with message_v2 carrying a `thread_parent_id` field; fleet manifest ceiling first pinned at N (below), then raised to N+1 (at/after) via signed manifest + trusted-time advance.
- **Action:** Attempt `con send --thread PARENT_HEX ...` at ceiling N, then again at ceiling N+1.
- **Expect:** At ceiling N: refused (above-ceiling local create), falls back to/forces v1 tag-50 (no thread). At ceiling N+1: emits message_v2 with thread_parent_id; `con messages` renders the threaded relationship at the ceiling.
- **Defends:** Invariant 1; ceiling-activation gate ("CEILING-ACTIVE iff intro_version<=ceiling AND every still-usable release can transport it"); invariant 3.
- **Refs:** `content/message/cli.rs`, ROUTES intro_version, RouterProjector ceiling-filter.

### CONTENT-08 — message cli bucket reuse when send input surface unchanged (param-subset contract)  `guardrail`
- **Setup:** message_v2 introduces a new wire body but the `send WORKSPACE_ID_HEX TEXT` input surface is unchanged (still workspace+text). CliCommand "send" has a version-tagged run-fn list with an ABSENT v2 bucket entry.
- **Action:** Resolve the `send` command at ceiling = message_v2.intro_version.
- **Expect:** Ceiling selects the highest intro_version <= ceiling; the absent v2 bucket reuses the previous run fn under the param-subset contract (`v_next.required_inputs ⊆ active_cli.collected_params`); the same collected params {workspace_id, text} drive v2 fact creation. No new cli dir was needed.
- **Defends:** Version-bucket rule "cli ONLY if input surface changed (absent=reuse prev)"; invariant 2.
- **Refs:** registry.rs MATCH_COMMANDS `cli_command!("send", SEND_USAGE, send)` line 452, CliCommand version-tagged list.

### CONTENT-09 — reaction v1 (tag 52) replays into CONTENT_REACTIONS under its own adapter  `replay-cli`
- **Setup:** Store with `content::reaction` facts created via `con react WORKSPACE_ID_HEX MESSAGE_SELECTOR EMOJI` (tag 52, fixed-width `CONTENT_REACTION_BYTES`; emoji sealed in `REACTION_CIPHERTEXT_BYTES = 80` slot = 64 emoji bytes + 16 poly1305 tag). Ceiling = head.
- **Action:** Wipe+replay.
- **Expect:** Each tag-52 fact routes to `content::reaction::project::ContentReactionProjector` and rebuilds identical `CONTENT_REACTIONS` rows; emoji opens to the same string on display. No projector error.
- **Defends:** Invariant 4; invariant 2.
- **Refs:** `content/reaction/layout.rs` TYPE_CONTENT_REACTION=52, `content/reaction/fact.rs` REACTION_CIPHERTEXT_BYTES=80, registry.rs:606 ContentReactionProjector, read_models CONTENT_REACTIONS.

### CONTENT-10 — reaction v2 (custom-emoji larger ciphertext) refused on local create below ceiling  `blackbox-cli`
- **Setup:** Head defines `content::reaction_v2` (new tag, larger sealed slot or descriptor for a custom-emoji image id) intro_version N+1; ceiling = N.
- **Action:** `con react WORKSPACE_ID_HEX MESSAGE_SELECTOR :customemoji:` that would require the v2 wire.
- **Expect:** Local create of the above-ceiling reaction_v2 is REFUSED; the command either emits a v1 unicode-emoji tag-52 fact (fits 64 bytes) or errors that the custom emoji is not ceiling-active — it never writes an above-ceiling fact.
- **Defends:** Invariant 1; admission local-refuse.
- **Refs:** `content/reaction/fact.rs`, `content/message/cli.rs` REACT_USAGE line 27, admission.

### CONTENT-11 — reaction v2 received below ceiling pending; activates on ceiling-rise replay  `handler-unit`
- **Setup:** Peer delivers a reaction_v2 fact (new tag) while local ceiling = N (below intro). Then manifest raises ceiling to N+1.
- **Action:** Receive (pending), then later wipe+replay after ceiling rises.
- **Expect:** Below ceiling: pending opaque, uncounted, not in `CONTENT_REACTIONS`, no error surfaced. After ceiling rise + replay: routes to ContentReactionV2Projector, materializes the custom-emoji reaction row. v1 tag-52 reactions still route to v1 projector.
- **Defends:** Admission pending + activation; invariant 4; invariant 5.
- **Refs:** projectors.rs:456, FACT_ROUTES sibling reaction_v2, CONTENT_REACTIONS.

### CONTENT-12 — reaction deletion (v1 there is no delete; proposed v2 reaction-retraction) preserves prior reaction under v1 replay  `projector-unit`
- **Setup:** v1 has no reaction-deletion fact family. Proposed v2 adds a reaction-retraction fact (new tag). Store holds a v1 reaction and a v2 retraction; replay on a still-usable release with ceiling below the retraction tag.
- **Action:** Wipe+replay below ceiling.
- **Expect:** v1 reaction row stays present (retraction inert/pending below ceiling); the v1 ContentReactionProjector meaning is unchanged. No mass-conversion of the reaction into a deleted state.
- **Defends:** Invariant 5 (old meaning preserved); pending-not-convert.
- **Refs:** `content/reaction/project.rs`, CONTENT_REACTIONS, FACT_ROUTES.

### CONTENT-13 — file v1 (tag 54) replays: descriptor + sealed_metadata + root_hash rebuild CONTENT_FILES  `replay-cli`
- **Setup:** Store with `content::file` facts (`con send-file ...`; tag 54, fields message_id/file_id/blob_bytes/total_slices/slice_bytes/root_hash(32)/sealed_metadata(`SEALED_METADATA_BYTES` padded slot — filename+mime sealed)). Ceiling = head.
- **Action:** Wipe+replay.
- **Expect:** Each tag-54 fact routes to `content::file::project::ContentFileProjector`, rebuilds identical `CONTENT_FILES` rows; `con files WORKSPACE_ID_HEX` lists identical descriptors; sealed_metadata opens to same filename/mime. No projector error.
- **Defends:** Invariant 4; invariant 2.
- **Refs:** `content/file/layout.rs` TYPE_CONTENT_FILE=54, ContentFileProjector registry.rs:601, read_models CONTENT_FILES, `content/file/queries.rs`.

### CONTENT-14 — file_slice v1 (tag 55) replays: BAO proof verified against parent root, FILE_SLICES rebuilt  `replay-cli`
- **Setup:** Store with `content::file_slice` facts (tag 55, fields file_id/slice_index/proof(`FILE_SLICE_BAO_PROOF_BYTES` padded BAO slot of encrypted slice); `FILE_SLICE_PLAINTEXT_BYTES = 256 KiB`). Parent tag-54 file fact present. Ceiling = head.
- **Action:** Wipe+replay (slice projector verifies BAO proof against parent file root_hash before counting).
- **Expect:** Each tag-55 fact routes to `content::file_slice::project::ContentFileSliceProjector`; BAO verification reproduces the same encrypted slice bytes; `FILE_SLICES` rows identical; `con save-file` reconstructs identical blob. No projector error.
- **Defends:** Invariant 4 (deterministic, own-tag adapter); carrier-capacity precedent (file_slice is the chunk-don't-grow exemplar).
- **Refs:** `content/file_slice/layout.rs` TYPE_CONTENT_FILE_SLICE=55, `content/file_slice/fact.rs` FILE_SLICE_BAO_PROOF_BYTES, ContentFileSliceProjector registry.rs:603, read_models FILE_SLICES.

### CONTENT-15 — file_slice v2 (larger chunk size / new BAO geometry) refused on local create below ceiling  `blackbox-cli`
- **Setup:** Head defines `content::file_slice_v2` (new tag, e.g. 512 KiB plaintext slice and a re-sized BAO proof slot, requiring a wider connection frame `FILE_SLICE` size class) intro_version N+1; ceiling = N because an older still-usable release's frame_file_slice carrier cannot transport the larger slice.
- **Action:** `con send-file` of a large file while ceiling = N.
- **Expect:** Local create emits v1 tag-55 slices at the v1 256 KiB geometry (the carrier capacity gates ceiling activation); the v2 slice tag is REFUSED. File still transfers chunked at v1 sizes.
- **Defends:** Invariant 1; "carrier capacity GATES ceiling activation (chunk-don't-grow)"; invariant 3.
- **Refs:** `content/file_slice/fact.rs` FILE_SLICE_PLAINTEXT_BYTES, connection_frame_wire.rs CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES, ROUTES intro_version.

### CONTENT-16 — file_slice v2 received below ceiling pending; v1 slices keep BAO meaning  `handler-unit`
- **Setup:** Peer delivers file_slice_v2 facts (new tag) while ceiling = N. Store also holds v1 tag-55 slices for the same file.
- **Action:** Receive v2 slices (pending), then wipe+replay below ceiling.
- **Expect:** v2 slices pending opaque/uncounted (not in `FILE_SLICES`, no BAO verification attempted, no error surfaced); v1 slices still verify and count. File reconstruction uses only v1 slices. After ceiling rises and replay, v2 slices route to ContentFileSliceV2Projector.
- **Defends:** Admission pending; invariant 4; invariant 5.
- **Refs:** projectors.rs:456, FACT_ROUTES sibling file_slice_v2, FILE_SLICES.

### CONTENT-17 — file v2 (encrypted/larger sealed_metadata descriptor) dormant below, producible at/after ceiling  `blackbox-cli`
- **Setup:** Head defines `content::file_v2` (new tag) whose `sealed_metadata` carries an encrypted extended descriptor (larger slot / new metadata-encryption scheme). Ceiling pinned at N (below), then raised to N+1.
- **Action:** `con send-file` at ceiling N, then at ceiling N+1.
- **Expect:** At N: emits v1 tag-54 file with v1 sealed_metadata; v2 refused. At N+1: emits file_v2 with the encrypted extended descriptor; `con files` renders it at the ceiling. v1 and v2 files coexist; each rendered by its own projector.
- **Defends:** Invariant 1; ceiling-activation; invariant 2.
- **Refs:** `content/file/layout.rs` SEALED_METADATA_BYTES, ContentFileProjector / proposed ContentFileV2Projector, CONTENT_FILES.

### CONTENT-18 — file_deletion v1 (tag 53) replays into FILE_DELETIONS; old tombstone meaning preserved  `replay-cli`
- **Setup:** Store with `content::file_deletion` facts (`con delete-file ...`; tag 53, fields target_file_id/author_user_id/signer). Ceiling = head.
- **Action:** Wipe+replay.
- **Expect:** Each tag-53 fact routes to `content::file_deletion::project::ContentFileDeletionProjector`; `FILE_DELETIONS` rows rebuilt; deleted files stay tombstoned in `con files`. No projector error.
- **Defends:** Invariant 4; invariant 2.
- **Refs:** `content/file_deletion/layout.rs` TYPE_CONTENT_FILE_DELETION=53, ContentFileDeletionProjector registry.rs:602, read_models FILE_DELETIONS, MATCH_COMMANDS delete-file line 467.

### CONTENT-19 — file_deletion v2 received below ceiling pending; does NOT tombstone v1 files  `handler-unit`
- **Setup:** Proposed `content::file_deletion_v2` (new tag, e.g. carries a deletion scope / multi-file selector). Peer delivers a v2 deletion while ceiling = N (below intro).
- **Action:** Receive (pending), then wipe+replay below ceiling.
- **Expect:** The v2 deletion is inert: target files remain live (not tombstoned), no `FILE_DELETIONS` row, no error. A v1 tag-53 deletion in the same store still tombstones its target. After ceiling rises + replay, v2 deletion activates.
- **Defends:** Admission pending; pending-not-convert (no mass tombstoning); invariant 5.
- **Refs:** projectors.rs:456, FILE_DELETIONS, FACT_ROUTES.

### CONTENT-20 — message_deletion v1 (tag 51) replays into MESSAGE_DELETIONS/MESSAGE_TOMBSTONES  `replay-cli`
- **Setup:** Store with `content::message_deletion` facts (`con delete-message ...`; tag 51, fields target_message_id/target_frontier_id/target_minute/author_user_id/signer). Ceiling = head.
- **Action:** Wipe+replay.
- **Expect:** Each tag-51 fact routes to `content::message_deletion::project::ContentMessageDeletionProjector`; `MESSAGE_DELETIONS` and `MESSAGE_TOMBSTONES` rebuilt identically; deleted messages stay hidden in `con messages`/`con view`. No projector error.
- **Defends:** Invariant 4; invariant 2.
- **Refs:** `content/message_deletion/layout.rs` TYPE_CONTENT_MESSAGE_DELETION=51, ContentMessageDeletionProjector registry.rs:605, read_models MESSAGE_DELETIONS/MESSAGE_TOMBSTONES, MATCH_COMMANDS delete-message line 472.

### CONTENT-21 — message_deletion v2 (proposed reason/scope field) dormant below ceiling, producible at/after  `blackbox-cli`
- **Setup:** Head defines `content::message_deletion_v2` (new tag adding a deletion-reason or range selector). Ceiling pinned at N, then raised to N+1.
- **Action:** `con delete-message` at ceiling N, then at ceiling N+1.
- **Expect:** At N: emits v1 tag-51 deletion (no reason); v2 refused. At N+1: emits message_deletion_v2; tombstone row carries the new field rendered at the ceiling. Both versions coexist via their own projectors; the tombstone read-model is shared at head.
- **Defends:** Invariant 1; ceiling-activation; version-bucket "rows/queries shared at head."
- **Refs:** `content/message_deletion/`, MESSAGE_TOMBSTONES, FACT_ROUTES.

### CONTENT-22 — retention_policy v1 (tag 147) disappearing-set replays; floor/TTL meaning preserved  `replay-cli`
- **Setup:** Store with `content::retention_policy` facts via `con disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]` (tag 147, fields scope_kind(workspace/channel/thread)/scope_id/ttl_minutes/retire_minute/supersedes_policy_id chain). Ceiling = head.
- **Action:** Wipe+replay.
- **Expect:** Each tag-147 fact routes to `content::retention_policy::project::RetentionPolicyProjector`; the supersedes chain re-derives the same active policy per `(workspace_id, scope_kind, scope_id)`; `con disappearing-status WORKSPACE_ID_HEX` reproduces identical effective_floor/current_ttl_minutes/horizon_floor. No projector error.
- **Defends:** Invariant 4 (chain re-derivation deterministic); invariant 2.
- **Refs:** `content/retention_policy/layout.rs` TYPE_RETENTION_POLICY=147, RetentionPolicyProjector registry.rs:624, `content/retention_policy/cli.rs` DISAPPEARING_SET/STATUS_USAGE, `content/retention_policy/fact.rs` SCOPE_KIND_*.

### CONTENT-23 — disappearing-tighten v1 monotonic-floor meaning replays unchanged under v1 adapter  `replay-cli`
- **Setup:** Store with a chain of tag-147 policies where `con disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES --yes` lowered the TTL (advanced retire_minute) on top of a prior `disappearing-set`. Ceiling = head.
- **Action:** Wipe+replay.
- **Expect:** Replay re-applies the supersedes chain monotonically; the tightened (later) policy wins; `disappearing-status` shows the tightened TTL/floor; no message retired by the tightened policy reappears. The v1 projector's monotonic-floor rule is preserved exactly.
- **Defends:** Invariant 4; invariant 5 (old meaning preserved); monotonic-floor invariant in RetentionPolicyProjector.
- **Refs:** `content/retention_policy/commands.rs` (tighten), DISAPPEARING_TIGHTEN_USAGE, supersedes_policy_id chain.

### CONTENT-24 — retention_policy v2 (new scope_kind / per-message TTL) refused on local create below ceiling  `blackbox-cli`
- **Setup:** Head defines `content::retention_policy_v2` (new tag) adding a scope_kind beyond workspace/channel/thread or a per-message TTL field, intro_version N+1; ceiling = N (an older still-usable release cannot evaluate the new scope).
- **Action:** `con disappearing-set` (or a v2-only variant) targeting the new scope at ceiling N.
- **Expect:** The above-ceiling v2 policy is REFUSED on local create; only the v1 tag-147 policy may be authored. No v2 fact written. `disappearing-status` keeps evaluating v1 policies at the ceiling.
- **Defends:** Invariant 1; admission local-refuse; invariant 3 (older release must evaluate every ceiling-active policy).
- **Refs:** `content/retention_policy/fact.rs` SCOPE_KIND_WORKSPACE/CHANNEL/THREAD, FACT_ROUTES, ceiling rule.

### CONTENT-25 — retention_policy v2 received below ceiling pending; floor NOT tightened by inert v2  `handler-unit`
- **Setup:** Peer delivers a retention_policy_v2 fact (new tag) that, if active, would tighten the floor. Local ceiling = N (below v2 intro).
- **Action:** Receive (pending), then `con disappearing-status` and a wipe+replay below ceiling.
- **Expect:** The v2 policy is inert: it does NOT enter the supersedes chain, does NOT tighten effective_floor, no error surfaced, pending opaque. Messages that would be retired by v2 stay live. After ceiling rises + replay, the v2 policy activates and the floor tightens deterministically.
- **Defends:** Admission pending + activation; pending-not-convert; invariant 5; invariant 4.
- **Refs:** projectors.rs:456, RetentionPolicyProjector, `content/retention_policy/queries.rs`, DISAPPEARING_STATUS.

### CONTENT-26 — disappearing-compact is a local context op, not a versioned fact — no v2 tag introduced  `guardrail`
- **Setup:** Head build. `con disappearing-compact WORKSPACE_ID_HEX` compacts tombstones/purges via the `content::purge` CONTEXT (role `content_purged`, `content/purge/project.rs`), which has NO `layout.rs` and is NOT in `FACT_ROUTES`.
- **Action:** Inspect `FACT_ROUTES` and the purge module; run `disappearing-compact`.
- **Expect:** No new fact tag is produced by compaction (purge is context-only). `fact_route_tags_are_globally_unique` (registry.rs 717-729) still holds with exactly 47 routes; the compaction result is deterministically reproducible from retained facts on replay (it derives, it does not create non-deterministic facts).
- **Defends:** Invariant 4 ("recreates only deterministic facts"); model "purge is CONTEXT, NOT a fact family."
- **Refs:** `content/purge/project.rs` content_purged_role/target_purge_key, registry.rs FACT_ROUTES + fact_route_tags_are_globally_unique, DISAPPEARING_COMPACT_USAGE.

### CONTENT-27 — disappearing-status read-model is shared at head; v1 and v2 policies render at the ceiling  `multinode-network`
- **Setup:** Two still-usable releases connected; ceiling = N where retention_policy_v2 is NOT ceiling-active. Store holds v1 policies plus a pending v2.
- **Action:** On each node run `con disappearing-status WORKSPACE_ID_HEX`.
- **Expect:** Both nodes report identical effective_floor/current_ttl/horizon_floor computed from v1 policies at the ceiling; the pending v2 contributes nothing on either. Same protocol version => same status row content.
- **Defends:** Invariant 2 (rendering uniformity); invariant 3; "withhold a new DERIVATION of existing facts until ceiling-active."
- **Refs:** `content/retention_policy/queries.rs`, `cli.rs` status_output, read_models retention rows.

### CONTENT-28 — in-band unfurl as a ceiling-gated shared snapshot fact: sender snapshot only, never refetch  `multinode-network`
- **Setup:** Head defines a proposed `content::unfurl` snapshot fact (new tag) carrying a SENDER-captured preview (title/desc/image-ref) attached to a message, intro_version N+1. Two nodes; ceiling raised to N+1 so unfurl is ceiling-active. Sender authors a message containing a URL.
- **Action:** Sender emits the unfurl snapshot fact; it syncs to the recipient; recipient runs `con view`.
- **Expect:** The recipient renders the unfurl strictly from the retained snapshot fact — the recipient NEVER fetches the URL. The fact is signed by the sender and travels as a normal content fact. Both nodes (same protocol version) render the same preview.
- **Defends:** Invariant 2 (surfaced meaning = f(retained facts, version)); charter "recipient never fetches URL."
- **Refs:** proposed `content/unfurl/` sibling, FACT_ROUTES new tag, sync::share_fact_with_sync, `content/message/project.rs` view path.

### CONTENT-29 — in-band unfurl below ceiling is pending; recipient still never fetches  `handler-unit`
- **Setup:** Sender (head) emits an unfurl snapshot fact; recipient ceiling = N (below unfurl intro). Recipient receives the fact.
- **Action:** Receive (pending), then `con view` the message, then wipe+replay below ceiling.
- **Expect:** The unfurl fact is pending opaque/uninterpreted; `con view` shows the message WITHOUT an unfurl preview and does NOT fetch the URL as a fallback (no network egress). No error surfaced. After ceiling rises + replay, the snapshot renders — still without any URL fetch.
- **Defends:** Admission pending; charter "recipient never fetches URL; replay never refetches"; invariant 5.
- **Refs:** projectors.rs:456, proposed unfurl projector, view path, no-egress assertion.

### CONTENT-30 — unfurl replay NEVER refetches the URL (deterministic from snapshot)  `replay-cli`
- **Setup:** Store with ceiling-active unfurl snapshot facts (from CONTENT-28). A replay harness with network egress observable (e.g. a fail-closed network shim).
- **Action:** Wipe+replay the full fact log.
- **Expect:** Replay rebuilds the unfurl preview rows purely from the retained snapshot facts; zero outbound HTTP/URL fetches occur during replay; the rebuilt preview is byte-identical to pre-wipe. Replay is order-independent and ceiling-independent (each unfurl keyed by its own tag).
- **Defends:** Invariant 4 (replay determinism, no non-deterministic recreation); charter "replay never refetches."
- **Refs:** proposed unfurl projector, replay path, FACT_ROUTES.

### CONTENT-31 — unsafe message-body encoding handled by suppress/tighten + reissue, NOT mass conversion  `guardrail`
- **Setup:** A message v_bad transport/encoding flagged unsafe (e.g. an unbounded body length that breaks fixed-width admission). Store holds existing v1 tag-50 messages encoded safely; the unsafe encoding is being retired below natural expiry under the safety floor.
- **Action:** Apply the safety-floor retirement (drop the unsafe transport format) and trigger reissue/tighten.
- **Expect:** Only the unsafe transport format is removed (invariant 6 — removed before expiry ONLY when unsafe); existing safe v1 messages are NOT rewritten/converted — they keep their tag-50 reader forever; new safe messages are reissued under a safe tag. No bulk conversion pass over the message log.
- **Defends:** Invariant 6 (safety floor); invariant 5 (readers forever); charter "unsafe encoding handled by suppress/tighten/reissue not mass conversion."
- **Refs:** `content/message/encode.rs` CONTENT_MESSAGE_BYTES fixed-width admission, FACT_ROUTES, safety-floor rule.

### CONTENT-32 — global tag uniqueness holds when every content family gains a v2 sibling  `guardrail`
- **Setup:** Hypothetical head where each of the 7 content families plus `unfurl` has registered a distinct v2 tag (e.g. message_v2, reaction_v2, file_v2, file_slice_v2, file_deletion_v2, message_deletion_v2, retention_policy_v2, unfurl) in `FACT_ROUTES`, each with its own kept-forever projector and sibling `_v2/` dir.
- **Action:** Run the registry uniqueness test `fact_route_tags_are_globally_unique`.
- **Expect:** All `FactRoute.tag` values (the original 43 + the new v2 tags) are distinct u8s; no v2 tag collides with an existing content tag (50-55, 147) or any other scope's tag; each v1 and v2 family is 1:1 routed. The test passes.
- **Defends:** Versioning knob "incompatible wire shape => a NEW tag + new projector + sibling dir, in EVERY scope"; structural uniqueness.
- **Refs:** registry.rs 717-729 fact_route_tags_are_globally_unique, projector_routes! 593-624, FactRoute@402.

### CONTENT-33 — content count is computed at the ceiling (v2 facts uncounted below ceiling)  `blackbox-cli`
- **Setup:** Store with v1 content facts plus pending v2 content facts (message_v2, reaction_v2). Ceiling = N (below v2 intros).
- **Action:** Run `con content-count` and `con count`.
- **Expect:** Counts include only ceiling-active (v1) content facts; pending v2 facts are uncounted. After ceiling rises to cover v2 and a wipe+replay, the counts increase to include the now-active v2 facts.
- **Defends:** Admission "pending ... uncounted"; invariant 2 (count is a derivation surfaced at the ceiling).
- **Refs:** MATCH_COMMANDS content-count line 505 / count line (auth::workspace::cli), `content/message/cli.rs` content_count.

### CONTENT-34 — v1 content facts remain transportable to a still-usable older release while it speaks tag 50-55/147  `multinode-network`
- **Setup:** Node A (head, ceiling N+1, has v2 capabilities) and node B (older still-usable release, supports only v1 content tags). They sync.
- **Action:** A shares v1 content facts (message/reaction/file/file_slice/deletions/policy) and (separately) v2 facts with B.
- **Expect:** v1 facts (tags 50-55, 147) transport and project on B unchanged; A answers B in the request's (v1) version. A does NOT push v2 facts as ceiling-active to B's view (v2 not ceiling-active while B is in the fleet); A withholds v2 derivations. B is never asked to interpret a tag it cannot.
- **Defends:** Invariant 1 (ceiling-active transportable by every still-usable release); transport "answer in request's version"; invariant 3.
- **Refs:** sync::send_requested_fact, sync::share_fact_with_sync, ceiling = min over still-usable releases.
## 14. Auth authority cross-version (safety-critical)

This cluster proves that protocol versioning never widens, narrows, forges, or
re-anchors AUTHORITY. The authority-changing families are the eight that emit or
consume `auth_workspace` / `auth_user` / `auth_admin` / `auth_user_invite` /
`auth_device_invite` / `auth_invite_accepted` / `auth_endpoint_shared` /
`auth_invite_server` context offers and that materialize membership/admin rows:
`auth::workspace` (tag 131), `auth::user` (14), `auth::admin` (139),
`auth::user_invite` (10), `auth::device_invite` (134), `auth::invite_accepted`
(146), `auth::endpoint` (128, the local binding), `auth::endpoint_shared` (135).
The proposed (not-yet-existing) `user_profile_v2` is the worked example of a
new authority-adjacent family that must admit ONLY display changes. Tests are
grounded in the real projectors in `src/protocol/auth/*/project.rs`, the router
in `src/core/projectors.rs`, and the registry in `src/protocol/registry.rs`.

Convention used below: "ceiling-gated family" means a route whose
`intro_version` exceeds the active ceiling; a local create is REFUSED and a
received fact of that tag is PENDING (pending opaque, unprojected) per the
admission rule (`RouterProjector::project` Err path, projectors.rs:456). Where a
{new,old} version axis and a per-scope axis apply, each is a separate test.

---

### AUTHZ-01 — above-ceiling user fact (tag 14) is refused at local creation  `blackbox-cli`
- **Setup:** Single `con` node, workspace + root admin bootstrapped. Manifest pins the fleet ceiling at protocol N where `auth::user` route `intro_version = N+1` (a hypothetical reissue of tag 14's wire shape, sibling `user_v2/`). Trusted time fresh, not BLOCKED.
- **Action:** Run a `con` flow that would create an above-ceiling `auth::user` fact (the invite-accept path that submits a `UserFact` via `Runtime::submit_fact`, runtime.rs:268).
- **Expect:** Creation is REFUSED before submission; no `auth_user` context offer is published; `users` lists no new member; exit non-zero with an above-ceiling diagnostic.
- **Defends:** ADMISSION (local above-ceiling refused) + invariant (3) ceiling monotonicity — a client cannot mint membership the fleet cannot transport.
- **Refs:** `auth::user::project::UserProjector`, registry.rs `FACT_ROUTES`, runtime.rs:268, projectors.rs:456.

### AUTHZ-02 — received above-ceiling admin fact (tag 139) is pending, not granted  `multinode-network`
- **Setup:** Two nodes. Node B's ceiling is N; the `auth::admin` route on a hypothetical reissue carries `intro_version = N+1`. Node A (above-ceiling capable, alpha) sends a syntactically valid `auth::admin` fact tagged for the new shape.
- **Action:** A shares the fact over a connection; B's `ProtocolProjector` routes it.
- **Expect:** B retains it as opaque bytes (NOT dropped, NOT errored to the user), it is unprojected/undisplayed; no `admin` row is written; `grant-admin`-derived authority for that target does NOT appear; the actor set on B is unchanged.
- **Defends:** ADMISSION pending + invariant (1)/(3) — an unsupported client must not admit a different actor set.
- **Refs:** `auth::admin::project::AdminProjector`, `RouterProjector` (projectors.rs:423), unknown-tag Err (projectors.rs:456).

### AUTHZ-03 — pending authority fact ACTIVATES on wipe+replay after ceiling rises  `replay-cli`
- **Setup:** Node B from AUTHZ-02 holding the pending above-ceiling `auth::admin` fact. A new signed manifest raises B's ceiling to cover `intro_version = N+1`; trusted_time advanced past `blocker.expires_at + M`.
- **Action:** Wipe derived state and replay all retained facts (the historical adapter keyed by the fact's OWN tag).
- **Expect:** The formerly pending admin fact now projects via its `v_{N+1}` adapter; the `admin` row materializes and the target gains admin authority — but only after the ceiling rose. The pre-rise state had NO such authority.
- **Defends:** ADMISSION activation-on-replay + invariant (4) replay determinism (ceiling-independent per-tag adapter).
- **Refs:** `auth::admin::project`, version-bucket `project/v_{N+1}`, projectors.rs:489 `project_typed`.

### AUTHZ-04 — each authority-changing family is independently ceiling-gated  `guardrail`
- **Setup:** Registry-level test enumerating the eight authority-changing routes (tags 131,14,139,10,134,146,128,135) with synthetic `intro_version` above ceiling, one family at a time.
- **Action:** For each, attempt local creation at a ceiling below that family's intro_version while the other seven stay at/below ceiling.
- **Expect:** ONLY the gated family is refused; the other seven still create normally. No family's gating bleeds into another (per-family isolation). Tag uniqueness still holds (`fact_route_tags_are_globally_unique`, registry.rs:717-729).
- **Defends:** ADMISSION per-family gating; invariant (3).
- **Refs:** `FACT_ROUTES` in registry.rs, all eight `auth::*::project` modules.

### AUTHZ-05 — user_profile_v2 admits ONLY when auth_user anchor and signer endpoint_shared share one workspace  `handler-unit`
- **Setup:** Proposed `auth::user_profile_v2` family present at/below ceiling. Construct a profile fact whose `auth_user` anchor (subject) is in workspace W1 but whose signer `endpoint_shared` is in workspace W2.
- **Action:** Project the profile fact with both context dependencies satisfied.
- **Expect:** REFUSED with a workspace-mismatch error (mirrors `endpoint_shared` workspace checks at project.rs:149/161). No profile row written; no display change.
- **Defends:** user_profile_v2 same-workspace anchor rule (charter clause 2).
- **Refs:** modeled on `auth::endpoint_shared::project` workspace guards; `auth::user::project` `auth_user` offer.

### AUTHZ-06 — user_profile_v2 requires endpoint_shared to PROVE the subject (user_authority_fact_id == subject_user_id)  `handler-unit`
- **Setup:** profile fact in workspace W; signer `endpoint_shared` is valid in W but its `user_authority_fact_id` names a DIFFERENT user than the profile's subject `user_fact_id`.
- **Action:** Project with workspace, subject `auth_user`, and signer `auth_endpoint_shared` context present.
- **Expect:** REFUSED — the signer does not prove the subject; no row, no display mutation.
- **Defends:** user_profile_v2 subject-proof rule (`user_authority_fact_id == subject_user_id`).
- **Refs:** `EndpointSharedFact.user_authority_fact_id` (endpoint_shared/fact.rs:49), `auth::user::project`.

### AUTHZ-07 — user_profile_v2 signer key must match the endpoint_shared signing key  `handler-unit`
- **Setup:** profile fact whose `signer_public_key` differs from the matched `endpoint_shared.signing_public_key` (same workspace, correct subject).
- **Action:** Project the profile fact.
- **Expect:** REFUSED with signer-key-mismatch (mirrors device_invite project.rs:158 / user_invite project.rs:128). No materialization.
- **Defends:** user_profile_v2 signer-key-match rule.
- **Refs:** `endpoint_shared::layout::verify_signature`, `EndpointSharedFact.signing_public_key`.

### AUTHZ-08 — user_profile_v2 admits and changes DISPLAY data only — never membership/admin/key/subject id  `projector-unit`
- **Setup:** A fully valid `user_profile_v2` (same-workspace anchor, subject proven, signer key matches), carrying a new display name / avatar field.
- **Action:** Project it, then dump the resulting read-model rows and authority context offers.
- **Expect:** Profile/display row updates; the `user` row's `public_key`, `user_invite_id`, and the subject `user_fact_id` are UNCHANGED; no `admin` row, no `auth_user`/`auth_admin` offer is emitted or revoked; membership set unchanged.
- **Defends:** user_profile_v2 display-only rule — cannot alter membership, admin authority, original user key, or subject id.
- **Refs:** `auth::user::layout::encode_row_value` (public_key/user_invite_id/username), `auth::admin::rows::admin_row`.

### AUTHZ-09 — user_profile_v2 cannot rewrite the original user key or re-anchor the subject  `handler-unit`
- **Setup:** A profile fact that attempts to carry a replacement `public_key` for the subject user, or a different `subject_user_id` than the proving endpoint_shared's `user_authority_fact_id`.
- **Action:** Project it.
- **Expect:** REFUSED (or the key/subject fields ignored such that the original `auth::user` row's `public_key` and id remain authoritative). Authority graph (admin/user/invite edges) is bit-for-bit identical before and after.
- **Defends:** user_profile_v2 immutability of original user key + subject id.
- **Refs:** `auth::user::project` (the `auth_user` offer is `fact.id..fact.id`), `auth::admin::project_delegated_admin` user-key match (project.rs:157).

### AUTHZ-10 — old user adapter rejects a malformed old user fact but never grants NEW authority  `replay-cli`
- **Setup:** Retained `auth::user` fact at the historical (old) tag wire shape, deliberately corrupted (e.g. non-canonical username padding per layout.rs:166, or a signature that fails `verify_signature`).
- **Action:** Wipe+replay routes it to the old per-tag historical adapter.
- **Expect:** The old adapter returns Err (rejects the malformed fact) and emits NO `auth_user` offer and NO user row; it does NOT silently upgrade it to a new-version authority grant. Replay continues for other facts.
- **Defends:** "old adapter may reject malformed old facts but must NOT grant new authority"; invariant (4)/(5).
- **Refs:** `auth::user::layout::decode_fact`/`verify_signature`, `auth::user::project::UserProjector`.

### AUTHZ-11 — old admin adapter rejecting a malformed grant does not fabricate a delegated-admin edge  `projector-unit`
- **Setup:** Retained old-shape `auth::admin` fact whose `signer_id != authority_fact_id` (violates project.rs:133) replayed through its historical adapter.
- **Action:** Project via the old adapter.
- **Expect:** Err ("signed admin grant signer must be the authority admin"); no `admin` row; no `auth_admin` global or workspace-scoped offer. The historical adapter cannot grant authority a new adapter would have. Actor set unchanged.
- **Defends:** old adapter rejects-but-never-grants; cross-version authority containment.
- **Refs:** `auth::admin::project_delegated_admin` (project.rs:116-165).

### AUTHZ-12 — purging an auth_user anchor while a device_invite names it is refused without an authority-preserving tombstone  `blackbox-cli`
- **Setup:** Workspace with `auth::user` U (offers `auth_user` over `U.id..U.id`) and a `auth::device_invite` D whose `user_authority_fact_id == U.id` (user-signed path, project.rs:102). No tombstone present.
- **Action:** Attempt a purge that would physically remove U's bytes (a content-style purge coordinate targeting U).
- **Expect:** REFUSED — U is an authority anchor still named by D; the purge handler does not remove it because no authority-preserving tombstone covers the dependents. D still validates on replay (its `auth_user` need is satisfiable).
- **Defends:** authority-anchor non-purgeability (charter clause: purging auth_user while dependents name it refused).
- **Refs:** `content/purge/project.rs` (`target_purged_need`, no auth authorization here), `auth::device_invite::project_user_signed` `auth_user` need.

### AUTHZ-13 — purging an auth_user anchor with an authority-preserving tombstone present is allowed  `blackbox-cli`
- **Setup:** Same as AUTHZ-12 but a tombstone fact exists that preserves U's authority binding (the dependents can still resolve their `auth_user` need from the tombstone, not the purged bytes).
- **Action:** Run the purge.
- **Expect:** U's canonical bytes may be removed; D and any admin/user_invite naming U still project deterministically on replay via the preserved tombstone; authority edges unchanged.
- **Defends:** non-purgeability is conditional on a preserving tombstone (the safe path).
- **Refs:** `content/purge/project.rs`, `auth::removal_frontier` / tombstone-bearing auth facts, invariant (4).

### AUTHZ-14 — purging the workspace anchor (tag 131) while admin/user_invite name it is refused  `blackbox-cli`
- **Setup:** Workspace W (offers `auth_workspace` over `W.id..W.id`); a bootstrap `auth::admin` and a bootstrap `auth::user_invite` both `need` `auth_workspace` ranged at W.id (admin project.rs:174, user_invite project.rs:161).
- **Action:** Attempt to purge W without a preserving tombstone.
- **Expect:** REFUSED; W remains; dependents keep resolving their `auth_workspace` need.
- **Defends:** authority-anchor non-purgeability for the workspace scope specifically.
- **Refs:** `auth::workspace::project` (the sole `auth_workspace` offer), `auth::admin`/`auth::user_invite` workspace needs.

### AUTHZ-15 — purging an auth_admin anchor while a delegated grant or user_invite names it is refused  `blackbox-cli`
- **Setup:** Admin A1 (root) grants delegated admin A2 (A2.authority_fact_id == A1.id); a delegated `auth::user_invite` names A1 as its `authority_fact_id` (user_invite project.rs:191).
- **Action:** Attempt to purge A1's `auth::admin` fact without a preserving tombstone.
- **Expect:** REFUSED; A2 and the user_invite keep resolving their `auth_admin` need on replay.
- **Defends:** non-purgeability for the admin authority scope.
- **Refs:** `auth::admin::DelegatedAdminNeeds.authority`, `auth::user_invite::EndpointAdminNeeds.admin`.

### AUTHZ-16 — an unsafe auth fact VERSION is suppressed/tightened while historical facts of safe versions stay valid  `replay-cli`
- **Setup:** Two retained `auth::endpoint_shared` facts: E_old at a SAFE historical wire version, E_bad at a version later flagged UNSAFE (security-deprecated in the manifest). Ceiling excludes the unsafe version.
- **Action:** Wipe+replay.
- **Expect:** E_old projects normally (row + `content_signer`/`auth_endpoint_shared` offers); E_bad is suppressed/refused (its version is unsafe) and grants NO authority. Only the unsafe version is suppressed; the safe historical version is untouched.
- **Defends:** "unsafe auth fact version suppressed/tightened while historical facts stay valid unless that version is unsafe"; invariant (6) safety floor.
- **Refs:** `auth::endpoint_shared::project`, manifest security-deprecation, invariant (6).

### AUTHZ-17 — a NON-unsafe old auth version is NEVER removed before natural expiry  `guardrail`
- **Setup:** Manifest where an old `auth::user_invite` (tag 10) transport version is merely below head but NOT flagged unsafe, and still spoken by a still-usable release.
- **Action:** Compute the active reader/transport set.
- **Expect:** The old version's READER stays registered forever; its transport stays in `[floor,head]`; it is NOT dropped just for being old. Historical user_invite facts of that version still admit and grant.
- **Defends:** invariant (5) readers-forever / (6) safety-floor (removal only when unsafe).
- **Refs:** `auth::user_invite::project`, `FACT_ROUTES` reader registration (kept forever).

### AUTHZ-18 — grant-admin across versions: deny when ceiling lacks the new admin shape  `blackbox-cli`
- **Setup:** Node at ceiling N. `grant-admin` CLI command's highest `intro_version <= N` run-fn produces the old `auth::admin` shape; a hypothetical N+1 admin shape exists but ceiling is N.
- **Action:** `con grant-admin WORKSPACE_ID_HEX USER_ID_HEX`.
- **Expect:** The command emits an OLD-shape admin fact (selected by ceiling, not head), it admits, and the grant is visible. It does NOT emit the above-ceiling N+1 shape. Admin authority is granted exactly as the old shape encodes it.
- **Defends:** CliCommand ceiling-selects highest intro_version<=ceiling; invariant (2) render-at-ceiling.
- **Refs:** `grant_admin` (admin/cli.rs:14), `MATCH_COMMANDS` entry 34, `auth::admin::commands::grant_admin`.

### AUTHZ-19 — grant-admin run-fn bucket ABSENT at N reuses previous under param-subset contract  `blackbox-cli`
- **Setup:** A protocol bump from N to N+1 that changes the admin WIRE shape but NOT the `grant-admin` input surface (still `WORKSPACE_ID_HEX USER_ID_HEX`); the `grant-admin` cli bucket has no N+1 entry.
- **Action:** Run `con grant-admin ...` at ceiling N+1.
- **Expect:** The previous run-fn is reused (absent bucket => reuse prev); its `required_inputs` ⊆ the collected params; the command succeeds and produces the N+1 fact via the shared collect path. No "missing command version" error.
- **Defends:** CLI absent-bucket reuse + param-subset contract.
- **Refs:** `MATCH_COMMANDS` grant-admin, admin/cli.rs `GRANT_ADMIN_USAGE`.

### AUTHZ-20 — invite across versions: bootstrap user_invite admits at ceiling, above-ceiling reissue refused  `blackbox-cli`
- **Setup:** Root workspace. Ceiling N covers the existing `auth::user_invite` (tag 10). A reissued user_invite shape at intro_version N+1 is above ceiling.
- **Action:** (a) `con invite ...` producing the ceiling-era bootstrap user_invite; (b) attempt to locally create the N+1 reissue.
- **Expect:** (a) succeeds — workspace-signed invite admits, `auth_user_invite` offer published; (b) refused as above-ceiling. The two are distinguished by tag/route, not by an internal version byte.
- **Defends:** ADMISSION (local above-ceiling refused) for the invite family; invariant (1).
- **Refs:** `auth::user_invite::project_workspace_signed`, `MATCH_COMMANDS` `invite`.

### AUTHZ-21 — accept across versions: invite_accepted is local-scope and must match the invite_secret at ceiling  `handler-unit`
- **Setup:** Local `auth::invite` secret fact present; build an `auth::invite_accepted` (tag 146) referencing it. Ceiling covers tag 146.
- **Action:** Project the invite_accepted fact.
- **Expect:** Admits only if scope==Local and `bootstrap_hash`/`workspace_id`/`invite_fact_id` all match the secret (project.rs:47-87); an above-ceiling invite_accepted reissue would instead be pending. No NEW authority is granted by acceptance itself (it only writes the local acceptance row).
- **Defends:** accept-path version handling; acceptance never widens authority.
- **Refs:** `auth::invite_accepted::project::InviteAcceptedProjector` (local-only), `auth::invite::decode_fact_payload`.

### AUTHZ-22 — device_invite endpoint-signed path: ceiling-gated, no cross-workspace authority leak across versions  `multinode-network`
- **Setup:** Two nodes at ceiling N. Node A sends an `auth::device_invite` (endpoint-signed path, `user_invite_fact_id == None`, project.rs:137) whose signer `endpoint_shared` is in a DIFFERENT workspace than the invite's `workspace_id`.
- **Action:** B projects it.
- **Expect:** REFUSED ("endpoint_shared-signed device_invite workspace does not match signer", project.rs:164). No `auth_device_invite` offer; no row. Cross-version transport does not relax this same-workspace check.
- **Defends:** authority-changing family cross-version safety (no different actor set); invariant (1).
- **Refs:** `auth::device_invite::project_endpoint_signed`, `endpoint_shared/fact.rs`.

### AUTHZ-23 — endpoint_shared device path: user_authority_fact_id must match device_invite across versions  `projector-unit`
- **Setup:** `auth::endpoint_shared` (Device role) whose `user_authority_fact_id` differs from the matched `device_invite.user_authority_fact_id` (project.rs:152). Family at/below ceiling, replayed via historical adapter.
- **Action:** Project the endpoint_shared fact.
- **Expect:** REFUSED ("endpoint_shared user authority does not match device_invite"). No `content_signer` or `auth_endpoint_shared` offer; the endpoint gains no authority. Holds identically whether projected live or under wipe+replay.
- **Defends:** endpoint authority binding integrity across versions; invariant (4).
- **Refs:** `auth::endpoint_shared::has_valid_authority` (Device branch, project.rs:139-155).

### AUTHZ-24 — endpoint_shared invite-server path: signer_id must equal user_authority_fact_id  `projector-unit`
- **Setup:** `auth::endpoint_shared` (InviteServer role) where `signer_id != user_authority_fact_id` (project.rs:167), authority `invite_server` context present.
- **Action:** Project it.
- **Expect:** REFUSED ("endpoint_shared user authority does not match invite_server"). No authority offer emitted. (Distinct scope from the Device path in AUTHZ-23 — enumerated separately.)
- **Defends:** invite-server endpoint binding integrity; per-role authority rule.
- **Refs:** `auth::endpoint_shared::has_valid_authority` (InviteServer branch, project.rs:158-170).

### AUTHZ-25 — bootstrap admin path: new version cannot let workspace key grant a NON-root admin  `handler-unit`
- **Setup:** `auth::admin` with `authority_fact_id == workspace_id` (bootstrap branch) but `user_fact_id != workspace_id` (project.rs:99) — i.e. trying to use the root key to grant admin to an arbitrary user directly.
- **Action:** Project via any version's adapter.
- **Expect:** REFUSED ("workspace admin authority can only bootstrap root admin"). No row. No version of the adapter may relax this; the bootstrap path admits ONLY the self-grant root admin.
- **Defends:** bootstrap-admin authority containment across versions.
- **Refs:** `auth::admin::project_bootstrap_admin` (project.rs:85-114).

### AUTHZ-26 — rendering uniformity: two supported clients at protocol N render identical admin/user rows regardless of release/platform  `multinode-network`
- **Setup:** Two `con` nodes at the SAME protocol N but different releases/platforms; both hold the same retained auth facts (workspace, root admin, one delegated admin, two users).
- **Action:** On each, run `users` and the admin listing; diff the read-model row CONTENT.
- **Expect:** Byte-identical authority rows (membership, admin grants, user public keys/invite ids). Only presentation chrome may differ. Neither renders a head-only derivation above the ceiling.
- **Defends:** invariant (2) rendering uniformity for the authority read-model; render-at-ceiling.
- **Refs:** `auth::user::rows`/`queries`, `auth::admin::rows`, `auth::workspace::queries`.

### AUTHZ-27 — replay determinism: authority graph is identical under reverse/scramble fact order  `replay-cli`
- **Setup:** A workspace whose authority graph spans all eight families (workspace -> bootstrap user_invite -> user -> endpoint_shared -> device_invite -> delegated user_invite -> delegated admin -> invite_accepted). Retained fact set fixed.
- **Action:** Wipe+replay forward; wipe+replay reverse; wipe+replay scrambled (the cascade test harness `test-replay-deps-reverse` is the existing analogue) — each rebuilding via per-tag historical adapters and context needs/offers.
- **Expect:** Identical final authority rows and offers in all three orders (context needs defer non-ready facts until anchors resolve). No order grants or drops an edge.
- **Defends:** invariant (4) order-independent, ceiling-independent replay for authority.
- **Refs:** context `need`/`offer` deferral across all `auth::*::project`; `sync::cascade_test_fact::cli` (`replay_deps_reverse`).

### AUTHZ-28 — BLOCKED MODE withholds new authority sharing but still serves local authority reads and replay  `blackbox-cli`
- **Setup:** Node whose trusted-time staleness window S has elapsed without a manifest refresh (or a backward clock rollback beyond tolerance) -> BLOCKED MODE.
- **Action:** (a) attempt to share a freshly created `auth::admin`/`auth::user` fact to peers; (b) run `users`/`workspaces` reads; (c) wipe+replay.
- **Expect:** (a) shared production is WITHHELD (the new authority fact is not advertised to peers); (b) local authority reads still succeed; (c) replay still rebuilds the authority graph from retained facts.
- **Defends:** TRUSTED TIME / BLOCKED MODE — withhold shared production, keep local reads + replay; authority safety under stale time.
- **Refs:** ceiling/trusted-time gate; `share_fact_with_sync` (the offer path each auth projector calls).

### AUTHZ-29 — above-ceiling authority fact is NOT errored to the operator (no projectors.rs:456 crash leak)  `handler-unit`
- **Setup:** Received `auth::endpoint_shared` fact tagged for an above-ceiling reissue (tag present in a future bucket, route not yet active at this ceiling).
- **Action:** Feed it through `ProtocolProjector`/`RouterProjector`.
- **Expect:** Under the pending model it is pending opaque and NOT surfaced as an error; it must NOT take the current "no target projector registered for fact tag" hard-Err path (projectors.rs:456) that today errors. The fact is uncounted in `content-count`/peer listings.
- **Defends:** ADMISSION pending semantics vs. today's hard error; invariant (1) (an above-ceiling fact must not crash a supported client).
- **Refs:** `RouterProjector::project` Err (projectors.rs:456), `connection::frame_observation` retention path.

### AUTHZ-30 — old auth transport version dropped sub-floor; expired peer gets no recovery responder  `multinode-network`
- **Setup:** Peer P speaks only an `auth::user_invite` transport version BELOW the operational floor (its release expired). Local node's floor excludes it.
- **Action:** P attempts to push/pull auth facts; local node negotiates transport.
- **Expect:** No sub-floor transport is offered; there is NO recovery responder for the expired peer (update is out-of-band). Local authority data stays safe and intact; after P updates and replays, it resyncs normally. Authority is never granted via a sub-floor transport.
- **Defends:** invariant (5) transport in `[floor,head]`, expired-peer-out, local-data-safe.
- **Refs:** transport negotiation (`send_facts_on_connection`, `share_fact_with_sync`), floor gate; `auth::user_invite` family.
## 15. Auth key material cross-version (forward secrecy)

Scope grounding (verified against `/home/holmes/poc-10/src`): the auth key-material
families are `auth::recipient_key` (tag 150, `RecipientKeyProjector`),
`auth::removal_frontier` (151, `RemovalFrontierProjector`),
`auth::local_key_secret` (152, `LocalKeySecretProjector`),
`auth::local_history_node_secret` (153, `LocalHistoryNodeSecretProjector`),
`auth::key_request` (154, `KeyRequestProjector`), `auth::key_wrap` (155,
`KeyWrapProjector`), `auth::local_recipient_key` (156, `LocalRecipientKeyProjector`),
`auth::local_secret_retirement` (157, `LocalSecretRetirementProjector`),
`auth::local_signer_secret` (133, `LocalSignerSecretProjector`). The two key
handlers are `create_key_wrap` (`CreateKeyWrapHandler`, `auth::create_key_wrap`)
and `unwrap_key_wrap` (`UnwrapKeyWrapHandler`, `auth::unwrap_key_wrap`); pure
constructors live in `auth/key_wrap/create.rs`
(`create_key_wrap_fact`, `create_validated_key_wrap_fact`, `unwrap_key_wrap_fact`,
`admit_key_wrap_fact`). The deterministic wrap key derives a sender x25519 secret
and nonce via `blake3_keyed_hash` over `deterministic_wrap_info` (purposes
`b"topo key wrap sender x25519 v1"` / `b"topo key wrap nonce v1"`,
`KEY_WRAP_PURPOSE = b"topo key wrap v1"`). Wrap-source coordinates and the shared
signer/scope helpers live in `auth/key_wrap/project.rs`
(`WrapSourceKind::{FrontierRoot,HistoryNode}`, `matching_wrap_sources_with_signer`,
`proactive_wrap_source_need`, `requested_wrap_source_need`). The CLI surface is
`auth::key_wrap::cli` (`key-recipient`, `key-rotate-recipient`->`key_recipient_rotation`,
`key-frontier`, `key-wrap`, `key-access`, `key-derive`, `key-node`, `keys`, `chop-now`).
Retirement context role is `local_secret_source_retired`; the only supported
reason is `RETIRE_REASON_CHOP = 1` (`local_secret_retirement/layout.rs`).

NOTE ON VERSIONING SUBSTRATE: today `FactRoute { tag, projector }`
(`projectors.rs:402`) carries NO `intro_version` and `FACT_ROUTES`
(`registry.rs:593` via `projector_routes!`) is NOT ceiling-filtered; there is no
`ReleaseManifestEntry`/ceiling code in `src`. The "{new,old} version" axis below
is therefore expressed against the consolidated model: a redesign = a NEW tag +
NEW kept-forever projector + a sibling `_vN/` directory, gated by ceiling
activation, with the OLD tag-150..157/133 projectors retained forever
(invariant 5). Tests are written so the structural/guardrail ones run today and
the cross-version ones state the expected behavior the model must preserve.

### KEYS-01 — old key_wrap/recipient_key/key_request adapters retained forever after a redesign  `guardrail`
- **Setup:** working tree at the consolidated-model checkpoint where a TreeKEM/key-wrap REDESIGN has shipped: new tags exist for `auth::key_wrap_v2`/`auth::recipient_key_v2`/`auth::key_request_v2` with sibling `key_wrap/_v2/`, `recipient_key/_v2/`, `key_request/_v2/` directories.
- **Action:** assert the original projector routes are still present in `FACT_ROUTES` (`registry.rs:593`): `project_auth_key_wrap => TYPE_KEY_WRAP (155)`, `project_auth_recipient_key => TYPE_RECIPIENT_KEY (150)`, `project_auth_key_request => TYPE_KEY_REQUEST (154)`, alongside the new v2 routes.
- **Expect:** all six routes coexist; `fact_route_tags_are_globally_unique` (registry.rs:717-729) still passes (v1 tags 150/154/155 distinct from the new v2 tags); no v1 route is deleted or repointed at a v2 projector.
- **Defends:** invariant 5 (readers forever) + the redesign-is-additive rule (new tag + new kept-forever projector + `_vN/` dir).
- **Refs:** `src/protocol/registry.rs` (`projector_routes!`, `FACT_ROUTES`, `fact_route_tags_are_globally_unique`), `src/protocol/auth/{key_wrap,recipient_key,key_request}/`.

### KEYS-02 — redesigned key-wrap family is a ceiling-gated NEW family, old adapters untouched  `guardrail`
- **Setup:** a new key-wrap protocol bundle `protocol N+1 = protocol N + {key_wrap:2, recipient_key:2, key_request:2}` introduced behind a fleet ceiling; current still-usable releases sit at protocol N.
- **Action:** with ceiling = N, attempt local creation of a `key_wrap_v2` fact via the new `key-wrap` v2 run-fn bucket entry.
- **Expect:** local creation of the above-ceiling `key_wrap_v2` fact is REFUSED (admission rule); the v1 `KeyWrapProjector`/`create_validated_key_wrap_fact` path remains active and produces v1 tag-155 wraps. No v1 adapter behavior changes.
- **Defends:** admission (local above-ceiling refused) + CEILING-ACTIVE gating of the new family; invariant 5 (old adapters retained).
- **Refs:** `auth/create_key_wrap.rs`, `auth/key_wrap/create.rs::create_validated_key_wrap_fact`, `auth/key_wrap/_v2/` (model), `registry.rs` MATCH_COMMANDS `key-wrap`.

### KEYS-03 — received above-ceiling key_wrap_v2 fact is pending, not errored or dropped  `handler-unit`
- **Setup:** node at ceiling N (no `key_wrap_v2` projector route active); peer sends a `key_wrap_v2`-tagged fact (new redesign tag).
- **Action:** the fact is received and offered to the router (`RouterProjector::project`).
- **Expect:** the fact is RETAINED as opaque bytes (pending), undisplayed/uncounted/unprojected, NOT dropped and NOT surfaced as a hard error to the user. (Today the same path ERRORS at `projectors.rs:456` "no target projector registered for fact tag {tag}" — the test pins that the model must convert this to pending for the redesigned key family.)
- **Defends:** admission pending semantics for received above-ceiling key material; invariant 1.
- **Refs:** `src/core/projectors.rs` (`RouterProjector::project` @423, Err @456), `auth/key_wrap/_v2/` (model).

### KEYS-04 — pending key_wrap_v2 activates on wipe+replay once ceiling rises  `replay-cli`
- **Setup:** node with a pending `key_wrap_v2` fact (from KEYS-03), then a signed manifest refresh raises the ceiling to N+1 covering the `key_wrap:2` tag.
- **Action:** `con` wipe + replay (full rebuild) at the new ceiling.
- **Expect:** the previously-pending `key_wrap_v2` fact now routes to the v2 projector, materializes its `key_wrap_rows` row and (if local recipient material exists) emits an `unwrap_key_wrap` intent — i.e. it activates. Every other retained fact replays via the adapter keyed by its OWN tag (150..157 via v1 projectors).
- **Defends:** invariant 4 (replay determinism; each fact replays via its own-tag adapter) + pending-activation-on-ceiling-rise.
- **Refs:** `src/core/projectors.rs` RouterProjector, `auth/key_wrap/_v2/project.rs` (model), `auth/key_wrap/project.rs::key_wrap`.

### KEYS-05 — create_key_wrap recreates the identical deterministic wrap on replay  `replay-cli`
- **Setup:** single `con` node that has run `key-frontier`, `key-recipient`, so a `local_key_secret` (FrontierRoot source) + `recipient_key` + `local_signer_secret` + `removal_frontier` all exist; projection has already emitted a `create_key_wrap` intent and the handler produced a tag-155 `key_wrap` fact with id K.
- **Action:** wipe the derived state and replay all retained facts.
- **Expect:** projection re-emits the SAME `create_key_wrap_intent` (same idempotence key from `create_key_wrap_key`), the handler re-derives the SAME `sender_wrap_public_key`/`nonce`/`ciphertext` (blake3 over identical `deterministic_wrap_info`), and the rebuilt `key_wrap` fact id == K. No new/duplicate wrap appears.
- **Defends:** invariant 4 (recreates only deterministic facts) + create_key_wrap determinism.
- **Refs:** `auth/key_wrap/create.rs::{create_key_wrap_fact,deterministic_sender_wrap_secret,deterministic_nonce,deterministic_wrap_info}`, `auth/recipient_key/project.rs` (intent emission), `auth/create_key_wrap.rs::create_key_wrap_key`.

### KEYS-06 — create_key_wrap refuses to fabricate a wrap when the local source secret is absent  `handler-unit`
- **Setup:** recipient_key + removal_frontier + local_signer_secret present, but the `local_key_secret` (FrontierRoot wrap source) has been purged/never existed; an attacker-style `create_key_wrap` intent names a `source_fact_id` that is not in the fact store.
- **Action:** invoke `CreateKeyWrapHandler::handle` (via `input_fact_ids` then `handle`).
- **Expect:** `context.require_fact(&input.source_fact_id)` fails → handler returns Err; NO `key_wrap` fact is emitted. Key material is never fabricated from nothing.
- **Defends:** "create_key_wrap recreates wraps ONLY when local source + signer material exist; never fabricates missing key material."
- **Refs:** `auth/create_key_wrap.rs::CreateKeyWrapHandler::{input_fact_ids,handle}`, `core/intents.rs::HandlerContext::require_fact`.

### KEYS-07 — create_key_wrap refuses when local signer secret is absent  `handler-unit`
- **Setup:** recipient_key + removal_frontier + `local_key_secret` (root source) present, but the `local_signer_secret` for the source's `owner_endpoint_id` is absent; intent names a `signer_secret_fact_id` not in store.
- **Action:** invoke `CreateKeyWrapHandler::handle`.
- **Expect:** `context.require_fact(&input.signer_secret_fact_id)` fails → Err; no wrap emitted. Even though source secret exists, missing signer material blocks fabrication.
- **Defends:** "ONLY when local source + signer material exist."
- **Refs:** `auth/create_key_wrap.rs::CreateKeyWrapHandler::handle`, `auth/key_wrap/create.rs::create_validated_key_wrap_fact` (signer match check).

### KEYS-08 — create_validated_key_wrap rejects a signer secret that does not match the wrap signer  `handler-unit`
- **Setup:** all three context facts present, but the supplied `local_signer_secret` belongs to a different endpoint than the source secret's `owner_endpoint_id` (which becomes `key_wrap.signer_endpoint_id`).
- **Action:** call `create::create_validated_key_wrap_fact(&intent, recipient, source, signer_secret)`.
- **Expect:** Err "signer secret does not match key wrap signer"; no wrap fact returned. Mismatched signer material cannot mint a wrap.
- **Defends:** signer-binding of created wraps (never fabricates with the wrong signer).
- **Refs:** `auth/key_wrap/create.rs::create_validated_key_wrap_fact` (`signer.signer_id != key_wrap.signer_endpoint_id`).

### KEYS-09 — create_key_wrap rejects empty/zero recipient public key material  `handler-unit`
- **Setup:** intent + source + signer present; recipient_key fact decodes but its `recipient_key` field is all zero bytes.
- **Action:** call `create::create_key_wrap_fact`.
- **Expect:** Err "recipient key material cannot be empty"; no wrap. Prevents minting a wrap to a degenerate/empty recipient key.
- **Defends:** never fabricate key material toward an empty recipient.
- **Refs:** `auth/key_wrap/create.rs::create_key_wrap_fact` (`recipient.recipient_key.iter().all(|b| *b == 0)`).

### KEYS-10 — unwrap_key_wrap creates the deterministic LOCAL secret fact (FrontierRoot)  `handler-unit`
- **Setup:** a tag-155 `key_wrap` fact W with `wrapped_secret_kind = FrontierRoot`; matching `local_recipient_key`, `recipient_key`, `removal_frontier` present; the `unwrap_key_wrap` intent emitted by `KeyWrapProjector` (because a local recipient existed).
- **Action:** invoke `UnwrapKeyWrapHandler::handle`.
- **Expect:** decrypt succeeds (`x25519_xchacha20poly1305_decrypt`), and a `local_key_secret` fact is produced with workspace/frontier/owner/created_at copied from the wrap, and its id == `wrap.wrapped_secret_id` (else Err "unwrapped secret fact id does not match key wrap target"). Output is FactScope::Local.
- **Defends:** "unwrap_key_wrap creates deterministic local secret facts" (root path).
- **Refs:** `auth/unwrap_key_wrap.rs::UnwrapKeyWrapHandler::handle`, `auth/key_wrap/create.rs::{unwrap_key_wrap_fact,root_secret_fact}`.

### KEYS-11 — unwrap_key_wrap creates the deterministic LOCAL secret fact (HistoryNode)  `handler-unit`
- **Setup:** a `key_wrap` W with `wrapped_secret_kind = HistoryNode` carrying range_start/range_width/bit_depth/fact_id_prefix and `wrapped_source_secret_id`/`wrapped_tombstone_node_id`; matching local recipient + recipient + frontier present.
- **Action:** invoke `UnwrapKeyWrapHandler::handle`.
- **Expect:** a `local_history_node_secret` fact is produced via `history_secret_fact`, copying the coordinate + source/tombstone ids; its id == `wrap.wrapped_secret_id`. FactScope::Local.
- **Defends:** "unwrap_key_wrap creates deterministic local secret facts" (history-node path); deterministic across kinds.
- **Refs:** `auth/key_wrap/create.rs::{unwrap_key_wrap_fact,history_secret_fact}`, `auth/local_history_node_secret/`.

### KEYS-12 — unwrap_key_wrap rejects a local recipient key that does not match the wrap's recipient  `handler-unit`
- **Setup:** key_wrap W targets `recipient_key_id` R; the supplied `local_recipient_key` decodes but its `recipient_key` public component differs from the shared `recipient_key` fact's `recipient_key`.
- **Action:** call `create::unwrap_key_wrap_fact(&intent, W, local_recipient, recipient, frontier)`.
- **Expect:** Err "local recipient key public key does not match recipient"; no local secret fact produced.
- **Defends:** unwrap binds the local private material to the exact shared recipient (no cross-recipient unwrap).
- **Refs:** `auth/key_wrap/create.rs::require_local_recipient_key`.

### KEYS-13 — unwrap_key_wrap rejects a signer that does not own the removal frontier  `handler-unit`
- **Setup:** key_wrap W with `signer_endpoint_id = S`; supplied `removal_frontier` fact has `owner_endpoint_id != S`.
- **Action:** call `create::unwrap_key_wrap_fact`.
- **Expect:** Err "key wrap signer does not own unwrap frontier"; no secret produced. Decryption only proceeds under a frontier the wrap signer owns.
- **Defends:** frontier-binding of unwrap; deterministic-only when the full chain validates.
- **Refs:** `auth/key_wrap/create.rs::unwrap_key_wrap_fact` (frontier owner check).

### KEYS-14 — unwrap does NOT resurrect an already-opened secret that has been retired/purged  `replay-cli`
- **Setup:** a `local_key_secret` L was created by a prior unwrap, then retired via a `local_secret_retirement` (reason CHOP) which caused `LocalKeySecretProjector` to `purge_self`. The originating `key_wrap` W and the retirement fact are both still retained.
- **Action:** wipe + replay all retained facts (W, retirement, local recipient, recipient, frontier).
- **Expect:** the `unwrap_key_wrap` intent re-runs and re-produces L, but `LocalKeySecretProjector::project_local_key_secret` sees the standing `local_secret_source_retired` context for L's id FIRST and immediately returns `purge_self(fact.id)` — L is NOT re-offered as a live `local_secret_source`/wrap-source and stays purged. Forward-secrecy hole closed even though the wrap survives.
- **Defends:** "unwrap respects purge/retirement, never resurrecting an opened secret"; invariant 4 ordering-independence (retirement check precedes materialize).
- **Refs:** `auth/local_key_secret/project.rs` (retirement_need check before materialize), `auth/local_secret_retirement/`, `auth/unwrap_key_wrap.rs`.

### KEYS-15 — history-node secret stays purged on replay after retirement (forward secrecy)  `replay-cli`
- **Setup:** a `local_history_node_secret` H opened by unwrap, then retired (either an explicit `local_secret_retirement` targeting H, or a tombstoning sibling node that publishes `secret_retired_offer(H)`).
- **Action:** wipe + replay.
- **Expect:** `LocalHistoryNodeSecretProjector::project_local_history_node_secret` finds the retirement context for H first and returns `purge_self(fact.id)`; H is not re-offered as `local_secret_source`/`secret_coverage`/wrap-source. Tombstone-driven retirement and explicit retirement both hold.
- **Defends:** same as KEYS-14 for the history-node family; tombstone lineage (`validate_history_retirement` accepts a tombstone node whose `tombstone_node_id == target`).
- **Refs:** `auth/local_history_node_secret/project.rs` (`validate_history_retirement`, `purge_self`), `auth/local_secret_retirement/project.rs`.

### KEYS-16 — recipient key rotation supersedes the previous key (root loss / rotate)  `blackbox-cli`
- **Setup:** `con` node with workspace W and an existing `recipient_key` R0 (from `key-recipient`); its `local_recipient_key` LR0 live.
- **Action:** run `con key-rotate-recipient W` (run fn `key_recipient_rotation`) supplying R0 as `previous_recipient_key_id`, producing R1.
- **Expect:** `RecipientKeyProjector` validates `validate_previous_recipient_key` (same endpoint, same workspace) and emits a `recipient_superseded` offer keyed at R0's id; the rotation output reports `superseded_recipient_keys: 1`. R1 becomes the live recipient.
- **Defends:** recipient key rotation on root loss; supersession proof correctness.
- **Refs:** `auth/key_wrap/cli.rs::{rotate_recipient,key_recipient_rotation}`, `auth/recipient_key/project.rs::{recipient_key,validate_previous_recipient_key}`.

### KEYS-17 — rotation rejects cross-endpoint supersession  `projector-unit`
- **Setup:** R1 claims `previous_recipient_key_id = R0`, but R0's `endpoint_id` differs from R1's `endpoint_id`.
- **Action:** project R1 through `RecipientKeyProjector` with R0 supplied as the `recipient_key` previous-need payload.
- **Expect:** Err "recipient key supersession previous_recipient_key endpoint does not match (cross-endpoint supersession is rejected)"; R1 is not admitted as a valid supersession. Prevents stealing another endpoint's key lineage.
- **Defends:** recipient key rotation correctness (only same-endpoint supersession).
- **Refs:** `auth/recipient_key/project.rs::validate_previous_recipient_key`.

### KEYS-18 — superseded recipient key stops emitting proactive key-wrap work  `projector-unit`
- **Setup:** recipient_key R0 that IS superseded — a later R1 published a `recipient_superseded` offer at R0's id.
- **Action:** project R0 with the `recipient_superseded` context present.
- **Expect:** `is_superseded` is true → after sharing the fact, `recipient_key` returns early BEFORE adding the `proactive_wrap_source_need` and BEFORE emitting any `create_key_wrap_intent`. Peers/local projection stop minting fresh wraps toward the superseded recipient key.
- **Defends:** "peers stop sending to superseded recipient keys"; root-loss/floor-advance recipient rotation.
- **Refs:** `auth/recipient_key/project.rs::recipient_key` (`if is_superseded { return Ok(output); }`).

### KEYS-19 — local recipient private key self-purges once its recipient is superseded  `projector-unit`
- **Setup:** `local_recipient_key` LR0 for recipient R0; R1 (superseding R0) has published `recipient_superseded` at R0's id.
- **Action:** project LR0 through `LocalRecipientKeyProjector`.
- **Expect:** `is_superseded` true → returns `output.purge_self(fact.id)`; LR0 stops offering `local_recipient_key` context and the private recipient secret is purged locally. Future wraps to R0 can no longer be unwrapped.
- **Defends:** "local private material purged after exact supersession proof"; forward secrecy on recipient rotation.
- **Refs:** `auth/local_recipient_key/project.rs::local_recipient_key` (`superseded_need`, `purge_self`).

### KEYS-20 — superseded recipient key + new wrap: no unwrap intent for the dead recipient  `projector-unit`
- **Setup:** a `key_wrap` W naming superseded recipient R0; LR0 has already self-purged (KEYS-19), so no `local_recipient_key` context for R0 exists.
- **Action:** project W through `KeyWrapProjector`.
- **Expect:** the wrap row still materializes (signer+recipient+frontier validate) but `local_recipient_fact` is `None` → NO `unwrap_key_wrap_intent` is emitted; the secret is never re-opened. A wrap to a retired recipient is inert.
- **Defends:** unwrap respects supersession/purge; peers cannot revive access via a stale wrap.
- **Refs:** `auth/key_wrap/project.rs::key_wrap` (the `if let Some(local_recipient_fact)` branch).

### KEYS-21 — duplicate key requests for the same edge converge on a single wrap  `projector-unit`
- **Setup:** two distinct `key_request` facts KR_a and KR_b (different fact ids, possibly different requester nonces/timestamps) that target the SAME `(workspace_id, frontier_id, recipient_key_id, responder_endpoint_id)` edge; matching recipient/frontier/wrap-source/signer context present.
- **Action:** project both KR_a and KR_b through `KeyRequestProjector`.
- **Expect:** each emits a `create_key_wrap_intent` whose idempotence key is `create_key_wrap_key(workspace_id, frontier_id, recipient_key_id, source-coordinate)` — IDENTICAL for both requests (the request fact id is NOT part of the key). The two intents collapse to ONE queued handler run → ONE deterministic `key_wrap` fact. Request entropy does not amplify key material.
- **Defends:** "duplicate key requests for the same deterministic edge converge on one wrap (no request entropy amplifying keys)."
- **Refs:** `auth/key_request/project.rs::key_request`, `auth/create_key_wrap.rs::create_key_wrap_key` (key = workspace+frontier+recipient+source coord only).

### KEYS-22 — proactive (recipient-key-driven) and requested (key-request-driven) wraps for the same edge are the same wrap  `projector-unit`
- **Setup:** a recipient_key R0 (not superseded) that emits a proactive `create_key_wrap_intent` for a FrontierRoot source; plus a `key_request` targeting the same recipient R0 + same frontier + same responder, emitting a requested `create_key_wrap_intent`.
- **Action:** project both paths.
- **Expect:** both produce the SAME `create_key_wrap_key` and the SAME deterministic wrap fact id — proactive and requested domains converge on one wrap; only the offer-domain prefix (`PROACTIVE_DOMAIN`/`REQUESTED_DOMAIN`) differs at the context layer, not the resulting key.
- **Defends:** request entropy never amplifies keys; deterministic edge identity.
- **Refs:** `auth/recipient_key/project.rs` (proactive), `auth/key_request/project.rs` (requested), `auth/key_wrap/project.rs::{wrap_source_offers,wrap_offer_key}`, `auth/create_key_wrap.rs::create_key_wrap_key`.

### KEYS-23 — key_request only mints wraps when responder owns the frontier and is the source owner  `projector-unit`
- **Setup:** a `key_request` whose `responder_endpoint_id` does NOT own the supplied `removal_frontier`, OR whose matching wrap source's `owner_endpoint_id != responder_endpoint_id`.
- **Action:** project through `KeyRequestProjector`.
- **Expect:** for the frontier mismatch: Err "key request frontier is not owned by responder". For the source-owner mismatch: the loop `if source.owner_endpoint_id != request.responder_endpoint_id { continue; }` skips it → NO `create_key_wrap_intent`. A requester cannot coerce a wrap from material the responder does not own.
- **Defends:** never fabricate/serve key material the local node is not authorized to wrap; converge-on-authorized-edge.
- **Refs:** `auth/key_request/project.rs::key_request` (frontier-owner check, source-owner `continue`).

### KEYS-24 — local_signer_secret material purged drops both create and proactive paths after retirement  `replay-cli`
- **Setup:** node where the `local_signer_secret` for the frontier owner has been removed (e.g. endpoint retired); recipient_key/removal_frontier/local_key_secret remain.
- **Action:** wipe + replay; observe `matching_wrap_sources_with_signer` over the proactive wrap-source need.
- **Expect:** `local_signer_secret_fact_id(...)` returns `None` for the source's `owner_endpoint_id` → no `(source, signer, source)` tuple → NO `create_key_wrap_intent` from `recipient_key` projection (and likewise from `key_request`). Existing wraps still replay via tag 155, but no NEW wrap is minted without local signer material.
- **Defends:** "create_key_wrap recreates wraps ONLY when local source + signer material exist"; replay does not fabricate.
- **Refs:** `auth/key_wrap/project.rs::{matching_wrap_sources_with_signer,local_signer_secret_fact_id}`, `auth/recipient_key/project.rs`.

### KEYS-25 — chop-now retires a covered secret subtree and is deterministic on replay  `blackbox-cli`
- **Setup:** `con` node with derived `local_history_node_secret` coverage under a frontier; run `con chop-now W FLOOR_MINUTE`.
- **Action:** run `chop-now`, capture the receipt (`subtree_tombstones_written`, `purged_secret_bytes`, etc.), then wipe + replay.
- **Expect:** chop-now writes `local_secret_retirement` (reason CHOP, `floor_minute`) + tombstone nodes; covered `local_*_secret` facts self-purge. On replay the same retirement/tombstone facts are retained and produce the SAME purges and the SAME `keys` summary counts. `purged_secret_bytes` reflects removed local material.
- **Defends:** removal_frontier/local_secret_retirement floor-advance retirement; invariant 4 determinism of retirement.
- **Refs:** `auth/key_wrap/cli.rs::{chop_now_args,chop_now_output}`, `auth/key_wrap/commands.rs` (chop flow), `auth/local_secret_retirement/`, `auth/local_history_node_secret/project.rs`.

### KEYS-26 — local_secret_retirement only fires for a matching local key-material target  `projector-unit`
- **Setup:** a `local_secret_retirement` fact naming `target_secret_id = T`, but the only local context at T is NOT key material (e.g. some other local fact), or T's workspace differs from the retirement's workspace.
- **Action:** project through `LocalSecretRetirementProjector`.
- **Expect:** workspace mismatch → Err "local key secret retirement workspace mismatch"/"local history secret retirement workspace mismatch"; non-key-material target → Err "local secret retirement target context is not key material". No `local_secret_source_retired` offer is published, so no wrongful purge of unrelated material.
- **Defends:** retirement targets exact key material only; never over-purges.
- **Refs:** `auth/local_secret_retirement/project.rs::{project_typed,validate_target_secret}`.

### KEYS-27 — retirement is local-scoped only; cross-version retirement bytes unchanged  `guardrail`
- **Setup:** `local_secret_retirement` layout = tag(157) + workspace(32) + target(32) + reason(1) + floor_minute(8) + created_at_ms(8) = 82 bytes; reason must be `RETIRE_REASON_CHOP=1`.
- **Action:** assert (a) a non-local-scope retirement fact is rejected ("local secret retirement fact must have local scope"); (b) an unsupported `reason_kind != 1` is rejected at decode ("local secret retirement reason is unsupported"); (c) the byte layout const `LOCAL_SECRET_RETIREMENT_BYTES` is stable.
- **Expect:** all three hold; the retirement family carries no internal version byte (versioning is by tag), so a future redesign would be a NEW tag, not a reused byte.
- **Defends:** invariant 5/6 substrate (retirement is a tag-versioned, scope-bounded fact) + scope safety of retirement.
- **Refs:** `auth/local_secret_retirement/layout.rs` (`validate_fact`, `TYPE_LOCAL_SECRET_RETIREMENT`), `auth/local_secret_retirement/project.rs` (scope check).

### KEYS-28 — removal_frontier requires proven owner (shared signer or local signer secret)  `projector-unit`
- **Setup:** a `removal_frontier` fact whose `owner_endpoint_id` has NO matching `content_signer` (endpoint_shared) offer AND no `local_signer_secret`.
- **Action:** project through `RemovalFrontierProjector`.
- **Expect:** `(None, None)` arm → returns the waiting output with only the two needs, NO `auth_removal_frontier` offer published → downstream key_wrap/key_request/local_key_secret projection that depends on this frontier stays blocked. A frontier cannot anchor key material without proven ownership.
- **Defends:** frontier authority gating (root-of-trust for the whole key tree); peers cannot inject a frontier to coerce wraps.
- **Refs:** `auth/removal_frontier/project.rs::removal_frontier` (`(None, None) => waiting`).

### KEYS-29 — removal_frontier admitted via local signer secret carries empty context_have (private path)  `projector-unit`
- **Setup:** a `removal_frontier` owned by the local endpoint, proven only by `local_signer_secret` (no shared `content_signer` payload available).
- **Action:** project through `RemovalFrontierProjector`.
- **Expect:** `(None, Some(owner_fact))` arm → `validate_frontier_local_owner` validates workspace/signer_id/public_key, `context_have = Vec::new()` (the local secret is NOT shared as a sync dependency), and the `auth_removal_frontier` offer IS published so local key material can proceed. Local private signer material never leaks into shared context_have.
- **Defends:** removal_frontier across the shared-vs-local proof axis; forward secrecy of the local signer.
- **Refs:** `auth/removal_frontier/project.rs::{removal_frontier,validate_frontier_local_owner}`.

### KEYS-30 — key_wrap rejects a wrap whose frontier owner != wrap signer  `projector-unit`
- **Setup:** a `key_wrap` W with `signer_endpoint_id = S`; the matched `removal_frontier` context has `owner_endpoint_id != S`.
- **Action:** project W through `KeyWrapProjector`.
- **Expect:** Err "key wrap signer does not own removal frontier"; the wrap row is not written and no unwrap intent emitted. Prevents a wrap signed under a frontier the signer doesn't control.
- **Defends:** signer/frontier coherence at admission; no fabricated authority.
- **Refs:** `auth/key_wrap/project.rs::key_wrap` (`frontier.owner_endpoint_id != wrap.signer_endpoint_id`).

### KEYS-31 — post-retirement disk compromise cannot decrypt retired content (forward secrecy)  `replay-cli`
- **Setup:** node where a frontier-root `local_key_secret` and its derived `local_history_node_secret`s were used to open historical content, then `chop-now FLOOR` retired them: the local secret facts self-purged and `local_secret_retirement` facts persist; the originating `key_wrap` facts (tag 155) also persist (sync-shared).
- **Action:** simulate disk capture = wipe derived state + replay ONLY the retained on-disk facts (no live network, no fresh unwrap acceptance), then attempt `con key-access W FRONTIER` / read pre-floor content.
- **Expect:** replay re-runs unwrap intents but each opened secret immediately self-purges (standing retirement context, KEYS-14/15), so no live `local_key_secret`/`local_history_node_secret` is offered; `key-access` for the retired frontier/range reports no access and pre-floor content cannot be decrypted. The surviving `key_wrap` ciphertext is inert without live local recipient/secret material.
- **Defends:** forward secrecy — "post-retirement disk compromise cannot decrypt retired content"; unwrap never resurrects an opened-then-retired secret.
- **Refs:** `auth/local_key_secret/project.rs` + `auth/local_history_node_secret/project.rs` (`purge_self` on retirement), `auth/unwrap_key_wrap.rs`, `auth/key_wrap/cli.rs::key_access_*`.

### KEYS-32 — peers replaying an old-tag wrap use the historical key_wrap adapter (ceiling-independent replay)  `replay-cli`
- **Setup:** after a key-wrap REDESIGN ships and ceiling = N+1 (v2 active), a node still retains tag-155 v1 `key_wrap` facts created at protocol N.
- **Action:** wipe + replay at ceiling N+1.
- **Expect:** every retained tag-155 fact replays through the ORIGINAL `project_auth_key_wrap`/`KeyWrapProjector` adapter (keyed by its own tag 155), NOT the v2 projector; v1 unwrap intents still fire deterministically. Replay is ceiling-independent — the active ceiling does not change which adapter a retained fact uses.
- **Defends:** invariant 4 (ceiling-independent replay; each retained fact replays via the adapter keyed by its OWN tag) + invariant 5 (old readers forever).
- **Refs:** `src/core/projectors.rs` RouterProjector (tag-keyed dispatch), `registry.rs` FACT_ROUTES (both v1 tag 155 and v2 tag routes present).

### KEYS-33 — recipient key with no previous key (NO_PREVIOUS_RECIPIENT_KEY) takes min_frontier_created_at_ms = 0  `projector-unit`
- **Setup:** an initial `recipient_key` R0 with `previous_recipient_key_id == NO_PREVIOUS_RECIPIENT_KEY ([0;32])`, not superseded; eligible FrontierRoot wrap sources of varying ages exist.
- **Action:** project R0 through `RecipientKeyProjector`.
- **Expect:** `min_frontier_created_at_ms = 0` → `proactive_wrap_source_need` matches ALL workspace frontier roots; `create_key_wrap_intent`s are emitted for every eligible source. (Contrast: a rotated key R1 sets `min_frontier_created_at_ms = recipient.created_at_ms`, so only frontiers created at/after the rotation match — old roots are excluded from re-wrapping to the new key.)
- **Defends:** rotation floor-advance semantics; recipient rotation does not auto-rewrap pre-rotation roots (forward-secrecy boundary at the recipient layer).
- **Refs:** `auth/recipient_key/project.rs::recipient_key` (`min_frontier_created_at_ms` branch), `auth/key_wrap/project.rs::{proactive_wrap_source_need,wrap_source_offer_valid_for_need}`.

### KEYS-34 — rotated recipient key only re-wraps frontiers created at/after the rotation  `projector-unit`
- **Setup:** rotated `recipient_key` R1 (supersedes R0), `created_at_ms = T_rot`; one FrontierRoot wrap source with `frontier_created_at_ms < T_rot` and one with `>= T_rot`.
- **Action:** project R1 (not itself superseded) through `RecipientKeyProjector`.
- **Expect:** `proactive_wrap_source_need(min = T_rot)` matches ONLY the source with `frontier_created_at_ms >= T_rot` (`wrap_source_offer_valid_for_need` proactive arm checks `>= min`); a `create_key_wrap_intent` is emitted for the new source only, not the pre-rotation one.
- **Defends:** recipient rotation floor advance; bounded re-wrap window.
- **Refs:** `auth/recipient_key/project.rs::recipient_key`, `auth/key_wrap/project.rs::wrap_source_offer_valid_for_need` (`source.frontier_created_at_ms >= min_frontier_created_at_ms`).

### KEYS-35 — wrap-source descriptor encoding/version is tag-stable across the redesign  `guardrail`
- **Setup:** `WrapSourceDescriptor` is encoded with leading version byte `3` and `ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN = 156` (`encode_wrap_source_descriptor`); kind byte 1=FrontierRoot, 2=HistoryNode.
- **Action:** assert `decode_wrap_source_descriptor` round-trips the v1 156-byte encoding and rejects any other length/version (`bytes.len() != 156 || bytes[0] != 3`).
- **Expect:** v1 descriptor decoding is preserved verbatim; a redesigned wrap-source coordinate scheme would be a NEW encoding under the new (v2) family, leaving the v1 decoder intact for replaying old wraps.
- **Defends:** invariant 5 — the wrap-source coordinate decoder (a "reader") is kept forever; deterministic edge identity is byte-stable.
- **Refs:** `auth/key_wrap/project.rs::{encode_wrap_source_descriptor,decode_wrap_source_metadata,ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN}`.

### KEYS-36 — create_key_wrap intent payload/key byte shape is stable (param-subset contract)  `guardrail`
- **Setup:** `CreateKeyWrapIntent` payload is fixed 212 bytes (`decode_create_key_wrap_payload` checks `payload.len() != 212 || payload[0] != 1`); idempotence key is `workspace + frontier + recipient + source-coordinate` (no fact ids beyond recipient, no request entropy).
- **Action:** assert encode/decode round-trips at 212 bytes; assert two intents with identical (workspace,frontier,recipient,source) but different `source_fact_id`/`signer_secret_fact_id` produce the SAME `create_key_wrap_key`.
- **Expect:** both hold — the idempotence key deliberately excludes the source/signer fact ids and any request entropy, so duplicate-edge requests converge. A versioned change to inputs would be a new `key-wrap` CLI bucket entry only if the collected param surface changes (absent => reuse prev).
- **Defends:** "no request entropy amplifying keys" at the intent-key level + CLI param-subset reuse contract.
- **Refs:** `auth/create_key_wrap.rs::{create_key_wrap_key,encode_create_key_wrap_payload,decode_create_key_wrap_payload}`.

### KEYS-37 — multinode: superseded recipient causes peers to stop minting wraps to it  `multinode-network`
- **Setup:** two `con` nodes A (holds frontier+signer+root secret) and B (recipient owner) syncing over a connection; B has `recipient_key` R0, then rotates to R1 (R0 superseded).
- **Action:** B's rotation fact syncs to A; A re-projects R0 and R1.
- **Expect:** A's `RecipientKeyProjector` sees `recipient_superseded` for R0 and stops emitting proactive `create_key_wrap_intent` toward R0; A only mints wraps toward the live R1 (subject to the rotation floor). A wrap row for R0 already created stays, but no NEW wrap to R0 is produced.
- **Defends:** "peers stop sending to superseded recipient keys" (cross-node).
- **Refs:** `auth/recipient_key/project.rs`, `auth/key_wrap/project.rs`, `sync::shared_fact` sharing of recipient/supersession context.

### KEYS-38 — multinode: requested wrap answered to a still-usable older peer at the request's edge, converges with proactive  `multinode-network`
- **Setup:** responder R (holds source+signer) and requester Q on a connection; Q sends a `key_request` for recipient Rk + frontier F; R also independently has a proactive wrap path for the same (Rk, F).
- **Action:** R projects the inbound `key_request` and its own recipient/source state.
- **Expect:** R produces exactly ONE `key_wrap` for the (workspace,F,Rk,source) edge (identical `create_key_wrap_key`), shares it once; Q unwraps it. Two `key_request`s from Q for the same edge do not produce two wraps.
- **Defends:** "duplicate key requests for the same deterministic edge converge on one wrap" across nodes; transport answer at request's edge.
- **Refs:** `auth/key_request/project.rs`, `auth/create_key_wrap.rs::create_key_wrap_key`, `sync::send_requested_fact`/`share_fact_with_sync`.

### KEYS-39 — local secret material self-purges before live frontier offer when retired in the same replay pass  `property`
- **Setup:** arbitrary interleavings (scramble replay, `replay --scramble --seed N` analogue via reordered fact application) of {root/history secret, its removal_frontier, its retirement fact}.
- **Action:** apply facts in randomized order; project the local secret.
- **Expect:** regardless of arrival order, once the `local_secret_source_retired` context for the secret's id is present, the secret projector returns `purge_self` and never publishes a live `local_secret_source`/wrap-source/coverage offer; if retirement is absent it publishes them. Order-independent (invariant 4).
- **Defends:** invariant 4 order-independence of retirement-vs-materialize; forward secrecy under any replay order.
- **Refs:** `auth/local_key_secret/project.rs`, `auth/local_history_node_secret/project.rs` (retirement_need checked before materialize).

### KEYS-40 — unwrap rejects a coordinate mismatch between intent and wrap (no cross-edge unwrap)  `handler-unit`
- **Setup:** an `unwrap_key_wrap` intent whose `(workspace_id, frontier_id, recipient_key_id)` does not match the supplied `key_wrap` fact's fields (e.g. wrong frontier).
- **Action:** call `create::unwrap_key_wrap_fact` (via handler).
- **Expect:** `require_unwrap_coordinate` returns Err ("key wrap frontier does not match unwrap intent" etc.); no local secret produced. The unwrap is bound to the exact wrap coordinate — an attacker cannot redirect an unwrap to a different edge.
- **Defends:** deterministic-edge binding of unwrap; never fabricate a secret for a mismatched coordinate.
- **Refs:** `auth/key_wrap/create.rs::require_unwrap_coordinate`, `auth/unwrap_key_wrap.rs`.
## 16. Multi-node end-to-end pairs

Scope note. These are black-box `con`-binary, >=2-node scenarios that exercise the
protocol-versioning model end to end. The versioning machinery (signed
`ReleaseManifestEntry`, ceiling computation, pending of above-ceiling
received facts, upgrade-retirement of connections before replay) is the *model
under test* — it is NOT yet present in `/home/holmes/poc-10/src` (verified:
`grep -rni "ceiling\|ReleaseManifest\|intro_version\|trusted_time"` matches no
real symbol). So every test below is written against the real, existing
black-box harness vocabulary that DOES exist today
(`tests/cli_harness/mod.rs` + `tests/black_box_sync_test.rs`:
`temp_db`, `spawn_daemon`/`spawn_daemon_with_sync_ms`, `create_workspace`,
`accept_workspace_invite`, `endpoint_id`, `create_local_content_key`,
`sync_range_until_queued`, `wait_for_content_count`, `assert_content_count`,
`fact_count`, `poll_for_message_text`, `poll_for_disappearing_value`,
`wait_for_fact_count_at_least`, and the real `con` subcommands
`create-workspace / accept / generate / send / react / send-file / save-file /
files / messages / view / content-count / sync-range --with-deps|--without-deps
/ grant-admin / disappearing-set / clock set|advance|clear / count / sync-status
/ stop / reset / assert eventually`), plus the *proposed* versioning knobs the
model requires (a fleet `--release-manifest FILE` flag and the new
`content::message:2` / `content::file:3` fact-tag versions living under
`content/message/_v2/` etc.). "New" binary = built with the higher protocol
bundle compiled in; "old" binary = the prior release whose
`supported_protocol.end()` is lower. Two binaries are obtained by building `con`
at two refs into two `--target-dir`s and selecting via `con_bin()`-style
helpers; tests name them `con_new` / `con_old`.

Axes enumerated separately per the charter: {new-creates / old-creates} x
{content message, content reaction, content file, auth admin, disappearing
policy} where relevant; plus the dependency-closure and upgrade-under-load
families.

---

### E2E-01 — two new nodes below ceiling create only ceiling-version message facts  `multinode-network`
- **Setup:** `alice`=`con_new`, `bob`=`con_new`, both fed the SAME signed `--release-manifest fleet.json` whose still-usable set yields ceiling = protocol 6 (the bundle that contains `content::message:1`, tag 50, NOT `content::message:2`). `temp_db` each; `spawn_daemon(&alice, alice_port)` / `spawn_daemon(&bob, bob_port)`; `create_workspace(&alice,..)`; `accept_workspace_invite(..)`; `create_local_content_key(&alice, &workspace)`.
- **Action:** `con_new --db alice send WORKSPACE "hi-below-ceiling"`.
- **Expect:** the persisted message fact on alice has first byte `TYPE_CONTENT_MESSAGE = 50` (the v1 tag), NOT a v2 tag; `wait_for_content_count(&bob, &workspace, 1)` succeeds and `poll_for_message_text(&bob, &workspace, "hi-below-ceiling", 10_000)` passes. Both nodes' `messages WORKSPACE` rows are byte-identical.
- **Defends:** (1) visibility; (2) rendering uniformity (clients render at the ceiling, not their head). Local creation of an above-ceiling `:2` fact is refused.
- **Refs:** `content::message` (tag 50) `layout.rs`/`create.rs`/`cli.rs`; the proposed `_v2/` sibling; `MATCH_COMMANDS` `send`; black-box `send`/`messages`/`content-count`.

### E2E-02 — new<->old below ceiling: message round-trip is identical  `multinode-network`
- **Setup:** `alice`=`con_new` (head=protocol 7), `bob`=`con_old` (head=protocol 6). Manifest's ceiling = 6 (old still usable, not expired, not deprecated). Workspace shared, content key created on alice, key-access converged on bob.
- **Action:** `con_new --db alice send WORKSPACE "round-trip"`, then `con_old --db bob ... sync` via running daemons.
- **Expect:** bob materializes the message (`wait_for_content_count(&bob, &workspace, 1)`); `messages WORKSPACE` content on alice (new) and bob (old) is identical text/sender/timestamp. The new node did NOT emit `content::message:2` because that capability is not ceiling-active.
- **Defends:** (1); (2) two supported clients at the same protocol version produce the same read-model row; (3) ceiling monotonicity.
- **Refs:** `content::message` create/project/rows; transport answer-in-request-version rule; `sync-range`.

### E2E-03 — new<->old below ceiling: reaction round-trips  `multinode-network`
- **Setup:** same pair as E2E-02 (new alice / old bob, ceiling 6). One message already synced both ways.
- **Action:** `con_old --db bob react WORKSPACE <message-selector> "👍"`; daemons sync.
- **Expect:** `con_new --db alice messages WORKSPACE` (or reaction query) shows the `👍` reaction attached to the target message; reaction fact first byte = `TYPE_CONTENT_REACTION = 52`; receipt `reaction_fact_id`/`emoji` keys present on bob; reaction row content identical on both nodes.
- **Defends:** (1); (2). Old node both creates and the new node reads a ceiling-active reaction.
- **Refs:** `content::reaction` (tag 52) `rows.rs`/`project.rs`; `react` in `MATCH_COMMANDS`; `CONTENT_REACTIONS` read-model.

### E2E-04 — new<->old below ceiling: file send + slice transfer + save round-trips byte-exact  `multinode-network`
- **Setup:** new alice / old bob, ceiling 6 (so `content::file:1` tag 54 and `content::file_slice` tag 55 are ceiling-active; the proposed `content::file:3` is above ceiling). Multi-slice payload via `patterned_payload(N)`.
- **Action:** `con_new --db alice send-file WORKSPACE "doc" --file PATH`; `sync_range_until_queued` for the file's minute; `con_old --db bob save-file WORKSPACE <file-selector> OUT`.
- **Expect:** send-file receipt has `file_fact_id`, `file_id`, `blob_bytes`, `total_slices`; bob's saved bytes equal the source bytes exactly (`patterned_payload` comparison); file fact first byte = 54, slices = 55; `files WORKSPACE` listing identical on both.
- **Defends:** (1) transportability by every still-usable release; (5) transport in [floor,head]; carrier-capacity gating (file_slice precedent).
- **Refs:** `content::file` (54), `content::file_slice` (55); `connection::frame_file_slice` (169); `CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES`; `send-file`/`save-file`/`files`.

### E2E-05 — new creates / old reads: ceiling-active admin grant admits+projects+displays+syncs to old  `multinode-network`
- **Setup:** new alice (host/admin) / old bob, ceiling 6 (`auth::admin` tag 139 ceiling-active). Bob is a workspace member with a recipient key; content-key access converged.
- **Action:** `con_new --db alice grant-admin WORKSPACE <bob_user_id>`; `sync_range_until_queued(&alice, &bob_endpoint, WORKSPACE, ...)`.
- **Expect:** grant-admin receipt `admin_id` non-empty on alice; after sync bob's `users WORKSPACE` (or admin query) shows bob as admin; admin fact first byte = 139; bob projects it via the kept-forever tag-139 projector, no error at `projectors.rs:456`.
- **Defends:** (1) admissible/projectable/displayable/transportable by every still-usable release; (2).
- **Refs:** `auth::admin` (139); `grant-admin` -> `grant_admin`; `RouterProjector`/`FactRoute`; `sync-range`.

### E2E-06 — new creates / old reads: disappearing-policy fact syncs and materializes on old  `multinode-network`
- **Setup:** new alice / old bob, ceiling 6 (`content::retention_policy` tag 147 ceiling-active). Workspace shared, message already present.
- **Action:** `con_new --db alice clock set <t>`, `con_new --db alice disappearing-set WORKSPACE 120`; `sync_range_until_queued(.., --with-deps)`.
- **Expect:** `poll_for_disappearing_value(&bob, &workspace, "current_ttl_minutes", "120", 10_000)` passes on old bob; policy fact first byte = 147; both nodes report `current_ttl_minutes: 120` identically.
- **Defends:** (1); (2). New node creates a ceiling-active policy fact; old node reads/derives identically.
- **Refs:** `content::retention_policy` (147); `disappearing-set` -> `disappearing_set`; `clock set`; `sync-range --with-deps`.

### E2E-07 — old creates / new reads: old's message projects into ceiling-era rows, grants no new authority  `multinode-network`
- **Setup:** old alice (head=protocol 6) / new bob (head=protocol 7), ceiling 6. Shared workspace, content key.
- **Action:** `con_old --db alice send WORKSPACE "from-old"`; sync to new bob.
- **Expect:** new bob materializes the message (`wait_for_content_count`); the message renders in bob's CEILING-era `CONTENT_MESSAGES` rows identically to a new-authored one; bob does NOT upgrade/derive a `content::message:2` row from it (no new derivation surfaced until ceiling rises). `messages` content identical on both.
- **Defends:** (2) withhold a new derivation of existing facts until ceiling-active; (4) old facts replay via their own tag-50 adapter.
- **Refs:** `content::message` (50) project/rows; the head-shared `rows.rs`/`queries.rs`; `RouterProjector` keyed by own tag.

### E2E-08 — old creates / new reads: old's reaction projects into ceiling-era reaction rows  `multinode-network`
- **Setup:** old alice / new bob, ceiling 6. A message already shared both ways.
- **Action:** `con_old --db alice react WORKSPACE <selector> "🎉"`; sync to new bob.
- **Expect:** new bob shows the reaction on the message; reaction fact first byte = 52; reaction row content identical to a new-authored reaction; no new authority/derivation introduced.
- **Defends:** (1); (2); (4).
- **Refs:** `content::reaction` (52); `react`; `CONTENT_REACTIONS`.

### E2E-09 — old creates / new reads: old's file synced and saved byte-exact by new node  `multinode-network`
- **Setup:** old alice / new bob, ceiling 6. Multi-slice `patterned_payload`.
- **Action:** `con_old --db alice send-file WORKSPACE "olddoc" --file PATH`; `sync_range_until_queued`; `con_new --db bob save-file WORKSPACE <selector> OUT`.
- **Expect:** new bob's saved bytes equal the source exactly; file/slice tags 54/55; `files WORKSPACE` identical on both; no `content::file:3` row derived on bob.
- **Defends:** (1); (2); (4); carrier capacity (file_slice precedent).
- **Refs:** `content::file` (54)/`content::file_slice` (55); `connection::frame_file_slice` (169); `save-file`/`files`.

### E2E-10 — mixed-version sync WITH deps: new holds v2 fact + v1 anchor, old requests, closure delivers anchor  `multinode-network`
- **Setup:** ceiling temporarily RAISED so new alice (`con_new`) has locally a `content::message:2` fact (the new wire-shape message, new tag, e.g. tag 56 under `content/message/_v2/`) whose dependency anchor is a v1 fact (`auth::workspace` 131 / `auth::user` 14 / a v1 `content::message` 50). Old bob (`con_old`) cannot project the `:2` tag. Daemons running, bob a member.
- **Action:** `con_old --db bob sync-range <alice_endpoint> --workspace WORKSPACE --start-ms 0 --end-ms MAX --with-deps`; or alice `sync-range <bob_endpoint> ... --with-deps`.
- **Expect:** the closure delivers every v1 anchor (workspace/user/v1-message) that old bob CAN project — bob's `content-count`/`users` reflect the anchors — while the unbundlable `:2` fact is NOT forced onto bob (or, if forwarded, lands PENDING: pending opaque, uncounted, undisplayed, NO `projectors.rs:456` error). `fact_count(&bob)` rises by exactly the anchor count, not including the v2 fact's row.
- **Defends:** (1) for the v1 anchors; admission/pending rule; (5) closure must not strand a still-usable peer.
- **Refs:** `sync-range --with-deps` -> `sync_range`; `sync::shared_fact` (162)/`sync::range_request` (160); `ShareFactWithSyncHandler`/`SendRequestedFactHandler`; `RouterProjector` pending path.

### E2E-11 — mixed-version sync: unbundlable v2 fact degrades to have/need, not error  `multinode-network`
- **Setup:** same as E2E-10. Old bob receives a `sync::compare`/`have_id` advertisement that references the v2 fact id.
- **Action:** drive a `sync-range` so bob emits `sync::need_id` (167) for ids it lacks; new alice advertises the v2 fact via `sync::have_id` (166).
- **Expect:** because the v2 tag is above bob's ceiling, the exchange DEGRADES — bob does not `need_id` it (or receives it pending); the connection stays alive, no projector error; the v1 anchors still flow. The protocol falls back to have/need framing rather than crashing the carrier.
- **Defends:** pending + degrade-to-have/need; (5) transport in [floor,head]; (6) safety floor (only drop if unsafe, not here).
- **Refs:** `sync::compare` (165), `sync::have_id` (166), `sync::need_id` (167); `SendNeededFactIdHandler`/`SendSyncCompareResponseHandler`; `seed_connection_sync`.

### E2E-12 — mixed-version sync: bundle that mixes v1+v2 facts packs only deliverable facts for old peer  `multinode-network`
- **Setup:** new alice has a `connection::frame_bundle` (170)-worth of facts: several v1 messages (50) plus one v2 message (56). Old bob's ceiling excludes 56.
- **Action:** alice's `SendFactsOnConnectionHandler` packs a bundle frame to bob.
- **Expect:** the inner bundle (`TIB1`) packed for bob contains only the tag-50 facts; the tag-56 fact is omitted (held for re-advertisement) — verified by bob's resulting `fact_count` rising by the v1 count only and bob never erroring. Frame fits `CONNECTION_FRAME_BUNDLE_FACT_SLOTS` (< 64 KiB).
- **Defends:** (1) transportable by every still-usable release; carrier capacity gating; pending.
- **Refs:** `connection::frame_bundle` (170); `connection_frame_wire.rs` `encode_inner_bundle`/`INNER_BUNDLE_TAG`; `SendFactsOnConnectionHandler` (`send_facts_on_connection`).

### E2E-13 — mixed-version sync: old creates v1 anchor that new needs for its v2 fact (reverse closure)  `multinode-network`
- **Setup:** old alice holds the v1 anchor (e.g. a `content::file` 54 + slices). New bob has authored locally a v2 derivation that depends on alice's anchor but is missing the anchor bytes.
- **Action:** new bob `sync-range <alice_endpoint> --workspace WORKSPACE --start-ms 0 --end-ms MAX --with-deps`.
- **Expect:** old alice (still-usable) answers with the v1 anchor in alice's own version (answer-in-request-version); new bob's closure completes; bob's v2-dependent state materializes only AFTER the anchor arrives. `save-file` on bob yields byte-exact bytes.
- **Defends:** (4) closure order-independence; transport answer-in-request-version; (1).
- **Refs:** `content::file`(54)/`file_slice`(55); `sync-range --with-deps`; `SendRequestedFactHandler`; `share_fact_with_sync`.

### E2E-14 — upgrade-under-load: queued intents are dropped per policy on upgrade  `multinode-network`
- **Setup:** `alice`=`con_old` daemon running with `spawn_daemon`, peered with `bob`. Queue several outbound intents on alice (e.g. multiple `sync-range ... --with-deps` dispatches that are `queued: yes` but not yet drained — spawn bob with `spawn_daemon_with_sync_ms(&bob, bob_port, 600_000)` so it does not pull yet). Verify queued via `sync-range` receipt `queued: yes`.
- **Action:** `con_old --db alice stop`; replace binary with `con_new` (higher head); `con_new --db alice start ...` (the upgrade boot).
- **Expect:** on the upgrade boot, the previously queued intents are NOT replayed/sent (intents are non-durable per policy and dropped on upgrade); alice re-derives its intent queue from facts. Bob's `fact_count` does not jump from stale queued sends after alice re-peers; only fact-derived sync resumes.
- **Defends:** upgrade policy "intents dropped"; intents are not facts (substance rule); (4) only deterministic facts recreated.
- **Refs:** `HANDLER_ROUTES`/`HandlerRoute` (`runtime.rs:71`); `submit_fact` (`runtime.rs:268`); `sync-range` queued receipt; `COMMAND_EXCLUDED_HANDLER_ROUTES`.

### E2E-15 — upgrade-under-load: live connections are retired BEFORE replay  `multinode-network`
- **Setup:** `alice`=`con_old` daemon with a LIVE connection to `bob` (a `connection::request`/`response` pair established, frames flowing). Confirm connection alive (bob receiving alice's `generate`d content).
- **Action:** `con_old --db alice stop` to begin upgrade; observe shutdown sequence; then `con_new --db alice start ...`.
- **Expect:** before alice's wipe+replay runs, a `connection::close` (45) / upgrade-retirement fact is emitted for the live connection and the socket is torn down; bob observes the close (its connection rows for alice show closed). Replay does NOT run with a live carrier attached. After restart alice re-bootstraps a fresh connection.
- **Defends:** "retire connections before replay" (transport rule); (4) replay determinism not corrupted by in-flight frames.
- **Refs:** `connection::close` (45) `commands.rs`/`project.rs`; `poc10_connection_close_purge_test.rs`; `bootstrap_request` (171)/`bootstrap_response` (172) re-handshake.

### E2E-16 — upgrade-under-load: full replay + pending purge before reconnect  `multinode-network`
- **Setup:** `alice`=`con_old` holding PENDING facts (received above-ceiling `content::message:2` tag-56 bytes, pending opaque). Manifest update raises alice's ceiling to cover tag 56 at boot of `con_new`.
- **Action:** upgrade alice: `stop` old, `start` new with the new manifest. The new boot performs wipe+replay across ALL retained facts (including the previously pending tag-56 bytes, now routable).
- **Expect:** after replay, the formerly pending tag-56 facts ACTIVATE — they project into rows and `messages WORKSPACE` now shows the v2-derived content; `content-count` rises to include them; no `projectors.rs:456` error during replay. Reconnect to bob happens only after replay completes.
- **Defends:** "pending facts activate on the next wipe+replay once ceiling rises"; (4) every retained fact replays via its own-tag adapter.
- **Refs:** `RouterProjector` route for tag 56 (new `_v2/` projector kept forever); `projectors.rs:456` (the error path that must NOT fire); wipe+replay; `content::message` v2.

### E2E-17 — upgrade-under-load: state_hash matches a clean rebuild after upgrade replay  `multinode-network`
- **Setup:** `alice`=`con_old` with a populated store (workspace, users, N messages, 1 file, 1 policy). Capture a content/state summary BEFORE upgrade (`content-count`, `count`, `sync-status` `root_fingerprint`, `messages` ordering).
- **Action:** upgrade alice to `con_new` (ceiling unchanged so no new derivations); the new boot wipes+replays derived state.
- **Expect:** post-upgrade `sync-status` `root_fingerprint`, `content-count` `content_messages`, `count`, and `messages` row order are IDENTICAL to the pre-upgrade capture. The shareable index root is order-independent of replay order.
- **Defends:** (4) replay determinism, order-independent, ceiling-independent; (2) rendering uniformity preserved across the upgrade.
- **Refs:** `sync::shared_fact` `rows.rs` `SyncStatus` (`root_fingerprint`/`root_count`); `sync-status`/`content-count`/`count`; `messages`.

### E2E-18 — new<->old below ceiling: identical state_hash / sync root across the version pair  `property`
- **Setup:** new alice / old bob fully converged on a shared workspace with the same set of ceiling-active facts (messages, reactions, one file, one admin grant, one policy). Both daemons quiesced.
- **Action:** `con_new --db alice sync-status` and `con_old --db bob sync-status` (scoped to the shared workspace's facts).
- **Expect:** the `root_fingerprint` over the shared facts matches between the new and old node; `content-count content_messages` equal; `users` admin sets equal. Two supported clients at the same protocol version produce the same read model regardless of release.
- **Defends:** (2) rendering uniformity; (1).
- **Refs:** `sync-status` -> `sync_status`; `sync::shared_fact` `SyncStatus`; `content-count`.

### E2E-19 — old creates / new reads: new node renders at ceiling, withholds v2 derivation of old's fact  `projector-unit`
- **Setup:** new bob (head=protocol 7, projector for `content::message:2` present) receives an old-authored `content::message:1` (tag 50) fact. Ceiling = 6 (v2 not active).
- **Action:** drive bob's `RouterProjector` over the tag-50 fact (black-box: sync it in; or focused: `project_typed` for tag 50).
- **Expect:** bob emits ONLY the ceiling-era (v1-shaped, head-shared) row; it does NOT run the v2 projector to produce a `content::message:2`-derived row, even though that code exists in the new binary. The surfaced row equals what an old binary would produce.
- **Defends:** (2) clients render at the ceiling not their head; withhold new derivation until ceiling-active.
- **Refs:** `content::message` (50) project + the `_v2/` project (must be skipped); `RouterProjector` (`projectors.rs:423`); `project_typed` (`:489`).

### E2E-20 — new creates above-ceiling fact locally is REFUSED (no leak to old peer)  `blackbox-cli`
- **Setup:** new alice, ceiling = 6 (so `content::message:2` is above ceiling). A normal shared workspace with old bob.
- **Action:** attempt to author the above-ceiling variant — e.g. a `send --v2`/`--profile` style flag that would mint a tag-56 fact (the proposed v2 surface), with ceiling still 6.
- **Expect:** the command is REFUSED with a clear error; NO tag-56 fact is persisted on alice; bob never sees any tag-56 fact; alice's `content-count` unchanged. Local creation of an above-ceiling fact is refused (it does not even pending — pending is only for RECEIVED facts).
- **Defends:** admission rule (local above-ceiling creation refused); (3) ceiling monotonicity gate.
- **Refs:** `content::message` create path; ceiling-active check on create; `send`/`MATCH_COMMANDS`.

### E2E-21 — received above-ceiling fact is PENDING on old node, not errored or dropped  `multinode-network`
- **Setup:** new alice (ceiling raised locally so it CAN mint a tag-56 `content::message:2`) connected to old bob (ceiling 6, no tag-56 projector active). Bob a member.
- **Action:** alice forwards the tag-56 fact to bob via sync/frame.
- **Expect:** bob RETAINS the tag-56 bytes (its `fact_count` rises by 1) but does NOT project/display/count it (`content-count content_messages` unchanged, `messages` does not show it); bob does NOT error (`projectors.rs:456` must not fire as a hard failure); bob does NOT drop it. The connection stays alive.
- **Defends:** pending rule (pending opaque, unprojected, undisplayed, uncounted, not dropped, not errored); contrast with today's `projectors.rs:456` Err.
- **Refs:** `RouterProjector::project` unknown-tag path (`projectors.rs:456`); `fact_count` vs `content-count`; `receive_network_frame` handler.

### E2E-22 — pending fact activates on old node after its own ceiling rises (wipe+replay)  `multinode-network`
- **Setup:** continue from E2E-21: bob holds the pending tag-56 fact. A signed manifest update arrives raising bob's still-usable ceiling to cover protocol 7 (tag 56).
- **Action:** restart bob's daemon (or trigger the wipe+replay boot) with the new manifest; replay runs over all retained facts including the tag-56 bytes.
- **Expect:** after replay bob's tag-56 fact ACTIVATES: `content-count content_messages` increases to include it and `messages WORKSPACE` now shows the v2 content. No replay error. Activation is purely local (no re-fetch from alice needed).
- **Defends:** "pending facts activate on the next wipe+replay once the ceiling rises"; (4) replay via own-tag adapter; (5) readers kept forever.
- **Refs:** tag-56 `_v2/` projector (kept forever); wipe+replay boot; `content-count`/`messages`.

### E2E-23 — new<->old below ceiling: deletion (message_deletion) round-trips and tombstones identically  `multinode-network`
- **Setup:** new alice / old bob, ceiling 6 (`content::message_deletion` tag 51 ceiling-active). A message synced both ways.
- **Action:** `con_old --db bob delete-message WORKSPACE <selector>`; sync to new alice.
- **Expect:** both nodes' `messages WORKSPACE` show the message tombstoned identically (`MESSAGE_TOMBSTONES`); deletion fact first byte = 51; `content-count` consistent across both.
- **Defends:** (1); (2) deletion derivation uniform across releases.
- **Refs:** `content::message_deletion` (51) `project.rs`/`rows.rs`; `delete-message` -> `delete_message`; `MESSAGE_TOMBSTONES`.

### E2E-24 — new<->old below ceiling: file deletion round-trips  `multinode-network`
- **Setup:** new alice / old bob, ceiling 6 (`content::file_deletion` tag 53 ceiling-active). A file synced both ways.
- **Action:** `con_new --db alice delete-file WORKSPACE <file-selector>`; sync to old bob.
- **Expect:** both nodes show the file removed from `files WORKSPACE` (`FILE_DELETIONS`); deletion fact first byte = 53; `save-file` of the deleted file fails identically on both.
- **Defends:** (1); (2).
- **Refs:** `content::file_deletion` (53); `delete-file` -> `delete_file`; `FILE_DELETIONS`.

### E2E-25 — old peer past expires_at is OUT: no recovery responder, local data safe  `multinode-network`
- **Setup:** old bob whose release `expires_at` is in the PAST per alice's manifest (trusted_time > expires_at + M). Alice = new, ceiling computed EXCLUDING bob (so ceiling may rise to 7). They share a workspace from before.
- **Action:** bob attempts to sync from alice; separately bob runs only LOCAL reads/replay.
- **Expect:** alice does NOT serve bob (no recovery responder — bob is sub-floor/expired and out); the connection is refused or not negotiated. Bob's LOCAL data remains intact: `con_old --db bob messages WORKSPACE`/`content-count` still render its existing facts; bob's wipe+replay still succeeds locally. Update is out-of-band.
- **Defends:** (5) expired/sub-floor peers are out, no recovery responder, local data safe (replays after update); (3) ceiling rises once blocker removed.
- **Refs:** transport negotiation (floor/head); `bootstrap_request`/`response`; ceiling = min over still-usable releases (expired excluded); local `messages`/`content-count`.

### E2E-26 — manifest-driven ceiling rise across a converged pair flips a capability to active on BOTH  `multinode-network`
- **Setup:** new alice + new bob, both initially ceiling 6 (an old release still in the fleet manifest pins it). Both can mint only tag-50 messages. Then the pinning old release passes `expires_at` and `trusted_time` advances past `expires_at + M` (via signed time observations / `clock`).
- **Action:** advance trusted time / refresh manifest on both; restart daemons; both recompute ceiling = 7.
- **Expect:** AFTER both rise, `send` now mints `content::message:2` (tag 56) on both, and the new derivation surfaces in `messages`; BEFORE the rise neither did. The flip is gated on `trusted_time > blocker.expires_at + M`, not on wall clock.
- **Defends:** (3) ceiling monotonicity / no-regression; trusted-time + skew-margin gate; ceiling-active = intro_version<=ceiling AND all still-usable releases transport it.
- **Refs:** manifest `expires_at`/`warn_after`; `clock` (trusted-time observation); `content::message` v1 vs v2 minting.

### E2E-27 — staleness window / clock rollback forces BLOCKED MODE: shared production withheld, local reads+replay run  `multinode-network`
- **Setup:** new alice + bob converged. Alice's trusted-time refresh stops for longer than the staleness window S (no signed observations), OR alice's clock rolls back beyond tolerance.
- **Action:** with alice in BLOCKED mode, attempt `con --db alice send WORKSPACE "blocked"` (shared production) AND `con --db alice messages WORKSPACE` (local read) AND a daemon restart (local replay).
- **Expect:** shared PRODUCTION is withheld — alice does not emit new facts to peers / the produce path is gated; but local READS (`messages`, `content-count`) still work and a wipe+replay on restart still rebuilds state. Bob does not receive new content from alice while blocked.
- **Defends:** blocked-mode rule (shared production withheld; local reads + replay still run); staleness window S; backward-rollback tolerance.
- **Refs:** trusted-time staleness/rollback; `send` (gated) vs `messages`/`content-count` (local); wipe+replay boot.

### E2E-28 — three-node mixed fleet: ceiling is the fleet-wide min, capability gated by the laggard  `multinode-network`
- **Setup:** `alice`=`con_new` (head 7), `bob`=`con_new` (head 7), `carol`=`con_old` (head 6, still usable). Shared workspace among all three. Fleet manifest lists all three; ceiling = min over still-usable = 6 (carol pins it).
- **Action:** alice `send WORKSPACE "fleet"`; sync to bob and carol.
- **Expect:** alice mints only tag-50 (not tag-56) because carol's presence pins the fleet ceiling to 6; all three render the message identically; bob (new) does NOT get a v2 derivation. Then remove carol from the fleet (expired) -> ceiling rises to 7 -> only THEN does alice/bob mint v2.
- **Defends:** (3) ceiling = min ACROSS ALL still-usable releases of supported_protocol.end(); (1); (2).
- **Refs:** three-daemon pattern (`three_player_sync_*`); manifest min computation; `content::message` v1/v2; `send`/`messages`.

### E2E-29 — upgrade-under-load with deps: queued sync-range --with-deps dropped, closure recomputed post-upgrade  `multinode-network`
- **Setup:** old alice with several `sync-range ... --with-deps` intents queued (`queued: yes`) but undelivered (bob on long `--sync-ms`). The queued closures reference facts alice holds.
- **Action:** upgrade alice (`stop` old, `start` new). Then re-issue a single `sync-range --with-deps` and let bob pull.
- **Expect:** the old queued intents are dropped on upgrade (not replayed); the NEW post-upgrade `sync-range --with-deps` recomputes the dependency closure from facts and delivers the full anchor set; bob's `fact_count`/`content-count` converge correctly with no duplicate or stale sends.
- **Defends:** upgrade intent-drop policy; (4) closure recomputed from facts (deterministic); dependency closure correctness.
- **Refs:** `sync-range --with-deps` -> `sync_range`; `share_fact_with_sync`/`send_requested_fact`; `HandlerRoute`; queued receipt.

### E2E-30 — new<->old: sealed bootstrap handshake negotiates a transport both speak  `multinode-network`
- **Setup:** new alice (can speak head transport 7) + old bob (floor..6). Unknown-peer first contact.
- **Action:** alice initiates a connection to bob via the bootstrap handshake (`bootstrap_request` -> `bootstrap_response`).
- **Expect:** the sealed frame validates (`frame[0]==46 && frame[1]==1` for the sealed request; response `47`), and the negotiated carrier version is one BOTH speak — alice initiates at the operational floor for the unknown peer, then negotiates UP to the highest mutually-supported; facts then flow over a `connection::frame_*` carrier the old node can decode.
- **Defends:** transport negotiation (initiate at floor when peer unknown; negotiate up between capable peers; answer in request's version); (5) transport in [floor,head].
- **Refs:** `bootstrap_request` (171)/`bootstrap_response` (172); `TYPE_SEALED_CONNECTION_REQUEST=46`/`=47` with internal VERSION=1; `connection_frame_wire.rs` `CONNECTION_FRAME_VERSION`/`TRNS`; `SendBootstrapConnectionRequestHandler`/`CreateConnectionResponseHandler`.

### E2E-31 — new creates / old reads: auth user/workspace anchor facts admit+project on old (full join round-trip)  `multinode-network`
- **Setup:** new alice host / old bob joining, ceiling 6 (`auth::workspace` 131, `auth::user` 14, `auth::endpoint_shared` 135 all ceiling-active).
- **Action:** `accept_workspace_invite(&alice, &bob, &workspace, alice_port, "bob", "bob-phone")` driving `con_old --db bob accept INVITE ...`.
- **Expect:** old bob admits and projects the workspace/user/endpoint facts (tags 131/14/135); `poll_for_workspace_member(&bob, &workspace, "bob", 10_000)` passes; `users WORKSPACE` on alice (new) and bob (old) list identical membership.
- **Defends:** (1) anchor facts admissible/projectable/displayable by every still-usable release; (2).
- **Refs:** `auth::workspace`(131)/`auth::user`(14)/`auth::endpoint_shared`(135); `accept` -> `accept`; `peers`/`users`; invite flow.

### E2E-32 — old creates / new reads: key-wrap material round-trips so new node decrypts old's content  `multinode-network`
- **Setup:** old alice creates a content key and wraps it for new bob's recipient key; ceiling 6 (`auth::key_wrap` 155, `auth::recipient_key` 150, `auth::removal_frontier` 151 ceiling-active).
- **Action:** `con_old --db alice key-wrap ...` after `con_new --db bob key-recipient WORKSPACE`; `sync_range_until_queued`; `poll_for_key_access(&bob, &workspace, <frontier>, "yes", 30_000)`.
- **Expect:** new bob gains key access (`poll_for_key_access` yes); bob can then `messages WORKSPACE`/decrypt alice's content authored under that key; key_wrap fact first byte = 155. The key material is ceiling-active and round-trips across the version gap.
- **Defends:** (1); (2); auth material transportability across releases.
- **Refs:** `auth::key_wrap`(155)/`auth::recipient_key`(150)/`auth::removal_frontier`(151); `key-wrap`/`key-recipient`; `CreateKeyWrapHandler`/`UnwrapKeyWrapHandler`; `poll_for_key_access`.
## 17. Platform, transition & pending activation

> Scope note: the ceiling/manifest/trusted-time/pending machinery in the
> consolidated model is **forward-looking** — `ReleaseManifestEntry`,
> `supported_protocol`, `trusted_time`, `intro_version`, `runs_during_replay`,
> ceiling filtering, and pending-retention do NOT yet exist in
> `/home/holmes/poc-10/src` (verified: zero hits for `ReleaseManifestEntry`,
> `supported_protocol`, `trusted_time`, `intro_version`, `runs_during_replay`,
> `ceiling`-as-protocol-term, `pending`-as-admission-term). Today an above-ceiling RECEIVED fact
> ERRORS at `RouterProjector::project` (`src/core/projectors.rs:456`,
> `"no target projector registered for fact tag {tag}"`). Each test below names
> the real entity it must attach to (the fact tag, the `FACT_ROUTES`/`projector_routes!`
> entry in `src/protocol/registry.rs`, the `con` CLI command, the `HANDLER_ROUTES`
> intent kind). Tests are written as the behavior the build must exhibit once the
> versioning knob lands; "today ERRORS" tests are guardrails that pin the current
> wrong behavior so the fix is observable.

This cluster fixes a concrete two-version scenario to keep cases comparable.
**protocol 6** = baseline `content::message` v1 (tag 50). **protocol 7** =
protocol 6 + `{content::message:2}` — a NEW tag (call it `content::message_v2`,
a sibling `message/_v2/` directory + kept-forever projector) with
`intro_version = 7`. The fleet manifest carries two platforms: `desktop` and
`mobile`, each a `ReleaseManifestEntry { release_id, platform,
supported_protocol: RangeInclusive<u32>, warn_after, expires_at, signature }`.
Skew margin = M, staleness window = S.

---

### E2EX-01 — Desktop and mobile at protocol 7 surface identical message rows  `multinode-network`
- **Setup:** Two `con` daemons, both binaries support protocol 7 (manifest: desktop release `supported_protocol=6..=7`, mobile release `supported_protocol=6..=7`); ceiling = min(7,7) = 7. Desktop creates a `content::message_v2` fact (tag, intro_version 7) carrying the v7 wire shape.
- **Action:** Desktop `con send` the v7 message; sync the fact to the mobile peer over a `connection::frame_small` (168) carrier; on mobile run `con messages` and `con view`.
- **Expect:** Mobile's `CONTENT_MESSAGES` read-model row content (body, sender, fact id, timestamp) is byte-identical to desktop's row for the same fact id. No platform field leaks into the row. Only presentation chrome (terminal width, color) may differ.
- **Defends:** (2) RENDERING UNIFORMITY — same protocol version => same read-model row regardless of platform.
- **Refs:** `content::message_v2` (sibling of tag 50 `TYPE_CONTENT_MESSAGE`), `registry.rs` `read_models` `CONTENT_MESSAGES`, `con messages`/`con view` (run fns `messages`/`view`), `connection::frame_small` 168.

### E2EX-02 — Desktop and mobile at protocol 6 surface identical v1 message rows  `multinode-network`
- **Setup:** Two `con` daemons, both pinned to protocol 6 (manifest desktop `6..=6`, mobile `6..=6`); ceiling = 6. Only `content::message` v1 (tag 50) facts exist.
- **Action:** Mobile `con send` a v1 message; sync to desktop; both run `con messages`.
- **Expect:** Identical `CONTENT_MESSAGES` rows on both platforms. The v2 projector exists in both binaries but is never invoked (no tag-50-v2 facts), and no v7 derivation is computed.
- **Defends:** (2) RENDERING UNIFORMITY at the OLD version; (5) READERS FOREVER (v1 reader still serves).
- **Refs:** `content::message` tag 50, `FACT_ROUTES` route for 50, `CONTENT_MESSAGES`.

### E2EX-03 — Mixed-platform same-version: presentation chrome differs, meaning does not  `multinode-network`
- **Setup:** Desktop release and mobile release both at ceiling 7. A single `content::message_v2` fact synced to both.
- **Action:** Render the message on each via `con view`.
- **Expect:** The semantic columns (decoded body, reactions count from `CONTENT_REACTIONS`, file refs) match exactly. Any difference is confined to chrome (e.g. mobile truncates display width) — assert the underlying row tuple read from `CONTENT_MESSAGES` is equal; chrome is computed AFTER the row, not inside the projector.
- **Defends:** (2) "only presentation chrome is platform-local".
- **Refs:** `con view` run fn `view`, `CONTENT_MESSAGES`/`CONTENT_REACTIONS` read-model tables (`registry.rs:36-182`).

### E2EX-04 — Mobile laggard caps the ceiling: v7 capability dormant on the DESKTOP that supports it  `multinode-network`
- **Setup:** Manifest: desktop release `supported_protocol=6..=7` (still usable, not expired), mobile release `supported_protocol=6..=6` (still usable, not expired). Ceiling = min over still-usable releases of `supported_protocol.end()` = min(7,6) = 6.
- **Action:** On the protocol-7-capable DESKTOP binary, attempt `con send` such that it would emit a `content::message_v2` fact (intro_version 7 > ceiling 6).
- **Expect:** Local creation of the above-ceiling fact is REFUSED — the desktop emits the v1 `content::message` (tag 50) instead, or refuses the v2-only operation, never minting an intro_version-7 fact while the ceiling is 6. The v2 capability is dormant.
- **Defends:** (1) VISIBILITY (a ceiling-active fact must be transportable by every still-usable release — v7 is not, so it is not ceiling-active); ADMISSION refusal of above-ceiling local creation.
- **Refs:** ceiling = min over manifest `supported_protocol.end()`, `content::message_v2` intro_version 7, `con send` run fn `send`, admission gate that today does NOT exist.

### E2EX-05 — Mobile laggard: v7 capability also dormant on the MOBILE laggard itself  `blackbox-cli`
- **Setup:** Same manifest as E2EX-04, but the action runs on the MOBILE laggard binary (which only speaks 6..=6).
- **Action:** On mobile, attempt any `con` path that would mint a `content::message_v2` (intro_version 7).
- **Expect:** Refused for the same ceiling reason (6 < 7) — but additionally the mobile binary has no v2 create/projector for protocol 7 at all, so it physically cannot. The observable is identical to E2EX-04: dormant on BOTH platforms.
- **Defends:** (1) VISIBILITY; the capability is dormant FLEET-WIDE, not just on the laggard.
- **Refs:** mobile `ReleaseManifestEntry.supported_protocol=6..=6`, `con send`.

### E2EX-06 — Mobile laggard: desktop renders existing v1 facts AT THE CEILING, withholds the v7 derivation  `projector-unit`
- **Setup:** Ceiling = 6 (mobile laggard). Retained facts include a `content::message` v1 (tag 50). The desktop binary CONTAINS the v7 derivation logic (e.g. a richer rendering of the same v1 facts gated at intro_version 7).
- **Action:** Run the protocol projector / read-model build on the desktop with ceiling 6.
- **Expect:** The desktop produces ceiling-6-era `CONTENT_MESSAGES` rows — identical to what the mobile laggard produces. The new v7 DERIVATION of the same v1 facts is WITHHELD until ceiling reaches 7. Clients render at the ceiling, not at their head.
- **Defends:** (2) "withhold a new DERIVATION of existing facts until ceiling-active"; (3) CEILING MONOTONICITY.
- **Refs:** projector selection by ceiling, `CONTENT_MESSAGES`, ceiling-filtered head rendering.

### E2EX-07 — Mobile release expires; trusted time crosses expires_at + M; ceiling rises 6 -> 7  `multinode-network`
- **Setup:** Manifest: mobile release `6..=6` with `expires_at = T`; desktop release `6..=7`. Ceiling currently 6 (mobile is the blocker). Skew margin M. trusted_time = monotonic max of signed observations.
- **Action:** Advance trusted_time past `T + M` (feed signed observations), then refresh the ceiling computation.
- **Expect:** The mobile release is no longer "still-usable" (past expires_at). Ceiling recomputes to min over remaining still-usable releases = desktop's `supported_protocol.end()` = 7. The ceiling transition is observed only AFTER `trusted_time > blocker.expires_at + M`, never at exactly `expires_at`.
- **Defends:** (3) CEILING MONOTONICITY; TRUSTED TIME skew margin M.
- **Refs:** `expires_at`, skew margin M, trusted_time monotonic-max, ceiling = min over still-usable `supported_protocol.end()`.

### E2EX-08 — Ceiling transition gated by M: at trusted_time == expires_at (before +M) ceiling stays 6  `handler-unit`
- **Setup:** Same manifest as E2EX-07. trusted_time advanced to exactly `T` (= mobile expires_at), but NOT past `T + M`.
- **Action:** Recompute ceiling.
- **Expect:** Ceiling stays 6. The mobile release is treated as still-usable until the margin clears; no v7 fact may be created locally yet.
- **Defends:** (3) + skew margin: "advance the ceiling only at trusted_time > blocker.expires_at + M".
- **Refs:** skew margin M, ceiling recompute, `expires_at`.

### E2EX-09 — CEILING TRANSITION: NEW binary now creates v_next once ceiling reaches 7  `blackbox-cli`
- **Setup:** Post-transition state of E2EX-07: mobile expired, ceiling = 7, desktop (new binary, `6..=7`) is the only still-usable release.
- **Action:** On the new binary run `con send` for a message that the v7 surface produces.
- **Expect:** A `content::message_v2` fact (intro_version 7) is now CREATED and admitted locally (previously refused at ceiling 6). It is projected, displayed, and counted via `con content-count`/`con messages`.
- **Defends:** ADMISSION (above-ceiling-no-more once ceiling rises); CEILING TRANSITION new-binary creates v_next.
- **Refs:** `content::message_v2` intro_version 7, `con send`, `con content-count` (run fn `content_count`).

### E2EX-10 — CEILING TRANSITION: previously-PENDING v_next facts ACTIVATE on the next wipe+replay  `replay-cli`
- **Setup:** Before the transition (ceiling 6), the new binary RECEIVED a `content::message_v2` fact (intro_version 7) from an alpha/ahead peer; it was PENDING — retained as opaque bytes, unprojected, undisplayed, uncounted, NOT dropped. After E2EX-07 the ceiling is now 7.
- **Action:** Run `con` wipe + replay (rebuild derived state) over the full retained fact log.
- **Expect:** On replay the pending `content::message_v2` fact now routes to its tag's projector (ceiling 7 covers intro_version 7), so it ACTIVATES: it projects into `CONTENT_MESSAGES`, becomes displayable via `con messages`, and is counted by `con content-count`. No fact was lost across the pending window.
- **Defends:** ADMISSION ("Pending facts ACTIVATE on the next wipe+replay once the ceiling rises to cover their tag"); (4) REPLAY DETERMINISM.
- **Refs:** pending retention, `RouterProjector::project` (`projectors.rs:454-458`), `content::message_v2` projector, `CONTENT_MESSAGES`.

### E2EX-11 — Pending retention guardrail: a received above-ceiling fact is RETAINED, not dropped/errored (today it ERRORS)  `guardrail`
- **Setup:** Ceiling 6. Feed a received fact with an unknown/above-ceiling tag (e.g. `content::message_v2`, or any intro_version-7 tag) into the projection path.
- **Action:** Project the fact through `RouterProjector::project`.
- **Expect (target):** The fact is PENDING — stored as opaque bytes, no projection output, not surfaced, not counted, NOT errored, NOT dropped. **Today's actual:** `Err("no target projector registered for fact tag {tag}")` at `src/core/projectors.rs:456`. This test pins the gap so the fix is observable: above-ceiling => pending, not Err.
- **Defends:** ADMISSION pending semantics; (5)/(6) facts not destroyed.
- **Refs:** `src/core/projectors.rs:454-458` (unknown-tag Err), `RouterProjector`, `FactRoute`.

### E2EX-12 — Old binary is OUT after the transition: expired desktop pinned to 6 cannot create or transport  `multinode-network`
- **Setup:** Post-transition, ceiling 7. A stale "old binary" desktop release pinned `6..=6` whose own `expires_at` has now passed (trusted_time > its expires_at + M).
- **Action:** The old binary attempts to join the workspace and `con send`.
- **Expect:** The old binary is OUT — it is past expiry, no longer a still-usable release, so it does not factor into the ceiling, and it cannot transport ceiling-active v7 facts. There is NO recovery responder for it. Update is out-of-band. Its LOCAL data is safe (it replays after update).
- **Defends:** (5) EXPIRED/SUB-FLOOR PEERS ARE OUT; (3) ceiling computed only over still-usable releases.
- **Refs:** `expires_at`, "no recovery responder", local-data-safe replay, ceiling = min over still-usable releases.

### E2EX-13 — ALPHA above-ceiling leak: alpha at head emits v_next into a SHARED workspace; production holds it pending  `multinode-network`
- **Setup:** A shared workspace with two members: an ALPHA build at head (knows protocol 7, ignores the production ceiling) and a PRODUCTION build at ceiling 6 (mobile laggard still present). Alpha mints a `content::message_v2` (intro_version 7) directly into the shared workspace.
- **Action:** The v7 fact syncs (via `share_fact_with_sync` / `connection::frame_small`) to the production peer.
- **Expect:** Production holds the v7 fact pending — pending opaque, unprojected, uncounted, undisplayed, not errored. Production's `CONTENT_MESSAGES`/`con messages` does not show it. Production keeps running at ceiling 6.
- **Defends:** ADMISSION pending of a RECEIVED above-ceiling fact; (3) production does not regress to honor an alpha-only capability.
- **Refs:** `share_fact_with_sync` HANDLER_ROUTE (`ShareFactWithSyncHandler`), `content::message_v2`, pending, `con messages`.

### E2EX-14 — ALPHA leak: production keeps the DEPENDENCY CLOSURE of a pending v_next fact  `projector-unit`
- **Setup:** Alpha emits a `content::message_v2` (v7) PLUS its dependencies — e.g. a `content::file` (tag 54) and `content::file_slice` (tag 55) it references, all sub-ceiling-7. Production at ceiling 6 holds the v2 message pending.
- **Action:** Production receives the whole bundle and runs projection.
- **Expect:** Production RETAINS the full dependency closure (the file/file_slice facts AND the pending v2 message bytes) so that a later replay at ceiling 7 can activate the v2 message with its dependencies intact. The dependencies that are themselves ceiling-active (<=6) DO project now; only the v7 message stays pending.
- **Defends:** ADMISSION ("keeps dependency closure"); (4) REPLAY DETERMINISM needs the closure retained.
- **Refs:** `content::file` 54, `content::file_slice` 55, `content::message_v2`, pending closure retention.

### E2EX-15 — ALPHA leak: production ACTIVATES the pending v_next ONLY after the ceiling reaches v_next  `replay-cli`
- **Setup:** Continuation of E2EX-13/14. The mobile laggard later expires (trusted_time > expires_at + M); production's ceiling rises to 7. The pending alpha `content::message_v2` and its closure are still retained.
- **Action:** Production runs wipe + replay.
- **Expect:** The previously-pending v2 message now activates (ceiling 7 >= intro_version 7), projecting into `CONTENT_MESSAGES` together with its already-projected dependency closure. Activation happens at replay time, not at receive time, and ONLY after the ceiling crossed.
- **Defends:** ADMISSION ("activates only after ceiling reaches v_next"); (4) REPLAY DETERMINISM (ceiling-independent replay via the historical adapter keyed by each fact's OWN tag).
- **Refs:** pending activation, `content::message_v2` projector keyed by tag, `CONTENT_MESSAGES`, ceiling = 7 post-transition.

### E2EX-16 — Sub-floor peer attempts to connect and is REFUSED  `multinode-network`
- **Setup:** Operational floor = protocol 6 (no still-usable release speaks below 6). A peer arrives speaking a sub-floor transport (protocol 5, i.e. below the floor — e.g. it offers a retired connection-frame/sealed-handshake shape).
- **Action:** The sub-floor peer initiates a `connection::bootstrap_request` (fact 171, sealed `TYPE_SEALED_CONNECTION_REQUEST=46`/internal VERSION) at the sub-floor wire shape.
- **Expect:** The connection is REFUSED. The local node does NOT spin up a recovery responder. No facts are shared with the sub-floor peer; the sealed-request validation/handshake rejects it. Update is out-of-band.
- **Defends:** (5) EXPIRED/SUB-FLOOR PEERS ARE OUT; TRANSPORT in [floor, head] (drop sub-floor).
- **Refs:** `connection::bootstrap_request` 171, `validate_sealed_connection_request_frame` (`bootstrap_request/layout.rs:84`, rejects unless `frame[0]==46 && frame[1]==1`), operational floor.

### E2EX-17 — Sub-floor peer refusal is observable at the sealed-handshake authenticator/opener (frame[1] version mismatch)  `handler-unit`
- **Setup:** A sealed connection-request frame whose header version byte is below the current internal `VERSION` (sub-floor), i.e. `frame[1] != 1`.
- **Action:** Call `validate_sealed_connection_request_frame` on the sub-floor frame, then drive `SendBootstrapConnectionRequestHandler` / `CreateConnectionResponseHandler`.
- **Expect:** `validate_sealed_connection_request_frame` returns Err (version mismatch), the bootstrap fact is never minted, and no `connection::response` (44) is created — the peer gets no answer (no recovery responder).
- **Defends:** (5) sub-floor refusal; (6) SAFETY FLOOR (only safe versions admitted).
- **Refs:** `bootstrap_request/layout.rs:84-90` (`validate_sealed_connection_request_frame`, `frame[1] != VERSION`), `connection::response` 44, `CreateConnectionResponseHandler` HANDLER_ROUTE.

### E2EX-18 — Still-usable OLDER peer is answered IN ITS OWN version (not refused)  `multinode-network`
- **Setup:** Floor 6, ceiling 7. A peer at protocol 6 (within [floor,head], still usable, NOT sub-floor) connects.
- **Action:** The protocol-6 peer requests facts; local node at protocol 7 responds.
- **Expect:** Local node ANSWERS in the request's version — it transports only ceiling-active facts the 6-peer can accept, negotiating UP only if both are capable. It does NOT refuse the 6-peer (contrast with E2EX-16). No v7-only `content::message_v2` is pushed to the 6-peer.
- **Defends:** (1) VISIBILITY (ceiling-active facts transportable by every still-usable release); TRANSPORT "answer in the request's version for a still-usable older peer".
- **Refs:** `send_requested_fact`/`SendRequestedFactHandler`, `share_fact_with_sync`, transport negotiate-up, `content::message_v2` withheld from 6-peer.

### E2EX-19 — Fleet-wide manifest: a DESKTOP build waits on a MOBILE release expiry to unlock v7  `multinode-network`
- **Setup:** Signed fleet manifest with desktop `6..=7` and mobile `6..=6` (`expires_at = T`). Desktop binary is fully v7-capable. Ceiling = 6 because the mobile entry caps it. trusted_time < T + M.
- **Action:** Desktop attempts to start emitting v7 (`content::message_v2`) facts.
- **Expect:** Desktop is BLOCKED from v7 by the fleet-wide manifest — it waits for the mobile release to expire. The constraint comes from a SIGNED manifest entry for a DIFFERENT platform, not from the desktop's own capability. Only after mobile's `expires_at + M` (E2EX-07) does desktop unlock v7.
- **Defends:** CEILING = min over still-usable releases ACROSS ALL PLATFORMS; (3) CEILING MONOTONICITY; fleet-wide signed manifest.
- **Refs:** `ReleaseManifestEntry{platform, supported_protocol, expires_at, signature}`, ceiling across platforms, `content::message_v2` intro_version 7.

### E2EX-20 — Fleet manifest signature gate: unsigned/forged mobile-expiry entry does NOT raise the ceiling  `guardrail`
- **Setup:** Same as E2EX-19, but an attacker presents an UNSIGNED (or bad-signature) `ReleaseManifestEntry` that claims the mobile release expired early, attempting to prematurely raise the ceiling to 7.
- **Action:** Feed the forged entry; recompute ceiling.
- **Expect:** The forged entry is rejected at signature verification; the mobile `6..=6` entry remains in force; ceiling stays 6. The desktop still cannot mint v7. Only validly-signed manifest changes move the ceiling.
- **Defends:** Fleet-wide SIGNED manifest integrity; (3) ceiling cannot be illegitimately advanced.
- **Refs:** `ReleaseManifestEntry.signature`, ceiling recompute.

### E2EX-21 — Carrier capacity GATES v7 ceiling activation even when manifest allows it (chunk-don't-grow)  `projector-unit`
- **Setup:** Manifest permits ceiling 7 (mobile expired), but the v7 `content::message_v2` wire shape would exceed `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` (4 KiB) and there is no carrier that can transport it intact.
- **Action:** Attempt to mark the v7 capability ceiling-active and transport a v7 fact.
- **Expect:** Activation is GATED by carrier capacity — a capability is ceiling-active iff `intro_version <= ceiling` AND every still-usable release can TRANSPORT it. If the v7 fact does not fit a size class, it must chunk (the `file_slice` precedent: `frame_file_slice` 169 / `frame_bundle` 170) rather than grow the frame. A too-big-to-carry capability stays dormant.
- **Defends:** "Carrier capacity GATES ceiling activation (chunk-don't-grow; the file_slice precedent)"; (1) transportable-by-every-release.
- **Refs:** `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` (4 KiB), `connection::frame_file_slice` 169, `connection::frame_bundle` 170, `connection_frame_wire.rs`.

### E2EX-22 — BLOCKED MODE on staleness window S: shared production withheld, local reads + replay still run  `blackbox-cli`
- **Setup:** Ceiling 7 reached. Node then goes without a trusted-time refresh for longer than staleness window S (no new signed observations).
- **Action:** After S elapses, run `con send` (would share to peers), then `con messages` (local read) and a wipe+replay.
- **Expect:** Node enters BLOCKED MODE: shared/production output is WITHHELD (no new facts pushed to peers, no new above-prior-ceiling minting), BUT local reads (`con messages`, `con view`) and `con` replay STILL RUN over retained facts. The node is read-only/replay-safe, not dead.
- **Defends:** "Staleness window S without refresh ... => BLOCKED MODE (shared production withheld; local reads + replay still run)."
- **Refs:** staleness window S, trusted_time refresh, `con send`/`con messages`, replay.

### E2EX-23 — BLOCKED MODE on backward clock rollback beyond tolerance  `handler-unit`
- **Setup:** Ceiling 7, trusted_time at some monotonic max. A signed observation arrives that would move trusted_time BACKWARD beyond the rollback tolerance (clock rolled back).
- **Action:** Feed the backward observation; attempt `con send`.
- **Expect:** trusted_time is NOT decreased (it is a monotonic max / lower bound), and the rollback-beyond-tolerance triggers BLOCKED MODE: shared production withheld; local reads + replay continue. The ceiling is NOT lowered by the rollback (no ceiling regression).
- **Defends:** TRUSTED TIME monotonicity; BLOCKED MODE on backward rollback; (3) no ceiling regression.
- **Refs:** trusted_time monotonic-max, rollback tolerance, BLOCKED MODE.

### E2EX-24 — Per-scope uniformity: AUTH fact (workspace) surfaces identically on desktop and mobile at same version  `multinode-network`
- **Setup:** Desktop and mobile both at ceiling 7. An `auth::workspace` (tag 131) and `auth::user` (tag 14) created on desktop, synced to mobile.
- **Action:** Run `con workspaces` and `con users` on both.
- **Expect:** Identical workspace/user row content on both platforms (`auth::workspace`/`auth::user` read-models). Auth meaning is platform-independent at the same protocol version. (Enumerated as a separate scope from content per the no-collapse instruction.)
- **Defends:** (2) RENDERING UNIFORMITY for the AUTH scope.
- **Refs:** `auth::workspace` 131, `auth::user` 14, `con workspaces`/`con users` (run fns `workspaces`/`users`).

### E2EX-25 — Per-scope uniformity: SYNC fact (shared_fact) surfaces identically across platforms at same version  `multinode-network`
- **Setup:** Desktop and mobile both at ceiling 7. A `sync::shared_fact` (tag 162) flows between them; `con sync-status` queried on both.
- **Action:** Run `con sync-status` and `con sync-range` on each platform after a sync round.
- **Expect:** Identical sync state (have/need/compare-derived rows) on both. Sync meaning is platform-independent at the same protocol version. (Separate scope from content/auth.)
- **Defends:** (2) RENDERING UNIFORMITY for the SYNC scope.
- **Refs:** `sync::shared_fact` 162, `sync::compare` 165 / `sync::have_id` 166 / `sync::need_id` 167, `con sync-status`/`con sync-range` (run fns `sync_status`/`sync_range`).

### E2EX-26 — Per-scope laggard dormancy: a v7 CONNECTION-frame capability is dormant on both platforms while mobile lags  `projector-unit`
- **Setup:** Ceiling capped at 6 by mobile laggard. A protocol-7 connection-frame variant (a new `connection::frame_*` tag with intro_version 7) exists in the desktop binary.
- **Action:** Desktop attempts to send facts using the v7 frame carrier.
- **Expect:** The v7 frame carrier is dormant (intro_version 7 > ceiling 6); desktop falls back to the ceiling-6 carriers (`frame_small` 168 / `frame_file_slice` 169 / `frame_bundle` 170). No v7 frame is emitted into the shared workspace. (CONNECTION scope, distinct from content/auth/sync dormancy.)
- **Defends:** (1) VISIBILITY for the CONNECTION scope; ceiling-filtered route activation.
- **Refs:** `connection::frame_small/file_slice/bundle` 168/169/170, RouterProjector ceiling-filtering, intro_version on routes.

### E2EX-27 — Ceiling-filtered router: a route whose intro_version > ceiling is INACTIVE (sub-ceiling routes active)  `projector-unit`
- **Setup:** `RouterProjector` over `FACT_ROUTES` (`registry.rs:568` `RouterProjector::new(FACT_ROUTES, &[])`), augmented with per-route `intro_version`. Ceiling = 6. Routes for tag 50 (`content::message` v1, intro <=6) and the v7 `content::message_v2` route (intro 7) both registered.
- **Action:** Project a tag-50 fact and a v2 fact at ceiling 6.
- **Expect:** The tag-50 route is ACTIVE (projects normally); the v7 route is INACTIVE/ceiling-filtered (the v2 fact is pending, not projected). When ceiling rises to 7 the v7 route becomes active. The router selects active routes by `intro_version <= ceiling`.
- **Defends:** "The router (RouterProjector over FACT_ROUTES) is CEILING-FILTERED (only routes with intro_version<=ceiling active)."
- **Refs:** `RouterProjector` (`projectors.rs:423-459`), `FACT_ROUTES`/`projector_routes!` (`registry.rs:584-593`), intro_version per route.

### E2EX-28 — CliCommand version selection: absent v7 bucket entry => reuse previous run fn (param-subset contract)  `blackbox-cli`
- **Setup:** Ceiling rises to 7. The `send` `CliCommand` (stable name -> version-tagged run fns) has NO v7 bucket entry because the v7 message change did NOT alter the input surface. v7 `required_inputs` ⊆ active v6 `collected_params`.
- **Action:** Run `con send` at ceiling 7.
- **Expect:** The CLI reuses the previous (v6) `send` run fn — the highest intro_version <= ceiling with a bucket entry — and it correctly produces the v7 `content::message_v2` fact because the input parameters are compatible (param-subset contract holds). No "missing command bucket" error.
- **Defends:** "CliCommand ... an ABSENT bucket entry => reuse previous (asserts parameter compatibility)"; VERSION BUCKETS cli-only-if-input-surface-changed.
- **Refs:** `MATCH_COMMANDS` `send` (run fn `send`, `content::message::cli`), CliCommand version-tagged run-fn list, `v_next.required_inputs ⊆ active_cli.collected_params`.

### E2EX-29 — Replay is CEILING-INDEPENDENT: same retained log replays to the same state at ceiling 6 and ceiling 7 for sub-ceiling facts  `replay-cli`
- **Setup:** A retained log of only sub-ceiling-6 facts (no v7 facts, no pending facts). Two replay passes: one with ceiling pinned at 6, one at 7.
- **Action:** Wipe + replay the same log at each ceiling.
- **Expect:** Both passes rebuild identical derived state for the sub-ceiling facts — each fact replays via the historical adapter keyed by its OWN tag, independent of the ambient ceiling. (Contrast E2EX-10/15: a ceiling rise only ADDS activation of pending v_next facts; it never changes how sub-ceiling facts replay.)
- **Defends:** (4) REPLAY DETERMINISM — "ceiling-independent; every retained fact replays via the historical adapter keyed by its OWN tag".
- **Refs:** replay adapter keyed by fact tag, `FACT_ROUTES`, `RouterProjector`.

### E2EX-30 — Retire connections before replay during a ceiling transition  `handler-unit`
- **Setup:** Mid-transition (mobile expiring). Open connections exist; a wipe+replay is about to run to activate pending v7 facts (E2EX-10).
- **Action:** Trigger the pre-replay connection retirement, then replay.
- **Expect:** Connections are retired via `connection::close` (45) / upgrade-retirement facts BEFORE the replay pass; the replay does not race live frame traffic; after replay, peers re-handshake at the new ceiling (7). No half-open connection survives the ceiling change.
- **Defends:** TRANSPORT "Retire connections (connection_close/upgrade-retirement facts) before replay"; (4) deterministic replay.
- **Refs:** `connection::close` 45, wipe+replay, `connection::bootstrap_request` 171 re-handshake.
## 18. Structural / registry / boundary guardrails

These guardrails are STRUCTURE tests in the spirit of the existing
`tests/poc10_architecture_boundary_test.rs`, `tests/poc10_protocol_registry_test.rs`,
and the `registry.rs::fact_route_tags_are_globally_unique` unit test. They assume
the target versioning machinery exists: `FactRoute`/`HandlerRoute`/`CliCommand`
each carry `intro_version: u32`, `HandlerRoute` also carries
`runs_during_replay: bool`, and a fleet-wide signed `ReleaseManifestEntry`
declares per-platform `supported_protocol: RangeInclusive<u32>`. The CEILING is the
min over still-usable releases of `supported_protocol.end()` at trusted_time. Where
the machinery does not yet exist on the checkout (verified: `intro_version`,
`runs_during_replay`, `ReleaseManifestEntry`, `ceiling`, `pending` are ALL absent
from `src/` today, and the unknown-tag path ERRORS at `projectors.rs:456`), the test
is RED and pins the target. Each test names the exact real entity it guards.

Notation: "new version" = a fact family / bucket introduced at a higher
`intro_version` than the ceiling; "old version" = a family at or below the floor.
Scopes are the four real ones: `auth`, `content`, `connection`, `sync`.

---

### GUARD-01 — every FactRoute in FACT_ROUTES declares an intro_version  `guardrail`
- **Setup:** the assembled `FACT_ROUTES` table in `src/protocol/registry.rs` (47 entries: 43 authenticated fact families plus four sealed transit carriers) with the target `FactRoute { tag, projector, replayed, intro_version }` shape from `src/core/projectors.rs:402`.
- **Action:** iterate `FACT_ROUTES`; for each route read `route.intro_version`.
- **Expect:** the table compiles only because every `projector_routes!` line supplies an `intro_version`; the test additionally asserts `FACT_ROUTES.len() == 47` and that every `intro_version` is a concrete `u32` (no `Option`, no default-zero sentinel) — i.e. the macro `projector_routes!` requires the field. A route lacking it fails to compile.
- **Defends:** Mechanism "ROUTES carry intro_version"; underpins invariant (1) VISIBILITY and (3) CEILING MONOTONICITY (a route the ceiling cannot place is meaningless).
- **Refs:** `src/protocol/registry.rs` `projector_routes!`/`FACT_ROUTES` (593-637), `src/core/projectors.rs:402` `FactRoute`.

### GUARD-02 — every HandlerRoute in HANDLER_ROUTES declares an intro_version  `guardrail`
- **Setup:** the 17-entry `HANDLER_ROUTES` table (registry.rs 711-831) with target `HandlerRoute { name, intent_kind, factory, intro_version, runs_during_replay }` (runtime.rs:71).
- **Action:** iterate `HANDLER_ROUTES`; read `route.intro_version` for each of the 17 intent kinds (`send_bootstrap_connection_request` … `receive_network_frame`).
- **Expect:** all 17 routes carry an `intro_version`; `HANDLER_ROUTES.len() == 17`; the `handler_route!` macro forces the field so omission does not compile.
- **Defends:** Mechanism "ROUTES carry intro_version" for intent handlers; supports CEILING-FILTERED router (only intro_version<=ceiling handlers active).
- **Refs:** `src/protocol/registry.rs` `HANDLER_ROUTES`/`handler_route!` (639-710), `src/core/runtime.rs:71`.

### GUARD-03 — every CliCommand in MATCH_COMMANDS declares an intro_version  `guardrail`
- **Setup:** the 47-entry `MATCH_COMMANDS` table (registry.rs 367-526) with target `CliCommand { name, usage, help, run, intro_version }` and the per-name version-tagged run list.
- **Action:** iterate `MATCH_COMMANDS`; read `intro_version` for each of the 47 stable names (`create-workspace` … `recurring-intents`, including `test-generate-deps` and `test-replay-deps-reverse`).
- **Expect:** all 47 commands carry an `intro_version`; `MATCH_COMMANDS.len() == 47`; the `cli_command!` macro forces the field. Asserts `key-rotate-recipient` maps to run fn `key_recipient_rotation` AND carries an `intro_version` (guards the name/fn mismatch noted in the inventory).
- **Defends:** Mechanism "CliCommand = stable name -> version-tagged list; ceiling selects highest intro_version<=ceiling".
- **Refs:** `src/protocol/registry.rs` `MATCH_COMMANDS`/`cli_command!` (356-510), `src/core/cli.rs` `CliCommand`.

### GUARD-04 — every HandlerRoute declares runs_during_replay explicitly  `guardrail`
- **Setup:** target `HandlerRoute` with `runs_during_replay: bool` (runtime.rs:71); the 17 routes.
- **Action:** iterate `HANDLER_ROUTES`; read `route.runs_during_replay`.
- **Expect:** every route carries an explicit `bool` (no inferred default). The 4 names in `COMMAND_EXCLUDED_HANDLER_ROUTES` (`send_bootstrap_connection_request`, `send_facts_on_connection`, `send_network_frame`, `receive_network_frame`) — the daemon/network IO handlers — assert `runs_during_replay == false` (replay must not re-emit live network frames); the remaining 13 (e.g. `share_fact_with_sync`, `create_key_wrap`, `unwrap_key_wrap`) assert a deliberate declared value. Omitting the field does not compile.
- **Defends:** Invariant (4) REPLAY DETERMINISM — replay reruns only deterministic, replay-safe handlers; no live network side effects on wipe+replay.
- **Refs:** `src/core/runtime.rs:71` `HandlerRoute`, `src/protocol/registry.rs` `COMMAND_EXCLUDED_HANDLER_ROUTES` (512-517), `HANDLER_ROUTES` (649-710).

### GUARD-05 — new auth fact family ships a complete manifest entry (auth scope)  `guardrail`
- **Setup:** introduce the proposed `auth::user_profile_v2` family at a new `intro_version` above the ceiling (the inventory confirms it does NOT exist yet; this guard runs when it is added).
- **Action:** load the fleet manifest source and the new family's manifest declaration; assert all six required fields per the plan doc (Part I above).
- **Expect:** the entry names (a) the fact `tag` (a fresh `u8`, e.g. not colliding with 14/`auth::user`); (b) its `intro_version`; (c) the blocking non-capable releases AND their `expires_at`; (d) the kept-forever old adapter (`user_v1` adapter preserved); (e) the security-deprecation policy (plaintext-name suppression policy); (f) the replay output (rows the projector emits). A family added with any field missing fails the guard.
- **Defends:** Mechanism "Adding a fact family requires a manifest entry naming releases, blockers+expiries, old adapters, security policy, replay output."
- **Refs:** `docs/research/Part I above` (114-140, 299-302), target `ReleaseManifestEntry`, `src/protocol/auth.rs` (scope manifest), `auth::user` (tag 14) as the superseded anchor.

### GUARD-06 — new content fact family ships a complete manifest entry (content scope)  `guardrail`
- **Setup:** introduce a hypothetical new content fact (e.g. a new message-body encoding `content::message` v2 delta) at a new `intro_version`.
- **Action:** assert the same six-field manifest entry for the content-scope family bucket.
- **Expect:** entry declares tag (the existing `TYPE_CONTENT_MESSAGE=50` is reused by tag; the bucket carries the version delta), intro_version, blocking releases + expiries, the kept-forever v1 message adapter (`ContentMessageProjector`), security policy (unsafe-encoding -> suppress/tighten), and replay output (`CONTENT_MESSAGE_ROWS`). Missing any field fails.
- **Defends:** Same manifest mechanism, content scope; supports invariant (5) READERS FOREVER (v1 message reader kept).
- **Refs:** `docs/research/Part I above` (276, 299-302), `content::message::project::ContentMessageProjector`, `registry.rs` `CONTENT_MESSAGE_ROWS`.

### GUARD-07 — new connection frame family ships a complete manifest entry (connection scope)  `guardrail`
- **Setup:** introduce a new connection frame size class / wire shape as a new `connection::frame_*` family (a new tag beyond 168/169/170/173) at a new `intro_version`, per "incompatible wire shape => new tag".
- **Action:** assert the six-field manifest entry; additionally assert the manifest names the carrier-capacity gate (chunk-don't-grow / file_slice precedent) because connection frames gate ceiling activation.
- **Expect:** entry declares fresh tag, intro_version, blocking releases + expiries, kept-forever old frame adapters (`ConnectionFrameSmallProjector` etc. preserved as transport readers while a still-usable release speaks them), security policy, replay output. Carrier-capacity note present.
- **Defends:** Manifest mechanism, connection scope; "Carrier capacity GATES ceiling activation."
- **Refs:** `src/protocol/connection_frame_wire.rs` (TRNS magic, size classes), `connection::frame_small`/`frame_file_slice`/`frame_bundle` (168/169/170), `docs/research/Part I above` (299-302).

### GUARD-08 — new sync fact family ships a complete manifest entry (sync scope)  `guardrail`
- **Setup:** introduce a new sync coordination fact (e.g. a v2 compare/negentropy encoding) as a new family at a new `intro_version`.
- **Action:** assert the six-field manifest entry for the sync-scope bucket.
- **Expect:** entry declares fresh tag (beyond 160/162/164-167/2), intro_version, blocking releases + expiries, kept-forever old sync adapter (`SyncCompareProjector` etc.), security policy, replay output. Missing any field fails.
- **Defends:** Manifest mechanism, sync scope.
- **Refs:** `sync::compare` (165) `SyncCompareProjector`, `sync::shared_fact` (162), `docs/research/Part I above` (299-302).

### GUARD-09 — no production path admits an above-ceiling fact (admission boundary)  `guardrail`
- **Setup:** a fleet manifest with ceiling C; a fact family whose `intro_version > C`; the admission/submit boundary (`Runtime::submit_fact` runtime.rs:268, `submit_facts` :274) wired to a ceiling check.
- **Action:** statically assert (grep-style boundary test over `src/core` + scope dirs) that the only entry points creating/admitting facts route through a single ceiling gate, and dynamically (unit) submit an above-ceiling fact via `submit_fact`.
- **Expect:** local creation is REFUSED (returns an admission error, not a panic, not silent acceptance). No `src/protocol/**/create.rs` constructor and no command run-fn can mint a fact whose tag's `intro_version > ceiling`. The boundary test finds zero fact-minting paths that bypass the gate.
- **Defends:** ADMISSION "local creation of an above-ceiling fact is REFUSED"; invariant (1) VISIBILITY.
- **Refs:** `src/core/runtime.rs:268` `submit_fact`/`:274` `submit_facts`, `src/protocol/*/*/create.rs`, target ceiling gate.

### GUARD-10 — no production path projects an above-ceiling fact's rows  `guardrail`
- **Setup:** ceiling C; a retained fact with tag whose `intro_version > C` (e.g. a received-but-not-yet-active fact).
- **Action:** run projection (`ProtocolProjector::project` -> `RouterProjector`) over that fact through the production path.
- **Expect:** the router does NOT emit read-model rows for the above-ceiling fact; it is uncounted and undisplayed. The CEILING-FILTERED router only activates routes with `intro_version<=ceiling`. (Contrast: today the unfiltered router would dispatch to the projector or error at projectors.rs:456 — the test pins the pending path instead.)
- **Defends:** ADMISSION (uncounted/undisplayed); invariant (2) RENDERING UNIFORMITY ("clients render AT THE CEILING, not their head").
- **Refs:** `src/protocol/registry.rs:568` `RouterProjector::new(FACT_ROUTES, &[])`, `src/core/projectors.rs:448-459`.

### GUARD-11 — no production path displays an above-ceiling fact (CLI surface)  `guardrail`
- **Setup:** ceiling C; an above-ceiling fact retained as opaque bytes; a read CLI command (`messages`, `view`, `files`, `content-count`, `count`).
- **Action:** invoke each read command via the `con` CLI / `MatchCliContext`.
- **Expect:** output omits the above-ceiling fact entirely; `content-count`/`count` do not include it in totals. No read query in any `queries.rs` surfaces opaque above-ceiling bytes.
- **Defends:** ADMISSION (undisplayed/uncounted), invariant (2).
- **Refs:** `content::message::cli` (`messages`, `view`, `files`, `content-count`), `auth::workspace::cli` (`count`), `read_models` typed tables (registry.rs 36-182).

### GUARD-12 — unknown-tag projection path holds pending instead of erroring  `guardrail`
- **Setup:** a received fact whose first byte (effective tag) matches no entry in `FACT_ROUTES` (an above-ceiling/unknown family).
- **Action:** project it through the production projector path.
- **Expect:** the fact is retained as opaque bytes, unprojected, undisplayed, uncounted — NOT dropped, NOT errored. Specifically the path must NOT return `Err("no target projector registered for fact tag {tag}")` (today's behavior at `src/core/projectors.rs:456`). The target replaces that hard error with a pending outcome.
- **Defends:** ADMISSION "received above-ceiling fact is PENDING … NOT dropped, NOT errored — today it ERRORS at projectors.rs:454".
- **Refs:** `src/core/projectors.rs:455-457` (the `Err(format!(...))`), `RouterProjector::project`.

### GUARD-13 — pending fact activates on next wipe+replay once ceiling rises  `replay-cli`
- **Setup:** an above-ceiling fact pending under ceiling C; then a manifest change raises the ceiling to C' >= the fact's `intro_version`.
- **Action:** perform wipe + replay (the upgrade path) and re-project all retained facts.
- **Expect:** the formerly pending fact now routes to its registered projector and produces its rows; it is counted/displayed. No re-receipt over the network is required — activation comes purely from replay at the higher ceiling.
- **Defends:** ADMISSION "Pending facts ACTIVATE on the next wipe+replay once the ceiling rises to cover their tag"; invariant (4) REPLAY DETERMINISM.
- **Refs:** target wipe+replay path, `RouterProjector`, `FACT_ROUTES` intro_version filter.

### GUARD-14 — sibling _vN/ dir has no mod.rs (role-file convention)  `guardrail`
- **Setup:** a new version bucket added as a sibling dir, e.g. `src/protocol/auth/user_profile_v2/` (or `auth/user/v2/`) holding the per-version deltas.
- **Action:** scan all `.rs` files under `src/` (reuse the `rust_files` walk) for any `mod.rs` inside the new `_vN/` dir.
- **Expect:** zero `mod.rs` files anywhere, including the new sibling dir — the dir is wired via `#[path = ...]` / `pub mod` in the scope manifest, matching `poc10_target_has_no_mod_rs_files`.
- **Defends:** Mechanism "sibling _vN/ dirs follow the role-file convention (no mod.rs)".
- **Refs:** `tests/poc10_architecture_boundary_test.rs::poc10_target_has_no_mod_rs_files` (467-481), `src/protocol/auth.rs` scope manifest.

### GUARD-15 — sibling _vN/ dir has no forbidden schema.rs / codec.rs  `guardrail`
- **Setup:** the new `_vN/` version bucket dir.
- **Action:** scan for `schema.rs` and `codec.rs` filenames inside `src/` (excluding the one allowed `src/core/schema.rs`).
- **Expect:** the new sibling dir contains none; schema stays in `FACTS_SCHEMA_SOURCE` DDL and codecs stay in `layout.rs`/`FactCodec` — matching `poc10_target_has_no_per_module_schema_or_codec_files`.
- **Defends:** Mechanism "no forbidden subdirs / files in _vN/".
- **Refs:** `tests/poc10_architecture_boundary_test.rs::poc10_target_has_no_per_module_schema_or_codec_files` (483-503), `src/core/schema.rs`, `registry.rs` `FACTS_SCHEMA_SOURCE`.

### GUARD-16 — sibling _vN/ dir uses no banned broad / dumping-ground filenames  `guardrail`
- **Setup:** the new `_vN/` version bucket dir.
- **Action:** scan for the banned broad names `utils.rs`, `helpers.rs`, `common.rs`, `misc.rs`, `manager.rs`, `service.rs`, plus the forbidden `matchers.rs`/`context.rs`/`selectors.rs`.
- **Expect:** the new sibling dir contains only the invariant-specific role files (`layout.rs`, `fact.rs`, `create.rs`, `project.rs`, `rows.rs`, `queries.rs`, `cli.rs`) — no dumping grounds, no central context/selector/matcher source-of-truth files.
- **Defends:** Mechanism "no banned broad names"; matches `poc10_target_has_no_dumping_ground_filenames` and `protocol_context_ranges_are_core_owned_and_domain_encoded`.
- **Refs:** `tests/poc10_architecture_boundary_test.rs::poc10_target_has_no_dumping_ground_filenames` (928-954), `tests/poc10_protocol_registry_test.rs::protocol_context_ranges_are_core_owned_and_domain_encoded` (46-105).

### GUARD-17 — sibling _vN/ project.rs emits only needs/offers/self-purge/intents  `guardrail`
- **Setup:** the new `_vN/project.rs` kept-forever projector.
- **Action:** run the projector-output boundary scan over the new `project.rs`.
- **Expect:** the new version projector uses the same `ProjectionOutput` helpers (no `pub rows:`, `.deletes`, `.labels`, no direct `crate::core::store`/`rusqlite`/`.execute(`) — identical contract to existing projectors.
- **Defends:** Mechanism "_vN/ follows the role-file convention" extended to projector-output contract; supports invariant (4) REPLAY DETERMINISM (rows via RowMutation only).
- **Refs:** `tests/poc10_architecture_boundary_test.rs::poc10_target_projectors_emit_only_needs_offers_self_purge_and_intents` (623-655) and `::poc10_target_projectors_do_not_write_store_rows_directly` (734-762).

### GUARD-18 — the original version dir is never renamed when a _vN/ ships  `guardrail`
- **Setup:** a baseline manifest of existing family dir names (e.g. `auth/user`, `content/message`, `connection/frame_small`); then a new `_vN/` sibling is added.
- **Action:** assert the original family dirs and their layout-tag constants still exist at their original paths after the new version ships.
- **Expect:** `src/protocol/auth/user/` (TYPE_USER=14), `src/protocol/content/message/` (TYPE_CONTENT_MESSAGE=50), etc. are all still present and unrenamed; the new bucket is purely additive (a sibling), never an in-place rename. The original projector route entries remain in `FACT_ROUTES`.
- **Defends:** Mechanism "the original version dir is never renamed"; invariant (5) READERS FOREVER (old readers kept at their original location).
- **Refs:** `src/protocol/content.rs` (19-26 module list), `src/protocol/registry.rs` `FACT_ROUTES`, inventory tag map.

### GUARD-19 — a bucket omitting cli.rs passes the param-subset compatibility check  `guardrail`
- **Setup:** a new version bucket whose input surface did NOT change, so it ships no `cli.rs` (absent => reuse previous command run fn). Example: a `content::message` v2 delta with the same `send` inputs.
- **Action:** assert the param-subset contract: `v_next.required_inputs ⊆ active_cli.collected_params` for the reused command.
- **Expect:** the absent-bucket reuse is admitted ONLY because every input the new version requires is already collected by the active (previous) CLI command; the check passes. The compatibility assertion is part of the bucket-resolution path, not silent.
- **Defends:** Mechanism "an ABSENT bucket entry => reuse previous (asserts parameter compatibility); v_next.required_inputs ⊆ active_cli.collected_params".
- **Refs:** `content::message::cli` (`send`, `SEND_USAGE`), `MATCH_COMMANDS` (registry.rs 452), target param-subset contract.

### GUARD-20 — a bucket changing its input surface MUST ship its own cli.rs  `guardrail`
- **Setup:** a new version bucket that requires a NEW input not collected by the previous CLI (param-subset would be violated).
- **Action:** attempt to resolve the bucket with `cli.rs` absent (reuse-previous).
- **Expect:** the param-subset check FAILS (`v_next.required_inputs ⊄ active_cli.collected_params`), forcing the bucket to ship its own `cli.rs`. This is the negative complement of GUARD-19 — reuse is refused when the input surface changed.
- **Defends:** Mechanism "cli ONLY if the input surface changed (absent=reuse prev under a param-subset contract)."
- **Refs:** target param-subset contract, `src/core/cli.rs` `CliCommand`, `MATCH_COMMANDS`.

### GUARD-21 — fact tag uniqueness across versions (extended uniqueness test)  `guardrail`
- **Setup:** the assembled `FACT_ROUTES` including any new `_vN/` family routes (a new family => a NEW tag, never a reused tag).
- **Action:** run the extended form of `fact_route_tags_are_globally_unique` over the full `FACT_ROUTES` set.
- **Expect:** all `FactRoute.tag` values remain globally distinct after adding version families; a new family that reused an existing tag (e.g. re-using 14 or 50) is caught as a duplicate and fails. Confirms the full current set of 47 routed tags (2,10,14,42-47,50-57,128,129,131,133-136,139,146,147,150-157,160,162,164-173) are unique and any addition extends without collision.
- **Defends:** Mechanism "tag uniqueness across versions"; the versioning knob is the tag, so two families must never share one.
- **Refs:** `src/protocol/registry.rs::fact_route_tags_are_globally_unique` (717-729), inventory full tag map.

### GUARD-22 — a new family's tag must not collide with sealed transit carrier tags 46/47/56/57  `guardrail`
- **Setup:** the sealed transit carrier tags `TYPE_SEALED_CONNECTION_REQUEST/RESPONSE=46/47/56/57` are routed through `FACT_ROUTES` even though they are not ordinary authenticated fact families; a new fact family added.
- **Action:** assert the new family's routed tag is distinct from 46/47/56/57 and from all 47 current routed tags.
- **Expect:** a new fact tag never reuses a sealed transit carrier tag, because the sealed frames share the socket-level recognizer space and are already represented in the route table. New family tags also avoid the TRNS 4-byte magic and bootstrap fact 171.
- **Defends:** Mechanism "tag uniqueness across versions" extended to non-routed sealed-envelope tags.
- **Refs:** `connection/*/transit.rs` sealed tags 46/47/56/57, inventory section 1.

### GUARD-23 — handler route names + intent kinds stay unique across versions  `guardrail`
- **Setup:** the 17-entry `HANDLER_ROUTES`, plus any version-added handler.
- **Action:** assert handler route `name`s are unique (matches `runtime_handler_routes_are_unique...`) AND that intent-kind strings are unique across versions.
- **Expect:** `MATCH_RUNTIME.handlers` names form a set of size == `handlers.len()`; no two routes share a `name` or `intent_kind`. A version-added handler must use a fresh route name (no silent shadow). The 4 `COMMAND_EXCLUDED_HANDLER_ROUTES` names all resolve to real routes.
- **Defends:** Mechanism "tag/route uniqueness across versions" for handler routing; invariant (4) (deterministic dispatch).
- **Refs:** `tests/poc10_protocol_registry_test.rs::runtime_handler_routes_are_unique_and_command_excluded_handlers_are_explicit` (133-168), `registry.rs` HANDLER_ROUTES.

### GUARD-24 — CLI command names stay unique across version buckets  `guardrail`
- **Setup:** `MATCH_COMMANDS` (47 stable names), each mapping to a version-tagged run-fn list.
- **Action:** assert command `name`s are globally unique; a version bucket adds versions UNDER a stable name, never a duplicate name.
- **Expect:** `MATCH_COMMANDS` names form a set of size == `MATCH_COMMANDS.len()` (47); adding a `_v2` run fn under `send` does NOT add a second `"send"` entry — it extends the version list of the existing stable name. Two entries with the same `name` fail.
- **Defends:** Mechanism "CliCommand = a stable name -> a version-tagged list of run fns"; one stable name per command.
- **Refs:** `src/protocol/registry.rs` `MATCH_COMMANDS` (367-510), `executable_protocol_tables_name_the_target_surfaces` (22-44).

### GUARD-25 — FACT_ROUTES covers every fact family plus sealed transit carriers after a version add  `guardrail`
- **Setup:** all directories under `src/protocol/{auth,connection,content,sync}` that contain an `authenticate.rs`, plus the four sealed transit carrier routes; a new `_vN/` family with its own `authenticate.rs`.
- **Action:** scan for authenticate-bearing dirs and sealed transit carrier tags; compare to `FACT_ROUTES.len()`; assert each family or sealed carrier tag appears in exactly one route.
- **Expect:** the mapping stays complete — a new authenticated family without a `FACT_ROUTES` entry fails, and a non-sealed route without a backing authenticator fails. Baseline is 43 authenticated families + 4 sealed carriers = 47 routes; a clean version add becomes 44 + 4 = 48. The context-only `content/purge/` (no `authenticate.rs`) is correctly excluded.
- **Defends:** Structural invariant "every fact family is routed"; underpins ADMISSION/pending routing.
- **Refs:** inventory section 1 (43 authenticate.rs files, 47 routes), `src/protocol/content/purge/project.rs` (no layout/authenticate), `registry.rs` FACT_ROUTES.

### GUARD-26 — ROW_MUTATION_TABLES + SCHEMA_SOURCES extend, never shrink, on a version add  `guardrail`
- **Setup:** baseline `ROW_MUTATION_TABLES` (31 tables, registry.rs 521-553) and `SCHEMA_SOURCES`; a new version family that emits rows.
- **Action:** assert the new family's row table is present in BOTH `ROW_MUTATION_TABLES` and the `FACTS_SCHEMA_SOURCE` DDL, and that no existing entry was removed.
- **Expect:** every table a version projector mutates is declared in `ROW_MUTATION_TABLES` (the only tables intents/handlers may mutate) and has matching DDL; the new add is purely additive (old tables like `OPENED_MESSAGE_ROWS`, `CONTENT_MESSAGE_ROWS` remain). A projector writing a table absent from `ROW_MUTATION_TABLES` is rejected.
- **Defends:** Mechanism "rows/queries shared at head (old projectors emit ceiling-era rows)"; invariant (2) RENDERING UNIFORMITY (shared row schema).
- **Refs:** `src/protocol/registry.rs` `ROW_MUTATION_TABLES` (521-553), `FACTS_SCHEMA_SOURCE` (184-350), `SCHEMA_SOURCES` (519).

### GUARD-27 — manifest entry's replay output names a real ROW_MUTATION_TABLES target  `guardrail`
- **Setup:** a new family manifest entry whose "replay output" field names the rows it produces.
- **Action:** cross-check the manifest's declared replay-output table against `ROW_MUTATION_TABLES` and `read_models`.
- **Expect:** the replay-output table is a real declared table (e.g. `CONTENT_MESSAGE_ROWS`, `REACTION_ROWS`, `FILE_ROWS`) — a manifest naming a nonexistent or non-mutatable table fails. Ties the manifest (GUARD-05..08) to the concrete row registry.
- **Defends:** Manifest mechanism (replay output field is real), invariant (4) REPLAY DETERMINISM.
- **Refs:** `docs/research/Part I above` (299-302), `registry.rs` `ROW_MUTATION_TABLES`/`read_models` (36-182, 521-553).

### GUARD-28 — protocol version bundle maps to a named monotonic u32 (no internal version bytes for routed facts)  `guardrail`
- **Setup:** the target protocol-version bundle definition (protocol 7 = protocol 6 + {message:2, file:3}) and the routed-fact layouts.
- **Action:** scan routed-fact `encode.rs` files and transitional `layout.rs` files for an internal per-fact "version byte" that drives routing; assert routed facts version via TAG only.
- **Expect:** no routed fact uses an internal version byte for routing (the versioning knob is the tag). The only allowed internal version bytes are the non-routed sealed handshake (`bootstrap_request/layout.rs` private `VERSION=1`) and the connection frame wire header (`CONNECTION_FRAME_VERSION=1`) and inner bundle (`INNER_BUNDLE_VERSION=1`) — all socket/envelope level, not routed-fact level. The protocol-version u32 is monotonic.
- **Defends:** Mechanism "VERSIONING KNOB = the fact tag … No internal version bytes for routed facts"; "PROTOCOL VERSION = a single monotonic u32 = a NAMED BUNDLE."
- **Refs:** `connection_frame_wire.rs` (CONNECTION_FRAME_VERSION, INNER_BUNDLE_VERSION), `connection/bootstrap_request/layout.rs` (private VERSION), routed `encode.rs`/transitional `layout.rs` files (e.g. `content/message/encode.rs` TYPE byte only).

### GUARD-29 — CEILING-FILTERED router only activates routes with intro_version<=ceiling  `projector-unit`
- **Setup:** a `RouterProjector` built from `FACT_ROUTES` where some routes have `intro_version > ceiling` and some `<=`; a ceiling value C from the manifest.
- **Action:** project one fact of an at-ceiling family and one of an above-ceiling family.
- **Expect:** the at-ceiling fact dispatches to its projector and emits rows; the above-ceiling fact is filtered (pending per GUARD-12), not dispatched. The active route set is exactly `{r in FACT_ROUTES : r.intro_version <= ceiling}`.
- **Defends:** Mechanism "The router (RouterProjector over FACT_ROUTES) is CEILING-FILTERED."
- **Refs:** `src/core/projectors.rs:448-459` `RouterProjector::project`, `src/protocol/registry.rs:568`, target ceiling.

### GUARD-30 — capability is ceiling-active only if every still-usable release can transport it  `guardrail`
- **Setup:** a fleet manifest where one still-usable release (any platform, not past `expires_at`, not security-deprecated) has `supported_protocol.end()` below a family's `intro_version`.
- **Action:** compute the ceiling (min over still-usable releases, across all platforms) and check capability activation for that family.
- **Expect:** the family is NOT ceiling-active because the laggard release cannot transport it — the ceiling is pinned to that release's `supported_protocol.end()`. Activation requires `intro_version<=ceiling` AND every still-usable release transports it; a single non-capable still-usable release blocks it.
- **Defends:** Mechanism "CEILING = min over still-usable releases … ACROSS ALL PLATFORMS"; "CEILING-ACTIVE iff intro_version<=ceiling AND every still-usable release can transport it"; invariant (3).
- **Refs:** target `ReleaseManifestEntry { supported_protocol: RangeInclusive<u32>, expires_at, ... }`, ceiling computation.

---

## 19. Completeness-pass additions (adversarial rounds)

Concrete tests closing intersection gaps the completeness pass found across clusters.

### KEYS-GAP10a — chop-now (rotation R0→R1 + chop retirement) lands on the SAME wipe+replay that activates a pending key_wrap_v2  `replay-cli`
- **Setup:** `con` node at ceiling N holding live key material for workspace W: `recipient_key` R0 (from `key-recipient`) with live `local_recipient_key` LR0, a `removal_frontier` F, a `local_signer_secret`, and TWO `local_key_secret` FrontierRoot sources — S_old (`created_at_ms = T_old`) and S_new (`created_at_ms = T_new`, `T_new > T_old`) — each offering `local_secret_source` and `frontier_root_wrap_source_offers` (proactive domain, keyed by `frontier_created_at_ms`). The node ALSO retains one received above-ceiling `key_wrap_v2` fact (new redesign tag), pending as opaque bytes per KEYS-03 (no v2 route active at N). A signed manifest refresh then raises the ceiling to N+1, covering the `key_wrap:2` tag, AND the node runs `con chop-now W FLOOR_MINUTE` — which (commands.rs:571-589) rotates R0→R1 because a previous `local_recipient_key` exists (`create_recipient_key` with `previous_recipient_key_id = R0`, so R1.`created_at_ms = T_rot`), then (commands.rs:590-613) submits a `LocalSecretRetirement{reason_kind=RETIRE_REASON_CHOP, target_secret_id}` for EVERY `local_key_secret` in W (both S_old and S_new).
- **Action:** `con` wipe + full replay at ceiling N+1, replaying every retained fact via the adapter keyed by its OWN tag — the v2 wrap (now routed to the v2 `KeyWrapProjector`), R0/R1 (tag 150), F (151), S_old/S_new (152), the two `local_secret_retirement` facts (157), LR0 (156) and the signer secret (133) — in arbitrary order; drive `process_all_work_until_idle`.
- **Expect:** the three verified mechanisms compose without resurrection or divergence: (1) both `local_secret_retirement` facts project (`LocalSecretRetirementProjector`) and publish `secret_retired_offer`, so S_old and S_new each see `secret_retired_need` satisfied in `LocalKeySecretProjector` and return `purge_self(fact.id)` — neither offers `local_secret_source` or any `frontier_root_wrap_source_offers` after replay. (2) R0 is superseded by R1 (`recipient_superseded` offer at R0's id), so R0 emits NO proactive `create_key_wrap_intent`; R1 is the only live recipient and, per its rotation floor, sets `min_frontier_created_at_ms = R1.created_at_ms = T_rot`. (3) Because BOTH roots were retired (purged) in this same pass, `matching_wrap_sources_with_signer` over R1's `proactive_wrap_source_need(min = T_rot)` finds NO live wrap source → ZERO new `create_key_wrap_intent` emitted (independently of the floor, since no source survives). The activated `key_wrap_v2` fact routes to its v2 projector and materializes its row (KEYS-04), but if it would emit an `unwrap_key_wrap` intent it can only do so against still-live local recipient material — and any unwrap that re-derives a `local_key_secret` whose id matches a retired target immediately re-purges via the standing retirement context (KEYS-14/31 path), so no retired root secret is resurrected. The post-replay `con keys W` summary is identical across repeated wipe+replays (invariant 4).
- **Defends:** the unpinned collision of redesign-activation (KEYS-04/32) × recipient rotation floor (KEYS-16/33/34) × chop-now retirement (KEYS-25/14/15/31) on one deterministic replay; forward secrecy across the seam (a v2 wrap must not revive a same-pass-retired source); invariant 4 (order- and ceiling-independent rebuild).
- **Refs:** `auth/key_wrap/commands.rs::chop_now` (571-613, in-pass rotation + per-secret retirement), `auth/local_secret_retirement/project.rs::project_typed`, `auth/local_key_secret/project.rs::project_local_key_secret` (`secret_retired_need` → `purge_self`), `auth/recipient_key/project.rs::recipient_key` (`min_frontier_created_at_ms`, `is_superseded` early-return), `auth/key_wrap/project.rs::{matching_wrap_sources_with_signer,proactive_wrap_source_need,wrap_source_offer_valid_for_need}`, `auth/key_wrap/_v2/project.rs` (model), `core/projectors.rs` RouterProjector.

### KEYS-GAP10b — activated key_wrap_v2 whose source secret was retired in the same pass cannot fabricate/resurrect via create_key_wrap  `handler-unit`
- **Setup:** the replay state of KEYS-GAP10a at the instant the rotated recipient R1 (or the activated v2 family's create path) would queue a `create_key_wrap` intent naming `source_fact_id = S_old.id` — but S_old was retired this pass (`LocalSecretRetirement` for S_old projected, S_old's `LocalKeySecretProjector` returned `purge_self`), so S_old is no longer a retained/contextable fact. Construct the `CreateKeyWrapIntent{workspace_id=W, frontier_id=F, recipient_key_id=R1, source_fact_id=S_old.id, signer_secret_fact_id, source=FrontierRoot}` (idempotence key via `create_key_wrap_key`) and present it to `CreateKeyWrapHandler` with a `HandlerContext` reflecting the purged store (S_old absent).
- **Action:** invoke `CreateKeyWrapHandler::input_fact_ids` then `handle` (HANDLER_ROUTE `create_key_wrap`).
- **Expect:** `context.require_fact(&input.source_fact_id)` at `create_key_wrap.rs:181` fails for the retired S_old → handler returns `Err`; NO tag-155 (or v2) `key_wrap` fact is emitted, and no `local_key_secret` is re-minted. The retired source secret is never re-wrapped to the newly-live R1, and the v2 activation cannot launder a purged root back into circulation. (Contrast S_new in GAP10a, also retired here: same `require_fact` failure — both roots are gone, so the handler cannot fabricate from either.)
- **Defends:** `require_fact` at create_key_wrap.rs:180-182 as the forward-secrecy backstop when a wrap source is retired in the same pass that activates v2 — "create_key_wrap recreates wraps ONLY when local source + signer material exist; never fabricates missing key material" extended across the redesign-activation seam (KEYS-06 generalized to the rotation+retirement+v2 collision).
- **Refs:** `auth/create_key_wrap.rs::CreateKeyWrapHandler::{input_fact_ids,handle}` (require_fact 180-182), `core/intents.rs::HandlerContext::require_fact`, `auth/local_key_secret/project.rs` (`purge_self` removing the source), `auth/key_wrap/create.rs::create_validated_key_wrap_fact`.

### KEYS-GAP10c — create_key_wrap idempotence converges across the v2-activation + rotation replay (no entropy amplification)  `replay-cli`
- **Setup:** a variant of GAP10a where the chop-now retirement does NOT cover one surviving root S_keep (e.g. S_keep has `created_at_ms = T_keep >= T_rot` and is in a frontier/workspace the chop floor does not reach, so no `LocalSecretRetirement` targets it), while R0→R1 rotation and the `key_wrap_v2` activation still both land on the same wipe+replay. After rotation, R1's `min_frontier_created_at_ms = T_rot` and S_keep (`T_keep >= T_rot`) is the single eligible proactive wrap source; its `local_signer_secret` is present.
- **Action:** wipe + replay TWICE at ceiling N+1 with different retained-fact replay orders (forward and `test-replay-deps-reverse`-style reverse), each driving `process_all_work_until_idle`.
- **Expect:** R1 emits exactly ONE proactive `create_key_wrap_intent` for S_keep whose idempotence key from `create_key_wrap_key(W, F, R1, FrontierRoot-coordinate)` is IDENTICAL across both replay orders and excludes `source_fact_id`/`signer_secret_fact_id` and any request entropy (KEYS-21/36) — so the deterministic handler produces ONE byte-identical tag-155 wrap (same `sender_wrap_public_key`/`nonce`/`ciphertext` via `deterministic_wrap_info`), fact id stable across both runs. The independently-activated `key_wrap_v2` fact materializes its own v2 row via its own-tag adapter and does NOT collide with, duplicate, or alter the v1 wrap's idempotence key (distinct tag → distinct convergence domain). No duplicate wraps, no order-dependent state.
- **Defends:** `create_key_wrap_key` idempotence still converges when v2-activation and rotation coincide (the gap's "create_key_wrap_key must still converge"); rotation floor admits exactly the post-rotation eligible source; redesign activation is additive and tag-isolated; invariants 4 + "no request entropy amplifying keys."
- **Refs:** `auth/create_key_wrap.rs::create_key_wrap_key`, `auth/key_wrap/create.rs::{create_key_wrap_fact,deterministic_sender_wrap_secret,deterministic_nonce,deterministic_wrap_info}`, `auth/recipient_key/project.rs::recipient_key` (post-rotation `min_frontier_created_at_ms`, single eligible source), `auth/key_wrap/project.rs::{matching_wrap_sources_with_signer,wrap_source_offer_valid_for_need}`, `sync::cascade_test_fact::cli` (`test-replay-deps-reverse` for order independence), `auth/key_wrap/_v2/` (model).
### REPLAY-GAP11a — Pending file_slice_v2 whose parent content::file is purged during the pending window parks forever (does NOT error) on activation  `replay-cli`
- **Setup:** Node at a ceiling that covers only the v1 content families. A `content::file` (tag 54) `F` exists and is projected (CONTENT_FILES row present), authored under a parent `content::message` (tag 50). The node then RECEIVES, over sync, an above-ceiling `file_slice_v2` fact `S` (a proposed new-tag sibling of `content::file_slice` tag 55, intro_version = N+1, with the SAME `file_id` as `F`). Per ADMISSION, `S` is PENDING: retained as opaque bytes, unprojected, undisplayed, uncounted — NOT routed to a missing projector (it must NOT hit the `core/projectors.rs:456` "no target projector registered" error today). WHILE `S` is pending, `con delete-file` is run against `F`, producing a `content::file_deletion` (tag 53). The file projector resolves its `file_deletion_need` (`content/file/project.rs:111,125`), validates the deletion, and returns `delete_file_projection(...).purge_self(fact.id)` (`content/file/project.rs:126-135`) — so `F` is removed from the retained store and its CONTENT_FILES/FILE_SLICES rows are dropped. The retained log now holds `S` (pending) and the `file_deletion`, but NOT `F`.
- **Action:** A fleet-wide signed manifest raises the ceiling so `file_slice_v2`'s tag is ceiling-active (its kept-forever v2 projector + sibling `content/file_slice_v2/` directory are present and routed), trusted_time advances past `blocker.expires_at + M`. Then wipe derived state and replay all retained facts via the historical adapter keyed by each fact's OWN tag (the `con replay` canonical path / `drain_pending_projection`).
- **Expect:** On this replay `S` is now routed to its v2 projector and marked pending, but its first context step is the parent-file need — the v2 projector emits a `content_file` range need on `slice.file_id` exactly as `content/file_slice/project.rs:68-77` does, then `return Ok(ProjectionOutput::new().need(file_need))` because no `content::file` payload for that `file_id` is retained (`F` was purged). The fact PARKS (PROJ-17 semantics: no row, no offer, no error) and stays parked through fixpoint — there is no retained fact that can ever satisfy the `content_file` need, so it parks FOREVER. The replay MUST complete (Invariant 4): it must NOT return `Err`, must NOT abort the whole replay, and `S` must NOT resurrect a CONTENT_FILES/FILE_SLICES row for the purged file. `con content-count` / `con files` are unchanged by `S`; `con state-summary` counts `S` under retained-facts and under "parked/pending projection", never under a read-model area; the purged `F` stays absent. The test pins that an activating pending fact with a purged in-range dependency degrades to a permanent harmless park, identical to a freshly-received orphan slice — NOT a hard error and NOT a half-materialized row.
- **Defends:** ADMISSION/PENDING activation-on-replay (REPLAY-08, CONTENT-04, SYNC-11) extended to the case where the activation-time dependency was purged mid-pending; PROJ-17 park-on-missing-anchor semantics (park, don't error) applied to a newly-activated fact; Invariant 4 (replay deterministic, ceiling-independent per-tag adapter, must not abort on a parked fact); Invariant 1 (visibility deferred/dropped, never half-projected). Guards the `projectors.rs:456` hard-error hole on the activating replay path.
- **Refs:** `content/file_slice/project.rs:68-77` (`content_file` need + park `return Ok(...).need(file_need)`); `content/file/project.rs:111-135` (`target_purged_need` + `validate_file_deletion` + `delete_file_projection(...).purge_self(fact.id)`); `content::file_deletion` (tag 53, `delete-file` -> `content::file_deletion::cli`); `core/projectors.rs:356` `purge_self`, `:456` unknown-tag Err (the behavior pending/park must avoid); `core/pipeline/project_pending_facts.rs` `drain_pending_projection`; sibling tests REPLAY-08, CONTENT-04, SYNC-11; negentropy `context_have` closure `sync/shared_fact/rows.rs:280-285`.

### REPLAY-GAP11b — Pending auth fact whose in-range authority/signer anchor is removed during the pending window parks forever on activation, granting NO authority  `replay-cli`
- **Setup:** Node B at a ceiling covering only v1 auth families, inside a workspace with a root `auth::admin` (tag 139) `A_auth` acting as a granting authority. B RECEIVES an above-ceiling authority fact `Q` — a proposed `auth::user_profile_v2` (the not-yet-existing v2 sibling flagged in inventory section 1, intro_version = N+1) OR a `grant-admin` (`auth::admin` tag 139) above-ceiling delegated-admin fact — whose projector, on activation, needs an in-range v1 anchor: for the delegated `auth::admin` path this is `DelegatedAdminNeeds.authority` resolved at `auth/admin/project.rs:121-126` (the authority admin `A_auth`) and `needs.user`; for `user_profile_v2` it is the `auth_user` anchor offered by `UserProjector` at `auth/user/project.rs:91-94`. `Q` is PENDING (pending opaque, unprojected, uncounted, NOT errored at `projectors.rs:456`). WHILE `Q` is pending, the anchor fact it will need is REMOVED from the retained set during the window — e.g. the granting authority/user material is retired/purged through the auth removal path (`auth::local_secret_retirement` tag 157 / `auth::removal_frontier` tag 151 self-purge for key-material anchors, or the anchor fact otherwise no longer retained), so the `auth_user` / authority-admin payload `Q` will require is gone.
- **Action:** A signed manifest raises B's ceiling to cover `Q`'s tag (its kept-forever v_{N+1} projector + sibling `_v2/` dir present and routed); trusted_time advances past `blocker.expires_at + M`. Wipe derived state and replay all retained facts keyed by each fact's own tag.
- **Expect:** On replay `Q` now routes to its v_{N+1} projector and is marked pending, but its authority/anchor need is unsatisfiable (the anchor was removed mid-pending). The projector returns `Ok(needs.output())` with the unmet need re-emitted — `auth/admin/project.rs:125-126` (`let Some(authority_fact) = context.payload_for(&needs.authority) else { return Ok(needs.output()) }`) or the `auth_user` park modeled on `auth/user/project.rs:65-72`. `Q` PARKS FOREVER (PROJ-17/PROJ-18 semantics): no admin/user-profile row, no `auth_user`/`admin` offer, NO error, and crucially NO authority is granted to the target (the pre-removal state had no such authority and the activating replay must not mint it from an absent anchor). Replay completes without `Err` and without aborting; `con users` / `con peers` / the admin read-model show `Q`'s target with NO new authority; `con state-summary` counts `Q` as retained-but-parked. This pins that a pending AUTHORITY fact cannot bootstrap itself when its proving anchor was purged during the pending window — it degrades to a permanent harmless park, never a hard error and never an unanchored authority grant.
- **Defends:** ADMISSION activation-on-replay (AUTHZ-03) extended to a purged-during-pending authority anchor; PROJ-17/18 park-on-missing-anchor (park, don't error, don't grant); Invariant 1 (visibility/authority deferred, never granted without its anchor); Invariant 3/no-regression (an activating fact gains no authority beyond what its v1 anchors prove — PROJ-19); Invariant 4 (replay must not abort on the parked authority fact). Guards `projectors.rs:456` on the auth-scope activation path.
- **Refs:** `auth/admin/project.rs:121-146` (`DelegatedAdminNeeds`, `needs.authority`/`needs.user` parks at :125-128, id/workspace mismatch checks); `auth/user/project.rs:65-72,91-94` (`auth_user_invite` park pattern + `auth_user` anchor offer); proposed `auth::user_profile_v2` (inventory section 1 — does not yet exist); `auth::local_secret_retirement` (157) / `auth::removal_frontier` (151) removal path; `core/projectors.rs:356` `purge_self`, `:489` `project_typed`, `:456` unknown-tag Err; sibling test AUTHZ-03; PROJ-17/18/19.
### SYNC-GAP12a — Ceiling rises BETWEEN the compare-response plan and the requested-fact send within ONE have/need round  `multinode-network`
- **Setup:** Floor 6, ceiling 6 (a mobile laggard `6..=6`, `expires_at = T`, is the blocker; desktop `6..=7`). Peer A (desktop, head 7) and peer B share a workspace over an established connection `C` (`connection::response` tag 44). A's shareable index holds an in-range v1 owner `O1` (`content::message:1`, tag 50) AND an above-ceiling-at-6 owner `U` (`content::message_v2`, intro_version 7). B's `sync::compare` (tag 165) mismatches a leaf range covering both `O1` and `U`'s timestamps. M is the skew margin; trusted_time starts `< T + M`.
- **Action:** Drive the round in two steps, advancing trusted_time across the step boundary: (1) run `SendSyncCompareResponseHandler::handle` for B's compare at ceiling 6 — its `response_plan_with_summaries` + `expand_fact_ids_with_context_for_connection` closure picks the send set AND it emits the have/need exchange that lands a `sync::need_id` (tag 167) for `O1` (NOT for `U` — at ceiling 6 `U` is above-ceiling so the plan excludes it / it is not minted into the round). (2) BEFORE running `SendRequestedFactHandler::handle` on that need-id, feed signed observations so trusted_time crosses `T + M`, expire the mobile blocker, and recompute the ceiling to 7.
- **Expect:** The in-flight need-id for `O1` ships `O1` unchanged via `require_sendable_fact` (it was selected at ceiling 6 and stays valid at ceiling 7 — VISIBILITY is monotone, a v1 fact admissible at 6 is admissible at 7). The mid-round ceiling rise does NOT cause the half-completed round to ship `U` to B: `U` was never named in a `sync::need_id` during the ceiling-6 plan, and `SendRequestedFactHandler` only answers facts a peer explicitly requested by id, so no above-ceiling-at-plan-time fact is back-filled into a round whose closure was selected under the old ceiling. `U` is advertised only on the NEXT compare/seed pass that runs wholly at ceiling 7 (a fresh `response_plan_with_summaries`). Convergence is correct across the transition: B ends with `O1` now, `U` on the subsequent round — never a torn round that sends `U`'s owner without re-deriving the round under the new ceiling.
- **Defends:** CEILING MONOTONICITY (3); ADMISSION (an above-ceiling-at-plan-time fact is not smuggled into an in-flight round); convergence-across-a-mid-sync-transition; closes the empty cell where the ceiling advances WHILE a have/need round is in flight (CONN-17/28, E2EX-07, SYNC-11 only advance at rest).
- **Refs:** `sync/send_compare_response.rs` `SendSyncCompareResponseHandler::handle` (`response_plan_with_summaries`, `expand_fact_ids_with_context_for_connection`); `sync/send_requested_fact.rs` `SendRequestedFactHandler::handle` (`require_sendable_fact`); `sync::need_id` 167; `content::message_v2` intro_version 7; E2EX-07 ceiling 6->7 (`expires_at`, M, trusted_time monotonic-max).

### SYNC-GAP12b — Ceiling rises ACROSS the slices of ONE file mid-transfer; carrier-class selection recomputes per slice  `multinode-network`
- **Setup:** Floor 6, ceiling 6 (mobile `6..=6`, `expires_at = T`, blocks `frame_bundle` 170 activation; desktop `6..=7`). A `content::file` (tag 54) descriptor `F` plus its N `content::file_slice` facts (tag 55) are shareable on connection `C` to peer B. At ceiling 6, `frame_size_class_for_facts` resolves each one-slice send to `CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE` (169) and any small control fact to `CONNECTION_FRAME_SIZE_CLASS_SMALL` (168); the BUNDLE class (170) is NOT ceiling-active (a still-usable release cannot transport it). The file is being shipped slice-by-slice via repeated `SendRequestedFactHandler` sends answering B's per-slice need-ids. trusted_time < T + M.
- **Action:** Send the first K of N slices at ceiling 6 (each a `frame_file_slice` 169). Between slice K and slice K+1, cross `T + M`, expire mobile, recompute ceiling to 7 (now `frame_bundle` 170 is ceiling-active per E2EX-21 carrier-capacity gating). Continue sending the remaining slices.
- **Expect:** Every slice — those sent before AND after the transition — is carried inside a per-slice carrier whose class `frame_size_class_for_facts` recomputes against the live ceiling at send time: slices 1..K go as `frame_file_slice` (169); the post-transition slices MAY now be packed into a `frame_bundle` (170) if the sender batches them, OR continue as `frame_file_slice` — but in BOTH cases each carried `content::file_slice` is byte-identical (chunk-don't-grow: a slice is never grown to fit a larger frame). B opens every frame regardless of class and reassembles all N slices + `F` into one complete file. The carrier-class change mid-transfer is invisible to the carried payload; no slice is lost, duplicated, or resized across the ceiling boundary. (Contrast: a slice already framed as 169 is NOT re-sent as 170 — the recompute affects only not-yet-sent slices.)
- **Defends:** Carrier capacity GATES ceiling activation / chunk-don't-grow (the file_slice precedent); REPLAY DETERMINISM (4) and VISIBILITY (1) hold when `frame_size_class_for_facts` recomputes mid-transfer; closes the "across the slices of one file" half of the gap.
- **Refs:** `connection_frame_wire.rs:659` `frame_size_class_for_facts` (its call site `seal_connection_send_frame` :571); `CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE` (169) / `..._BUNDLE` (170) / `..._SMALL` (168); `content::file` 54 / `content::file_slice` 55; `sync/send_requested_fact.rs` per-slice send; E2EX-21 (carrier-capacity gate), E2EX-07 (ceiling 6->7).

### SYNC-GAP12c — Ceiling rises BETWEEN two child sync::compare ranges, splitting an anchor (selected under old ceiling) from its owner (becomes ceiling-active under new ceiling)  `multinode-network`
- **Setup:** Floor 6, ceiling 6 (mobile `6..=6`, `expires_at = T`; desktop `6..=7`). On peer A, a root `sync::compare` (tag 165) split (via `TimestampRange::split`, count > `MAX_HAVE_IDS_PER_RANGE` 64) into two child ranges: an EARLIER child range `Rlo` and a LATER child range `Rhi`. A v1 anchor `A` (`content::message:1`, tag 50) lives in `Rlo`; an owner `O` whose `negentropy_context_have_for_leaf` dependency is `A` lives in `Rhi`. Crucially `O` is a `content::message_v2` (intro_version 7) — above-ceiling at 6. trusted_time < T + M.
- **Action:** Process child `Rlo` first at ceiling 6: `SendSyncCompareResponseHandler` runs `expand_fact_ids_with_context_for_connection` / `shareable_facts_for_connection_range(C, Rlo.start, Rlo.end, include_deps=true)`; `A` is in-range-and-ceiling-active so it ships to B. THEN cross `T + M`, expire mobile, recompute ceiling to 7. THEN process child `Rhi`: re-derive its plan at ceiling 7, where `O` (intro_version 7) is now ceiling-active and its closure recomputes `{O, A}` via the BFS over `negentropy_context_have_for_leaf`.
- **Expect:** No torn closure: when `Rhi` is planned at ceiling 7, the include_deps BFS pulls `A` as `O`'s anchor, but `A` was ALREADY shipped to B during `Rlo` at ceiling 6, so B already holds it (`SendNeededFactIdHandler` is a no-op for an id B already retains — `persisted_fact(...).is_some()`), and `SendRequestedFact` re-requesting `A` is idempotent. B therefore ends with the complete closure `{A, O}`: the anchor selected under the OLD ceiling and the owner activated under the NEW ceiling converge into one valid dependency closure. The reverse-skew danger is also closed: had `Rhi` been planned BEFORE the rise (ceiling 6), `O` would be excluded (above-ceiling) and only re-offered on the post-rise pass — B is never left holding `O` (ceiling-active owner) without `A` (its anchor), nor `A` orphaned without an eventual `O`. Convergence holds regardless of WHICH side of the transition each child range is processed on.
- **Defends:** Convergence-across-a-mid-sync-transition for a closure SPANNING two child compare ranges; the include_deps closure recompute against the NEW ceiling does not orphan an anchor selected under the OLD ceiling (nor vice versa); CEILING MONOTONICITY (3), VISIBILITY (1); closes the "between two child sync::compare ranges" half of the gap.
- **Refs:** `sync/send_compare_response.rs` `SendSyncCompareResponseHandler::handle`; `sync/shared_fact/rows.rs:953` `shareable_facts_for_connection_range` (include_deps BFS over `negentropy_context_have_for_leaf` :1285) and `expand_fact_ids_with_context_for_connection` :1018; `sync/compare/create.rs` child-split (`MAX_HAVE_IDS_PER_RANGE`, `TimestampRange::split`); `sync/send_needed_fact_id.rs` no-op on already-retained id; `content::message_v2` intro_version 7 / `content::message:1` 50; E2EX-07 (ceiling 6->7), SYNC-11 (pending-then-activate at rest, the at-rest analog).
### REPLAY-GAP13a — In BLOCKED MODE, replay-dispatched `create_key_wrap` re-emits its workspace-scoped `key_wrap` (155) as a deterministic rebuild, NOT refused as new shared production  `handler-unit`
- **Setup:** Runtime opened from `MATCH_RUNTIME` in BLOCKED MODE (trusted-time staleness window S elapsed without manifest refresh, or backward clock rollback beyond tolerance). The store retains the wrap inputs for a `FrontierRoot` source: `recipient_key` (150), source `local_key_secret` (152), `local_signer_secret` (133), plus `removal_frontier` (151) and the `workspace` (131) the scope keys to. The `key_wrap` (155) fact K was produced by an earlier `create_key_wrap` dispatch and is still retained. Wipe derived state. The `create_key_wrap` route is `runs_during_replay = true`.
- **Action:** Run the wipe+replay path; projection re-emits the `create_key_wrap` intent and `CreateKeyWrapHandler::handle` runs over the retained inputs. `create::create_validated_key_wrap_fact` returns `PipelineEffects::new().fact(wrap)` where `wrap = Fact::new(auth::workspace::scope(workspace_id), ...)` (a WORKSPACE-scoped, therefore shareable, fact — `create.rs:94-96`).
- **Expect:** The handler's `.fact(wrap)` effect is COMMITTED during replay (deterministic rebuild), even though the recreated `key_wrap` is workspace-scoped/shareable. Blocked mode does NOT refuse this emission and does NOT reclassify the replay-recreated 155 as "new shared production" to be withheld. `create_key_wrap_key` over identical inputs equals the prior intent key, so the rebuilt fact id == K and re-submission dedupes to exactly one `key_wrap` (KEY_WRAPS rows unchanged, no duplicate). RED if blocked mode gates the `runs_during_replay=true` handler's `fact()` effect on the shared-production switch — that would silently drop the recreated key material and corrupt the rebuild.
- **Defends:** model "in blocked mode … local reads + replay still run" + invariant (4) "recreates only deterministic facts"; the seam where "blocked mode withholds shared production" must NOT swallow a deterministic replay-rebuild of a workspace-scoped fact. Distinguishes fact CREATION (allowed in replay) from sync ADVERTISEMENT (withheld — see 13b).
- **Refs:** `auth/create_key_wrap.rs` (`CreateKeyWrapHandler::handle`, `create_key_wrap_key`); `auth/key_wrap/create.rs::create_validated_key_wrap_fact` → `Fact::new(workspace::scope(...))` (create.rs:94-96); HANDLER_ROUTES `create_key_wrap` (inventory §3, #8); planned `runs_during_replay=true`; cross-ref TIME-28, CLI-25, KEYS-05, REPLAY-10.

### REPLAY-GAP13b — Replay rebuild of the shareable `key_wrap` does NOT trigger sync advertisement in BLOCKED MODE (shared production stays withheld)  `handler-unit`
- **Setup:** Same BLOCKED-MODE store as 13a, with at least one seeded sync connection (so the `share_fact_with_sync` / `seed_connection::advertise_indexed_fact_to_connections_except` path has somewhere to advertise). Wipe derived state.
- **Action:** Run the wipe+replay path. `CreateKeyWrapHandler` recreates the workspace-scoped `key_wrap` (per 13a). Observe whether projection of that recreated 155, in blocked mode, emits a `share_fact_with_sync` Upsert intent whose `ShareFactWithSyncHandler` would call `advertise_indexed_fact_to_connections_except`.
- **Expect:** The recreated `key_wrap` is admitted/projected locally, but NO new outbound sync advertisement is produced for it while blocked: either the `share_fact_with_sync` intent is `runs_during_replay=false` (not dispatched before the barrier) or the blocked-mode gate suppresses `advertise_indexed_fact_to_connections_except`, so SHARED_FACT (162) / HAVE_ID (166) advertisement rows for K are NOT created during the blocked replay. The withheld production is exactly the sync OFFER, not the fact's local recreation. (Contrast: 13a asserts the `fact()` survives; 13b asserts the peer-facing advertisement does not.)
- **Defends:** TRUSTED TIME / BLOCKED MODE "shared production withheld" — pins withholding to the sync-advertisement seam (`share_fact_with_sync` upsert → `advertise_indexed_fact_to_connections_except`), so a blocked replay rebuild does NOT leak the recreated key_wrap to peers. Complements AUTHZ-28 (which withholds NEW authority sharing) for the replay-recreated case.
- **Refs:** `sync/share_fact_with_sync.rs::ShareFactWithSyncHandler::handle` (Upsert branch → `record_sync_contribution` + `seed_connection::advertise_indexed_fact_to_connections_except`, lines 178-226); `auth/key_wrap/project.rs` (emits the share intent on 155); HANDLER_ROUTES `share_fact_with_sync` (#6) `runs_during_replay=true`; cross-ref REPLAY-21/22 (network/live-only withheld), AUTHZ-28.

### REPLAY-GAP13c — In BLOCKED MODE, replay-dispatched `unwrap_key_wrap` recreates its `FactScope::Local` opened secret (152/153) and is never gated by the shared-production switch  `handler-unit`
- **Setup:** Runtime in BLOCKED MODE retains the `key_wrap` (155), `local_recipient_key` (156), `recipient_key` (150), and `removal_frontier` (151) facts an earlier `unwrap_key_wrap` consumed to produce a local opened secret (`local_key_secret` 152 for a root wrap, or `local_history_node_secret` 153 for a node wrap). The opened secret is still retained (not purged). Wipe derived state. The `unwrap_key_wrap` route is `runs_during_replay = true`.
- **Action:** Run the wipe+replay path; projection re-emits the `unwrap_key_wrap` intent and `UnwrapKeyWrapHandler::handle` runs over the retained inputs. `create::unwrap_key_wrap_fact` returns `PipelineEffects::new().fact(secret)` where `secret = Fact::new(FactScope::Local, ...)` (create.rs:301-302 / 318-319).
- **Expect:** The local secret fact is COMMITTED during the blocked replay — its emission is never routed through the shared-production gate (it is `FactScope::Local`, and `require_non_local_fact_bytes` would in fact REFUSE it from any sync/outbound path — intents.rs:362-369). The rebuilt secret is bit-identical to the original (same fact id via `unwrap_key` idempotence key + deterministic open), so re-submission dedupes to exactly one local secret (no duplicate local secret rows). RED if blocked mode refuses or skips the `runs_during_replay=true` unwrap handler's local-fact emission — that silently drops the opened key material and leaves the node unable to decrypt its own content after a blocked-mode replay.
- **Defends:** model "in blocked mode … replay still run[s]" + invariant (4); local key material recreation is a deterministic rebuild that the shared-production withholding must never touch. Pins that `FactScope::Local` outputs of replay handlers are categorically outside "shared production".
- **Refs:** `auth/unwrap_key_wrap.rs` (`UnwrapKeyWrapHandler::handle`, `unwrap_key`); `auth/key_wrap/create.rs::unwrap_key_wrap_fact` → `Fact::new(FactScope::Local, ...)` (create.rs:301/318); `core/intents.rs::require_non_local_fact_bytes` (refuses Local for outbound, 362-369); HANDLER_ROUTES `unwrap_key_wrap` (#9); planned `runs_during_replay=true`; cross-ref REPLAY-14, KEYS-05.
### QUERY-GAP14a — render-correctness fix RE-APPLIES to OLD retained facts on replay after the ceiling crosses its intro_version  `replay-cli`
- **Setup:** Single `con` node holding only OLD `content::message` facts (tag 50, `CIPHERTEXT_BYTES = 128`, `content/message/fact.rs:11`) authored under the BUGGY `message_payload_bytes` derivation — i.e. `count_for_workspace` (`content/message/queries.rs:59`) computing `message_payload_bytes = content_messages * CIPHERTEXT_BYTES` at line 71. Send N messages of differing real plaintext lengths so the buggy `N*128` value provably differs from the per-message sum. The render-correctness FIX (recompute `message_payload_bytes` from real per-message payload sizes, gated as a protocol bump at intro_version V+3 per QUERY-08/09) is present in the binary at HEAD but the fleet ceiling is still V+2 (a still-usable release blocks it). Capture `con content-count WORKSPACE_ID_HEX` -> the `message_payload_bytes:` line (`content_count_output`, `content/message/cli.rs:380,384`) shows the OLD `N*128` value. NO message fact is rewritten — the tag stays 50, the wire bytes are unchanged.
- **Action:** Advance trusted_time past the blocker's `expires_at + M`, recompute the ceiling so it crosses V+3, then run `con replay` canonical (wipe derived state, re-mark all retained tag-50 facts pending, drain to fixpoint), then `con content-count WORKSPACE_ID_HEX`.
- **Expect:** After the ceiling crosses V+3 and the wipe+replay runs, `message_payload_bytes:` shows the CORRECTED per-message-sum value for ALL retained facts — including the OLD ones authored before the fix existed. The fix is a DERIVATION re-applied at the new ceiling over the same unchanged tag-50 facts; it is NOT a fact rewrite. `content_messages:` and `max_message_timestamp:` (`count.max_created_at_ms`) are unchanged (only the buggy field is corrected). This is the OPPOSITE of "old wire shape keeps its old projector forever": a render-correctness derivation re-applies to every retained fact regardless of authoring era.
- **Defends:** INVARIANT (2)+(4): a render-correctness fix is `f(retained facts, ceiling=V+3)` and re-applies on replay to ALL retained facts (old + new); replay is the mechanism that surfaces the corrected derivation once the ceiling crosses the fix's intro_version.
- **Refs:** `content/message/queries.rs:59,71` (`count_for_workspace`/`message_payload_bytes` buggy `*CIPHERTEXT_BYTES`), `content/message/fact.rs:11` (`CIPHERTEXT_BYTES=128`), `content/message/cli.rs:380,384,385` (`content_count_output`), QUERY-08/09 (the bump gate), REPLAY-17/E2EX-29 (ceiling-independent sub-ceiling replay); `con replay`/`content-count`.

### QUERY-GAP14b — BOUNDARY: a render-fix derivation re-applies to old facts, but an incompatible-wire-shape NEW TAG keeps its old projector — same replay, opposite outcomes  `replay-cli`
- **Setup:** One node retaining TWO independently-versioned changes in the same store: (1) OLD `content::message` facts (tag 50) subject to the V+3 `message_payload_bytes` render-correctness fix of QUERY-GAP14a (a DERIVATION over the unchanged tag-50 wire shape); and (2) a separate INCOMPATIBLE wire-shape change — a hypothetical `message:2` with a NEW tag (sibling `content/message_v2/`, its own kept-forever projector, new `FACT_ROUTES` entry per the VERSIONING KNOB rule), with some v1 (tag 50) AND some v2 (new tag) message facts retained, all admitted while ceiling-active. Ceiling now crosses V+3 (activating both the render fix and, say, `message:2`). Capture pre-replay `con content-count`.
- **Action:** `con replay` canonical at the post-V+3 ceiling, then `con content-count WORKSPACE_ID_HEX` and `con messages WORKSPACE_ID_HEX`.
- **Expect:** The two changes resolve on the SAME replay with OPPOSITE rules: (a) the render-correctness derivation re-applies uniformly — the OLD tag-50 facts now report the CORRECTED `message_payload_bytes` (their meaning is recomputed by the head/ceiling derivation); (b) the incompatible-wire-shape facts each replay via the historical adapter keyed by their OWN tag (tag 50 -> v1 projector, new tag -> v2 projector; `RouterProjector` effective_tag dispatch, `core/projectors.rs:423,433`) — a v1 fact NEVER gets a v2 wire interpretation and vice versa. No tag-50 fact is re-decoded as `message:2`; no `message:2` fact is decoded by the v1 projector. The render fix changes how retained facts are SUMMED; the wire-shape version change preserves each fact's ORIGINAL decoding.
- **Defends:** INVARIANT (2)+(4)+(5): draws the explicit boundary — a render-fix derivation (presentation/aggregation of retained facts) re-applies to old facts at the new ceiling, while an incompatible wire shape (a new fact TAG) keeps its own kept-forever projector and old facts keep their old decoding. The gap's central distinction, pinned in one test.
- **Refs:** `content/message/queries.rs:59,71`; `core/projectors.rs:423` (`RouterProjector`), `:433` (effective_tag reads first byte), `:456` (per-tag dispatch); `FACT_ROUTES` per-tag entries; REPLAY-02/03 (own-tag adapter for wire versions); QUERY-08/09 (render-fix bump gate); inventory §VERSIONING KNOB (new wire shape => new tag + new projector + `_vN/` dir).

### QUERY-GAP14c — render-fix correction is ceiling-driven, not log-driven: same retained tag-50 log yields OLD value at ceiling V+2 and CORRECTED value at ceiling V+3  `replay-cli`
- **Setup:** A single retained log of ONLY OLD `content::message` facts (tag 50), authored under the buggy derivation, with mixed real plaintext lengths (so corrected sum != `N*128`). The binary at HEAD contains both the V (buggy) and V+3 (corrected) `message_payload_bytes` derivations as a version-tagged list (CliCommand / derivation selects highest intro_version <= ceiling, per QUERY-22). Two replay passes over the SAME log: ceiling pinned at V+2, then ceiling pinned at V+3.
- **Action:** Wipe + replay the same tag-50 log at ceiling V+2, capture `con content-count WORKSPACE_ID_HEX` -> O_old; wipe + replay the identical log at ceiling V+3, capture -> O_new.
- **Expect:** O_old's `message_payload_bytes:` = the buggy `N*128`; O_new's = the corrected per-message sum — from the EXACT SAME retained facts. The difference is driven solely by which derivation is ceiling-active (highest intro_version <= ceiling), NOT by any change to the log. This refines E2EX-29: E2EX-29 says sub-ceiling FACTS replay identically regardless of ambient ceiling (true here — every fact is still admitted/decoded identically via tag 50), but the SURFACED DERIVATION over those identical facts is correctly ceiling-dependent. The two statements are not in tension: fact decoding is ceiling-independent; the render derivation renders at the ceiling.
- **Defends:** INVARIANT (2): surfaced meaning = `f(retained facts, protocol version=ceiling)` — the render-correctness derivation is selected by ceiling, so the same log produces the old value below V+3 and the corrected value at/above V+3; clears the apparent contradiction with E2EX-29's "ceiling-independent replay" (decoding vs derivation).
- **Refs:** `content/message/queries.rs:59,71` (`count_for_workspace`); `content/message/cli.rs:380` (`content_count_output`); QUERY-22 (CliCommand/derivation selects highest intro_version <= ceiling); E2EX-29 / REPLAY-03 (ceiling-independent FACT replay — the decoding layer); QUERY-08 (the V+3 bump).
### E2E-GAP15a — A holds newer B's owner pending, relays its shareable INDEX to a third node C at yet another ceiling; closure stays coherent across THREE ceilings  `multinode-network`
- **Setup:** Three daemons fed the SAME signed `--release-manifest fleet.json` but resolving to DIFFERENT effective ceilings (divergence is by manifest+`clock`, not negotiated — CEIL-27). `bob`=`con_new` (head 8, manifest yields ceiling 8: `content::message:2` tag 56 is ceiling-active for bob). `alice`=`con_new` whose still-usable set pins ceiling 7 (tag 56 above-ceiling => pending on receipt). `carol`=`con_old` (head 6, manifest pins ceiling 6: also above both 56 and the protocol-7 derivations). Topology = alice is the hub: `accept_workspace_invite(&alice,&bob,&workspace,alice_port,"bob","bob-phone")` and `accept_workspace_invite(&alice,&carol,&workspace,alice_port,"carol","carol-phone")` into ONE shared workspace; `create_local_content_key` on each; `spawn_daemon` all three. bob and carol have NO direct connection — everything routes through alice.
- **Action:** `con_new --db bob send WORKSPACE "v2-payload"` mints a tag-56 owner fact `U` (legal: at bob's ceiling 8). bob `sync-range ... --with-deps` to `endpoint_id(&alice)`; let alice pull. alice receives `U` (tag 56) ABOVE its ceiling 7 -> pending path. The `share_fact_with_sync` upsert on alice runs `record_sync_contribution` (shareable index) and `seed_connection::advertise_indexed_fact_to_connections_except` over alice's connections EXCLUDING bob's origin connection — so alice relays the `sync::shared_fact` (tag 162) / root `sync::compare` for `U`'s id to carol. Let carol pull from alice.
- **Expect:** (1) alice RETAINS `U` opaque: `fact_count(&alice)` increments by one, but `content-count`/`messages WORKSPACE` on alice do NOT show it (uncounted, undisplayed, not errored). (2) alice's `sync::shared_fact` index (tag 162) for `U` projects and advertises to carol WITHOUT alice decoding `U` (SYNC-29 — the index layer is decoupled from `U`'s projectability). (3) carol, seeing an advertised id it lacks, runs `send_needed_fact_id` and emits a `sync::need_id` (SYNC-16, id-only, version never inspected); alice answers via `send_requested_fact` shipping `U` as opaque bytes verbatim (SYNC-18, `require_sendable_fact` passes — tag 56 is non-local/non-private). (4) carol RECEIVES `U` (tag 56) above ITS ceiling 6 and ALSO holds it pending: `fact_count(&carol)` +1, `content-count(&carol,&workspace)` unchanged, no "no target projector registered for fact tag 56" error surfaces. (5) NO echo: carol does not re-advertise `U` back to alice as a fresh need (SYNC-17 — already-retained id suppresses re-request on alice), and alice does not re-send to bob (origin connection excluded). The three-ceiling closure converges with bob counting `U`, alice+carol holding it opaque, zero stranded need/have rounds.
- **Defends:** Invariant (1) VISIBILITY (a tag-56 fact is admissible/transportable by every node but projectable only at/above ceiling 8); ADMISSION (received above-ceiling fact PENDING not dropped/errored, at all three ceilings); CEIL-27 (each node uses its OWN locally-computed ceiling, not negotiated); the unpinned relay-of-pending-owner-index path that SYNC-29 + SYNC-16/17 + E2E-28 only cover pairwise.
- **Refs:** `content::message` v1 tag 50 / v2 tag 56; `sync::shared_fact` tag 162; `sync::need_id` 167 / `sync::have_id` 166; `share_fact_with_sync.rs` `ShareFactWithSyncHandler::handle` (`record_sync_contribution` + `advertise_indexed_fact_to_connections_except`, src lines 200-223); `seed_connection.rs:116` `advertise_indexed_fact_to_connections_except` / `connection_ids_for_shareable_fact`; `send_needed_fact_id.rs` `SendNeededFactIdHandler`; `send_requested_fact.rs` `SendRequestedFactHandler` (`shareable_fact_for_connection`, `require_sendable_fact`); three-daemon pattern (`three_player_sync_through_alice_keeps_workspace_scopes_separate`); pending error site `core/projectors.rs:456`.

### E2E-GAP15b — handler-unit: alice's shareable index for a pending owner advertises to a SECOND connection without decoding, and re-request is suppressed by retention  `handler-unit`
- **Setup:** Single store (`CORE_SCHEMA_SOURCE` + `FACTS_SCHEMA_SOURCE`). Seed two distinct connections rooted at alice: `C_bob` (alice<->bob) and `C_carol` (alice<->carol), each with the endpoint/endpoint_shared facts the existing `share_fact_with_sync` / `seed_connection` unit tests construct. Insert an owner fact `U` with first byte tag 56 (`content::message:2`) that is RETAINED-but-pending on this node (no projector ran for it; it is opaque bytes in `persisted_fact`). Build a `ShareFactWithSync{ owner_fact_id: U.id, context_have: [], state: SyncShareState::Upsert }` whose `record_sync_contribution` makes `U` shareable for BOTH `C_bob` and `C_carol`. Mark `C_bob` as `U`'s origin connection (via the `fact_receipt` origin set) so it is the EXCLUDED connection.
- **Action:** (1) Submit the upsert intent to `ShareFactWithSyncHandler::handle`. (2) Independently, construct a `sync::have_id` advertising `U.id` arriving on `C_carol`, and submit `send_needed_fact_id_intent(SendNeededFactId{ have_fact_id })` to `SendNeededFactIdHandler::handle`.
- **Expect:** (1) The share handler succeeds even though `U` is undecodable: `context.require_fact(&U.id)` + `require_non_local_fact_bytes(&U.id)` pass on opaque bytes (tag 56 is non-local), `record_sync_contribution` returns `changed=true`, and `advertise_indexed_fact_to_connections_except` emits a `send_facts_on_connection` intent for `C_carol` but NOT `C_bob` (origin excluded). The owner body is never decoded — no projector for tag 56 is invoked, no "no target projector registered for fact tag 56" error. (2) Because `U` is already retained, `persisted_fact(store,&U.id)?.is_some()` is true -> `SendNeededFactIdHandler::handle` returns empty `PipelineEffects::new()`; no `sync::need_id` is emitted (SYNC-17 echo suppression holds for a pending owner exactly as for a normal one). Together: alice can relay a pending owner's INDEX to a non-origin connection and will NOT re-fetch the same opaque owner it already holds.
- **Defends:** ADMISSION/SUBSTANCE: the shareable-index + advertise relay layer is version-agnostic and decoupled from owner projectability (extends SYNC-29 from one index-projection to the multi-connection relay write path); SYNC-16/17 retention-suppression for pending bytes; no-echo guarantee underpinning the E2E across three ceilings.
- **Refs:** `share_fact_with_sync.rs:178` `ShareFactWithSyncHandler::handle` (`require_fact` / `require_non_local_fact_bytes`, `record_sync_contribution`, `advertise_indexed_fact_to_connections_except` lines 200-223); `shared_fact/rows.rs:213` `record_sync_contribution`, `:1088` `connection_ids_for_shareable_fact`, `:1047` `shareable_fact_for_connection`; `seed_connection.rs:116`; `send_needed_fact_id.rs` early-return on `persisted_fact(...).is_some()`; `connection::fact_receipt::origin_connection_ids_for_fact`; tag 56 = `content::message:2`.

### E2E-GAP15c — three-ceiling fleet rises to cover tag 56: alice + carol activate the relayed pending owner on wipe+replay deterministically, no strand/duplicate  `multinode-network`
- **Setup:** Continue from E2E-GAP15a's end state: bob holds `U` (tag 56) materialized; alice (ceiling 7) and carol (ceiling 6) both hold `U` RETAINED-opaque/pending; the `sync::shared_fact` index for `U` and the connection facts persist on alice. All three still share one workspace.
- **Action:** Retire the laggard release so the FLEET ceiling rises to cover tag 56 on every node: drop carol from the still-usable set (e.g. `clock advance` past its release `expires_at + M`, or remove carol's release from `fleet.json`) and refresh manifests so alice's and carol's ceilings both reach 8. Then run a wipe+replay on alice and on carol (the model's "pending facts ACTIVATE on the next wipe+replay once the ceiling rises to cover their tag"). Issue NO new `send`.
- **Expect:** (1) On alice's replay, `U` is re-fed via the historical adapter keyed by its OWN tag 56 (REPLAY DETERMINISM, ceiling-independent per-fact) and now MATERIALIZES: `wait_for_content_count(&alice,&workspace,1)` and `poll_for_message_text(&alice,&workspace,"v2-payload",10_000)` pass; alice's `messages WORKSPACE` row now equals bob's byte-for-byte (Invariant (2) rendering uniformity at the common ceiling). (2) carol's replay likewise activates `U` and materializes the SAME row. (3) Determinism/no-echo: `fact_count` on each node is UNCHANGED by the replay (activation re-derives display rows from retained facts; it recreates only deterministic facts, mints no new owner) — no duplicate `U`, no new `sync::need_id`/`have_id` rounds spawned, no fact stranded as still-opaque on alice or carol. (4) bob is unaffected (already materialized; no regression). The cross-version dependency closure that spanned three ceilings collapses to a single coherent rendering once the ceiling covers tag 56.
- **Defends:** ADMISSION ("pending facts ACTIVATE on the next wipe+replay once the ceiling rises to cover their tag"); Invariant (4) REPLAY DETERMINISM (each retained fact replays via the adapter keyed by its own tag, ceiling-independent, recreates only deterministic facts); Invariant (2) (post-activation rows identical across nodes at the common ceiling); confirms the three-ceiling relay leaves NO permanent strand or echo.
- **Refs:** `content::message:2` tag 56 historical adapter via `FACT_ROUTES` / `RouterProjector::project` (`core/projectors.rs:448`, error site :456 must NOT fire post-rise); wipe+replay harness; `wait_for_content_count` / `poll_for_message_text` / `fact_count`; manifest refresh + `clock advance` ceiling recompute; contrast SYNC-09/11 (single-node activation) and E2E-28 (fleet-min rise) which this extends to the relayed-owner three-ceiling case.
### AUTHZ-GAP16a — pending bootstrap admin (tag 139) activating after its `auth_workspace` anchor was purged-with-preserving-tombstone resolves from the tombstone, never from nothing  `replay-cli`
- **Setup:** Node B from AUTHZ-02/03 holding a PENDING above-ceiling bootstrap `auth::admin` fact AD (a hypothetical N+1 reissue of tag 139; `authority_fact_id == workspace_id == W.id`, the root self-grant branch, `project_bootstrap_admin`). During the pending window — ceiling still N, AD opaque/unprojected — the workspace anchor W (the SOLE emitter of the `auth_workspace` offer over `W.id..W.id`, `auth::workspace::project`) is purged with an authority-preserving tombstone per the AUTHZ-13 safe path: a tombstone that re-publishes the `auth_workspace` offer AND lets core load anchor payload whose loaded `Fact.id == W.id` and whose decoded `WorkspaceFact` re-verifies `workspace::authenticate::verify_signature`. Then a signed manifest raises B's ceiling to cover AD's intro_version; trusted_time advanced past `blocker.expires_at + M`.
- **Action:** Wipe derived state and replay all retained facts (per-tag historical adapters). AD now routes to its `v_{N+1}` admin adapter; `project_bootstrap_admin` calls `context.payload_for(&needs.workspace)` (role `auth_workspace`, range `W.id..W.id`, project.rs:91/174).
- **Expect:** The bootstrap admin materializes (root `admin` row + the two `auth_admin` offers, project.rs:243-269) ONLY by consuming the preserving tombstone's payload: the matched payload satisfies `matched.offer.owner == matched.payload.id` (projectors.rs:184) AND `decode_workspace_context`'s `workspace_fact.id == W.id` check (project.rs:234) AND `admin.signer_public_key == workspace.public_key` (project.rs:102). It MUST NOT materialize from a missing/None payload (that path returns `Ok(needs.output())` and parks — project.rs:92), and MUST NOT fabricate the row from the tombstone's own id as if it were W. Pre-rise state (and any replay where the tombstone does not load W-id payload) shows NO admin authority.
- **Defends:** ADMISSION activation-on-replay (AUTHZ-03) INTERSECTED with anchor purge-with-preserving-tombstone (AUTHZ-13): the activating authority projector must resolve its anchor from the tombstone exactly as a live admit would, neither fabricating authority from a removed anchor nor silently dropping a legitimately-tombstoned grant. Invariants (3) ceiling monotonicity, (4) replay determinism, (6) safety floor.
- **Refs:** `auth::admin::project::project_bootstrap_admin` (project.rs:85-114), `BootstrapAdminNeeds` (project.rs:167-187), `decode_workspace_context` (project.rs:230-241), `auth::workspace::project::WorkspaceProjector` (sole `auth_workspace` offer), `ProjectionContext::payload_for` / `payload_for_checked` owner-check (projectors.rs:170-188), AUTHZ-03, AUTHZ-13.

### AUTHZ-GAP16b — pending DELEGATED admin (tag 139) whose granting `auth_admin` authority anchor was purged-with-tombstone cannot be satisfied by a substitute-id tombstone  `projector-unit`
- **Setup:** Workspace W with root admin A1. A node holds a PENDING above-ceiling DELEGATED `auth::admin` fact AD2 (N+1 reissue; `authority_fact_id == A1.id != W.id`, so `project_delegated_admin`; target user U in W). During pending the granting authority anchor A1 (the `auth_admin` offer over `A1.id..A1.id`, project.rs:251-257) is purged. Construct TWO tombstone variants for the activating replay: (i) a FAITHFUL preserving tombstone whose loaded payload has `Fact.id == A1.id` and decodes to A1's exact `AdminFact` (re-verifies `auth::admin::authenticate::verify_signature`, `authority.public_key`, `authority.workspace_id == W.id`); (ii) a SUBSTITUTE tombstone with a DIFFERENT fact id `T.id != A1.id` that re-publishes the `auth_admin` coordinate at `A1.id..A1.id` but whose loaded payload id is `T.id`. Ceiling then rises to cover AD2; trusted_time past `expires_at + M`. The `auth_workspace` (W) and `auth_user` (U) anchors remain intact.
- **Action:** Wipe+replay. AD2 routes to its `v_{N+1}` delegated-admin adapter; `project_delegated_admin` resolves `payload_for(&needs.workspace)`, `payload_for(&needs.authority)`, `payload_for(&needs.user)` (project.rs:122-130).
- **Expect:** Variant (i): AD2 materializes the delegated `admin` row and `auth_admin` offers — the faithful tombstone passes `authority_fact.id == admin.authority_fact_id` (== A1.id, project.rs:137-138) and the `signer_public_key == authority.public_key` check (project.rs:145). Variant (ii): REJECTED with "admin authority context payload id mismatch" (project.rs:138) because `matched.payload.id == T.id != A1.id` — equivalently caught by the offer-owner check (projectors.rs:184) since the substitute tombstone's offer.owner is T.id. A substitute-id tombstone NEVER lets a delegated grant re-anchor onto a removed authority; it does not silently drop the legitimately-tombstoned case (i). No version of the adapter relaxes the id-equality binding.
- **Defends:** Cross-version authority containment under anchor purge: a pending delegated grant activating after its `auth_admin` anchor is purged must re-bind to the SAME authority fact id via a faithful tombstone, never to a re-keyed/substitute tombstone (which would forge an authority chain). Mirrors AUTHZ-11/AUTHZ-15 statically; this is the pending×purge×replay intersection. Invariants (3), (4).
- **Refs:** `auth::admin::project::project_delegated_admin` (project.rs:116-165), `DelegatedAdminNeeds` (project.rs:189-228), id-mismatch guards (project.rs:137-138, 234), `ProjectionContext::payload_for_checked` owner==payload.id (projectors.rs:184-186, 221), AUTHZ-11, AUTHZ-15.

### AUTHZ-GAP16c — pending admin activating after a NON-preserving (coordinate-only) anchor purge PARKS uncounted, never fabricates authority  `replay-cli`
- **Setup:** Same pending above-ceiling `auth::admin` AD as GAP16a/b, but the anchor purge during the pending window writes NO authority-preserving tombstone — the anchor bytes (W for the bootstrap case, or A1 for the delegated case) are physically removed and no fact whose loaded `Fact.id` equals the anchor id remains. The `auth_workspace` / `auth_admin` need coordinate therefore has no loadable offer-owner payload. Ceiling rises to cover AD; trusted_time past `expires_at + M`.
- **Action:** Wipe+replay. AD routes to its `v_{N+1}` adapter and projects; `payload_for(&needs.workspace)` (bootstrap) or `payload_for(&needs.authority)` (delegated) returns `None`.
- **Expect:** The projector takes the `let Some(..) else { return Ok(needs.output()); }` PARK path (project.rs:92 for bootstrap, project.rs:122/125/128 for delegated): AD re-emits its unmet `auth_workspace`/`auth_admin`/`auth_user` needs and is DEFERRED. NO `admin` row is written, NO `auth_admin` offer is published, the target gains NO admin authority, and AD stays uncounted/undisplayed (as it was while pending). The replay does NOT hard-error (no projectors.rs:456 path — AD's tag is now routed) and does NOT fabricate authority from the removed anchor. The grant remains recoverable only if a faithful tombstone (GAP16a/b variant i) is later supplied; an unsafe purge that destroyed the anchor must leave the grant dormant, not active.
- **Defends:** The "park, never fabricate" safety boundary when a pending authority fact activates but its anchor was purged WITHOUT a preserving tombstone — the opposite of GAP16a/b's faithful-tombstone path. Prevents both fabrication (authority from a removed anchor) and the silent error/crash that today's projectors.rs:456 would have produced for an unrouted tag. Invariants (1) (no crash, uncounted), (4), (6).
- **Refs:** `project_bootstrap_admin` / `project_delegated_admin` park returns (project.rs:92, 122, 125, 128), `ProjectionOutput::need` re-emission (projectors.rs:331), `RouterProjector::project` routed-tag path vs unknown-tag Err (projectors.rs:456), AUTHZ-03, AUTHZ-12, AUTHZ-29.
### CONTENT-GAP17a — Retention-floor purge over a MIXED v1+pending-v2 message set: v2 stays pending-and-unpurged at ceiling N, then self-purges on ceiling-rise activation (no resurrection)  `replay-cli`
- **Setup:** Single node at ceiling N where `content::message` v1 (tag 50) is ceiling-active but `content::message_v2` (a new tag, intro_version N+1, with its kept-forever `content/message_v2/` projector) is NOT. Seed a workspace and author several v1 messages via `con send WORKSPACE_ID_HEX TEXT` at low `minute` values. Then RECEIVE over sync one above-ceiling `message_v2` fact whose decoded `frontier_id`/`minute` fall in the same workspace and the same early minute band as the v1 messages; per ADMISSION it is PENDING (pending opaque bytes, unprojected, undisplayed, uncounted — it does NOT hit the `RouterProjector::project` Err at `core/projectors.rs:456`). Now author a `content::retention_policy` (tag 147) via `con disappearing-set WORKSPACE_ID_HEX TTL_MINUTES` and then `con disappearing-tighten WORKSPACE_ID_HEX SMALLER_TTL --yes`, advancing `retire_minute` so the tightened floor sits ABOVE the minute band shared by the v1 messages AND the pending v2 fact. Drive trusted-time observations / the `content_message_expiry` `expiration_timeline()` past the relevant wakes so the floor is reached. Capture `con messages`, `con content-count`, `con disappearing-status WORKSPACE_ID_HEX` (effective_floor/current_ttl_minutes/horizon_floor), and `state_hash`.
- **Action:** (1) Observe steady state at ceiling N. (2) Raise the fleet manifest so the oldest still-usable release supports protocol N+1 and advance trusted_time past `blocker.expires_at + M` so the ceiling rises to cover `message_v2`'s intro_version. (3) `con replay` (canonical wipe+replay).
- **Expect:** At ceiling N: the v1 messages whose `minute < retire_minute` self-purge — each v1 `ContentMessageProjector` reaches `retention_floor_reached(...)` and emits `retired_output(...)` which `purge_self(message_id)`s and writes the `MESSAGE_TOMBSTONES` row (`message/project.rs:105, 463-491`); they are absent from `CONTENT_MESSAGES`/`OPENED_MESSAGES`. The pending v2 fact is UNTOUCHED by this purge — it is opaque and its projector never ran, and per `purge_self` policy (`core/projectors.rs:351-355` "Core verifies ... this id is the projected fact id; cross-fact deletion must be expressed as context that wakes the target fact's projector") NO other projector may purge it; it remains retained, uncounted, invisible, and the retention floor cannot reach inside it. After ceiling-rise + replay: the now-active v2 fact routes to `content/message_v2/`'s projector, which recomputes the SAME `retention_floor_need` (role `content_retention_floor`, `content/message.rs:28`) from the retained tag-147 policy chain and the SAME replayable `content_message_expiry` time wakes — finds `message.minute < retire_minute` — and emits its OWN `retired_output`/`purge_self` so it materializes a tombstone and is ABSENT from `CONTENT_MESSAGES`. The v2 message MUST NOT resurrect as a live row. `con content-count` does not increase for the now-expired v2 message; `con disappearing-status` floor/TTL is identical to ceiling N (re-derived from the same v1 policy facts). `state_hash` is stable across the canonical replay.
- **Defends:** Closes the mixed-version retention-purge gap: a retention/disappearing floor that covers a pending-v2 fact's minute does not (and cannot) purge it at ceiling N, and the v2 fact, once active, RE-DERIVES its own expiry from retained retention+time facts and self-purges rather than leaking expired content back on upgrade. Invariant (4) replay determinism + ceiling-independence (each fact replays via its OWN-tag adapter); ADMISSION pending→activation; Invariant (5) old meaning preserved; the `purge_self` cross-fact constraint.
- **Refs:** `content/message/project.rs` `expiry_minute_reached`/`retention_floor_reached`/`cover_horizon_reached` (lines 99-107, 366-409), `expired_output`/`retired_output` `purge_self` (lines 434-491); `core/projectors.rs:351-359` `purge_self` policy + `:456` unknown-tag Err (the pending path that must intercept the v2 tag at ceiling N); `content/message.rs:19-40` `COVER_HORIZON_MINUTES`/`expiration_timeline()`/`retention_floor_need` (role `content_retention_floor`); `content::retention_policy` tag 147 + `RetentionPolicyProjector`, `disappearing-set`/`disappearing-tighten` (`content/retention_policy/cli.rs` DISAPPEARING_SET_USAGE/DISAPPEARING_TIGHTEN_USAGE, `commands.rs`); read_models CONTENT_MESSAGES/OPENED_MESSAGES/MESSAGE_TOMBSTONES (registry.rs 36-182); cross-refs REPLAY-19/20, CONTENT-22/23/25.

### CONTENT-GAP17b — A `content_purged` coordinate (deletion-style) CAN target an opaque pending-v2 fact; the offer is published but only CONSUMED when the v2 projector activates  `projector-unit`
- **Setup:** Construct, via `project_typed` unit harness, the cross-fact purge path against a pending target. Build a `content::message_v2` fact F2 (new tag, above ceiling N) with known decoded `frontier_id = FR`, `minute = M`, and fact id `ID2`; it is PENDING at the node (opaque, no `content_message_meta` offer emitted because its projector never ran). Build a `content::message_deletion` (tag 51) D whose `target_frontier_id = FR`, `target_minute = M`, `target_message_id = ID2`, authored by ID2's claimed author. Provide the deletion projector the signer/author context but NO `content_message_meta` payload for ID2 (since the v2 target is unprojectable at ceiling N).
- **Action:** Run `ContentMessageDeletionProjector::project_typed(D, context)` at ceiling N. Then separately decode the `target_purged_offer` it would publish and assert the coordinate bytes; then simulate ceiling-rise activation where the v2 projector emits its `target_purged_need(FR, M, ID2)` and check the offer/need overlap.
- **Expect:** At ceiling N the deletion projector BLOCKS on its `content_message_meta` `target_need` for `ID2` (`message_deletion/project.rs:61-99`) — it returns the needs and does NOT yet publish a usable purge for a target it cannot validate, so no spurious tombstone for the opaque fact and no resurrection-by-deletion. CRITICALLY: the purge coordinate key produced by `target_purged_offer(FR, M, ID2)` (`content/purge/project.rs:47-56, 74-85`, layout = version(1)+frontier(32)+minute(8 BE)+fact_id(32) = 73 bytes, `CONTENT_PURGE_KEY_VERSION = 1`) is byte-identical to the `target_purged_need(FR, M, ID2)` the v2 message projector emits at `message/project.rs:75-81` — i.e. a purge coordinate CAN address a fact id the node cannot yet project, because the coordinate is keyed on the target's `(frontier_id, minute, fact_id)` and is stored opaquely by core. On ceiling-rise + replay, once both the authorizing context (the now-derivable `content_message_meta` offer for the activated v2 target) and the deletion's offer are present, the v2 projector exact-matches the `content_purged` coordinate via `decode_target_purge_key` and self-purges (`author_deletion_output`), so the activated v2 fact finds itself ALREADY-PURGED and never produces a live `CONTENT_MESSAGES` row.
- **Defends:** Proves the inventory-section-1 purge coordinate (`target_purge_key`) can target an opaque pending fact, and that consumption is correctly deferred until the target projector exists — answering the open "whether a purge coordinate can target a fact the node cannot yet project." Closes the leak-on-upgrade question for the deletion-style purge path. Invariant (4); ADMISSION pending→activation; the `content_purged` MATCH rule (target projectors exact-match their own coordinate).
- **Refs:** `content/purge/project.rs` `target_purged_offer`/`target_purged_need`/`target_purge_key`/`decode_target_purge_key`/`TargetPurgeKey`/`content_purged_role` (lines 32-105), `CONTENT_PURGE_KEY_VERSION = 1`, `TARGET_PURGE_KEY_BYTES = 1+32+8+32`; `content/message_deletion/project.rs:61-137` (`content_message_meta` target_need gate + `target_purged_offer` emission); `content/message/project.rs:75-81` (`target_purged_need` keyed on `frontier_id`/`minute`/`fact.id`); `core/projectors.rs:351-359` `purge_self` self-only constraint.

### CONTENT-GAP17c — `disappearing-compact` over a mixed set leaves the pending-v2 fact retained and uncounted; compaction is reproducible and the v2 fact re-expires (not resurrects) on activation  `replay-cli`
- **Setup:** Continue from CONTENT-GAP17a's pre-rise state: ceiling N, v1 messages already retention-floor-purged (tombstoned), one `message_v2` fact still PENDING whose `minute` is below the same tightened `retire_minute`, plus the retained tag-147 policy chain. Run `con disappearing-compact WORKSPACE_ID_HEX`, which drives the `content::purge` CONTEXT (role `content_purged`, `content/purge/project.rs` — NO `layout.rs`, NOT in `FACT_ROUTES`) to compact tombstones/purges. Capture FACT_ROUTES count (must stay 47), `con content-count`, `con messages`, and `state_hash` H1.
- **Action:** (1) Run `con disappearing-compact` again and confirm idempotence (no new facts, same `state_hash`). (2) Raise the manifest + advance trusted_time so the ceiling covers `message_v2`. (3) `con replay`; then re-run `con disappearing-compact` and `con replay` once more for a second-pass determinism check (H1 vs H2).
- **Expect:** Compaction at ceiling N produces NO new fact tag (`fact_route_tags_are_globally_unique`, registry.rs:717-729, still holds with exactly 47 routes — purge is context-only) and does NOT touch the pending v2 fact: it stays retained-opaque, uncounted by `con content-count`, invisible in `con messages`. Compaction is deterministically reproducible from retained facts (re-run yields identical `state_hash`). After ceiling-rise + replay the v2 projector activates, recomputes the SAME retention floor from the SAME retained tag-147 chain + `content_message_expiry` time wakes, and self-purges (`retired_output`/`purge_self`) so the v2 fact is tombstoned, ABSENT from `CONTENT_MESSAGES`, and not resurrected by compaction; a second compact+replay pass is byte-stable (H1 == H2). No expired v2 content leaks back post-upgrade through the compaction path.
- **Defends:** Closes the compaction sub-case of the mixed-version retention gap: context-only compaction neither prematurely purges nor later resurrects a pending-v2 fact; the v2 fact's expiry is re-derived deterministically on activation. Invariant (4) "recreates only deterministic facts" + order/ceiling independence; model "purge is CONTEXT, NOT a fact family"; ADMISSION pending→activation.
- **Refs:** `content/purge/project.rs` `content_purged_role`/`target_purge_key`; `content/retention_policy/cli.rs` DISAPPEARING_COMPACT_USAGE + `compact_workspace_id`; registry.rs `FACT_ROUTES` + `fact_route_tags_are_globally_unique` (717-729, 47 routes); `content/message/project.rs:434-491` `expired_output`/`retired_output` `purge_self`; cross-refs CONTENT-26, REPLAY-20.
### CEIL-GAP18a — version conjunct arrives one ceiling-step before its carrier class: fact stays dormant in the gap  `property`
- **Setup:** A new fat fact family F is carrier-blocked: its encoded byte size exceeds `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` (4 KiB) and also exceeds `CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES` (= `file::layout::CONTENT_FILE_BYTES`), so `frame_size_class_for_facts` cannot place it in small/bundle, and unlike `content::file_slice` (tag 55) it has NO `frame_file_slice` (tag 169) chunking path yet. F is introduced at `intro_version = 8`. Protocol bundle staging (one monotonic u32 = named bundle of fact-tag versions): protocol **8** adds F's tag at intro 8 but NO new carrier; protocol **9** adds the larger/chunked carrier class that can finally transport F. Fleet still-usable set at trusted_time `t0`: a single blocker rel-old `supported_protocol = 1..=7` `expires_at = T7`; rel-head `1..=9`. trusted_time `t0 < T7 + M` so ceiling == 7.
- **Action:** Advance trusted_time past `T7 + M` (rel-old leaves the still-usable set). Recompute ceiling and re-evaluate ceiling-active for F. Now every still-usable release supports protocol **8** for F's TAG (`intro_version 8 <= ceiling 8`) — the VERSION conjunct just became true — but the still-usable set's carriers (the protocol-8 carrier inventory) still has no class that fits F (the protocol-9 carrier has not yet been required/reached fleet-wide). Then attempt to mint and ship an F-fact: locally create it and run `SendFactsOnConnectionHandler` so `fact_batches` calls `frame_size_class_for_facts`.
- **Expect:** F is NOT ceiling-active even though `intro_version (8) <= ceiling (8)` — the transportability conjunct still fails (the carrier class lags one ceiling step behind). F stays dormant in the gap between the two conjuncts becoming true: local creation of the above-(transport-)ceiling F is REFUSED (`con send`-equivalent path declines to mint), and any forced send fails the carrier gate — `frame_size_class_for_facts` returns `Err("connection::frame inner payload does not fit small, file-slice, or {N}x{M} bundle slots")` and `SendFactsOnConnectionHandler` surfaces `"send_facts_on_connection fact exceeds connection frame bundle slot"` rather than growing a frame. The version-conjunct rise alone never flips F live.
- **Defends:** Invariant (1) VISIBILITY (admissible/projectable/displayable/transportable by EVERY still-usable release — both conjuncts, AT THE SAME INSTANT, required); ceiling-active definition (intro_version<=ceiling AND transportable by every still-usable carrier); CARRIER CAPACITY GATES CEILING (chunk-don't-grow); closes coverage gap #8 (two-conjunct timing skew: version reached one ceiling step before its carrier).
- **Refs:** `CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES` / `CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES` / `CONNECTION_FRAME_BUNDLE_FACT_SLOTS` and `frame_size_class_for_facts` (`connection_frame_wire.rs:60,67,659-682`); `connection/send_facts_on_connection.rs:372`; `connection::frame_file_slice` tag 169 / `content::file_slice` tag 55 (the still-absent chunking path); contrast static CEIL-17 / TIME-33 / CONN-10 / MAN-28 / E2EX-21.

### CEIL-GAP18b — carrier conjunct arrives one ceiling-step before its fact's intro_version: fact still dormant (symmetric skew)  `property`
- **Setup:** Same fat family F, but stage the skew the OTHER way. The fleet first reaches a protocol that adds the larger/chunked carrier class (a new `frame_*` tag sibling, e.g. a chunked path modeled on `frame_file_slice` tag 169) at protocol **8**, while F's own TAG is introduced LATER at `intro_version = 9`. Fleet still-usable set: blocker rel-old `1..=7` `expires_at = T7`; rel-head `1..=9`. Start at ceiling 7, then advance trusted_time past `T7 + M` so ceiling becomes **8** (every still-usable release now supports protocol 8 and thus the new carrier class — the TRANSPORT conjunct is satisfied), but `intro_version 9 > ceiling 8` (the VERSION conjunct is not yet true).
- **Action:** Re-evaluate ceiling-active for F at ceiling 8. Then attempt to locally mint an F-fact via the F-creating `con` command path (admission check), independent of whether a carrier now exists.
- **Expect:** F is NOT ceiling-active even though a carrier that can transport it now exists on every still-usable release — the version conjunct fails (`intro_version 9 > ceiling 8`). Local creation of F is REFUSED (above-ceiling mint refused); a RECEIVED F-fact (e.g. from an over-eager peer) is PENDING — retained as opaque bytes, unprojected/undisplayed/uncounted, NOT dropped and NOT errored to the user (it must NOT hit `RouterProjector::project`'s `"no target projector registered for fact tag {tag}"` at projectors.rs:456 as a user-facing error). The existence of a carrier never advances activation ahead of the version conjunct. Both conjuncts must hold at the same instant; the carrier leading by a ceiling step does not flip F live.
- **Defends:** Invariant (1) VISIBILITY (BOTH conjuncts required simultaneously — the converse skew to CEIL-GAP18a); ADMISSION (above-ceiling local-create refused; received above-ceiling PENDING, not errored); ceiling-active definition; closes coverage gap #8 in the carrier-leads-version direction.
- **Refs:** `frame_size_class_for_facts` / new chunked carrier sibling tag (`connection_frame_wire.rs`, `connection::frame_file_slice` tag 169 precedent); pending vs `RouterProjector::project` Err@456 (`core/projectors.rs:456`); ceiling-active glossary; intro_version on routes (`FACT_ROUTES` / `RouterProjector`).

### CEIL-GAP18c — F activates EXACTLY when the lagging second conjunct lands, and gap-window-minted facts activate cleanly on the activating replay  `blackbox-cli`
- **Setup:** Continue CEIL-GAP18a's staging (version conjunct true at ceiling 8, carrier still lagging). Two blockers gate the two conjuncts on separate timelines: rel-old `1..=7` `expires_at = T7` (its exit raises ceiling to 8, satisfying F's `intro_version 8 <= ceiling`); rel-mid `1..=8` `expires_at = T8` with `T8 > T7` whose still-usable presence is what keeps the protocol-8-only carrier inventory (no protocol-9 chunked carrier) in force — only when rel-mid also leaves does the fleet require protocol **9** and its larger/chunked carrier, satisfying the transport conjunct. rel-head `1..=9`. During the GAP window (`T7 + M < trusted_time < T8 + M`, ceiling == 8, F still carrier-blocked) an over-eager alpha/peer node ships an F-fact to this node; this node, correctly, holds it pending (opaque, uncounted).
- **Action:** (1) In the gap window, run the F-creating `con` command and `con content-count` / `con messages`. (2) Advance trusted_time past `T8 + M` so rel-mid leaves and ceiling/carrier-inventory reaches protocol 9 (BOTH conjuncts now true at the same instant). (3) Run the upgrade wipe+replay, then re-run `con content-count` and the F-shipping send (`SendFactsOnConnectionHandler` / `frame_size_class_for_facts`).
- **Expect:** During the gap window: F-create is REFUSED, the pending inbound F is uncounted/undisplayed (count unchanged, no user-facing error). At the instant the LAST lagging conjunct lands (both `intro_version 8 <= ceiling` AND a transporting carrier on every still-usable release), F becomes ceiling-active — not one step earlier. On the activating wipe+replay the gap-window pending F-fact ACTIVATES: it routes to its kept-forever projector (keyed by its OWN tag), materializes, and is counted; replay is order-independent and ceiling-independent (each retained fact replays via the adapter for its own tag). A subsequent send now seals F via the protocol-9 carrier class (no frame growth). Activation is driven ONLY by the legitimate second-conjunct arrival, never by F's own gap-window arrival.
- **Defends:** Invariant (1) (both conjuncts at the same instant gate activation — the precise minting-a-fact-peers-cannot-carry failure mode); ADMISSION (gap-window above-(transport-)ceiling create refused; received F pending then ACTIVATES on next wipe+replay once ceiling+carrier cover its tag); Invariant (4) REPLAY DETERMINISM (per-tag historical adapter, order/ceiling-independent); CARRIER CAPACITY GATES CEILING; closes coverage gap #8's staged-conjunct timeline (the unpinned gap-window behavior).
- **Refs:** `con send` / `con content-count` / `con messages` (MATCH_COMMANDS, registry.rs); `frame_size_class_for_facts` and protocol-9 chunked carrier (`connection_frame_wire.rs:659-682`); `SendFactsOnConnectionHandler` carrier refusal (`connection/send_facts_on_connection.rs:372`); pending activation on wipe+replay vs `RouterProjector::project` Err@456 (`core/projectors.rs:456`); ceiling = min over still-usable releases at trusted_time with margin M (multi-blocker expiry, cf. CEIL-16); contrast static CEIL-17/18, MAN-28, E2EX-21.
### MAN-GAP19a — Own-release-expired node STILL activates pending above-ceiling facts on wipe+replay when the fleet ceiling rises  `replay-cli`
- **Setup:** A `con` node whose OWN release relX has `expires_at = Ex`; trusted_time advanced to `T > Ex + M`, so relX is past expiry and the node is PRODUCTION-BLOCKED (per MAN-09: `con send` refuses to emit `content::message` tag 50). Before expiry the node had RECEIVED an above-ceiling `message:2` fact (new tag, sibling `content/message_v2/`, kept-forever projector) which is currently PENDING — pending opaque, unprojected, undisplayed, `con content-count` excludes it (REPLAY-07 state). The fleet manifest also knows the blocker relO (platform=ios `6..=6`, `expires_at = Eo`); the SAME trusted_time advance that expired relX ALSO carries `T > Eo + M`, so relO drops from the still-usable set and the ceiling RISES to cover `message:2`'s tag. Capture pre-replay `con content-count` and `con state-summary`.
- **Action:** Run `con replay` canonical (wipes derived state, re-marks all retained facts pending, drains projection to fixpoint) on this OWN-EXPIRED, production-blocked node.
- **Expect:** The own-release expiry does NOT gate the replay-side activation: the previously-pending `message:2` fact is marked pending and projects via its OWN-tag (v2) kept-forever adapter, producing its CONTENT_MESSAGES row; `con content-count` increases by one; `con messages` now shows it; `state_hash` changes to reflect the activated row. Replay completes — it does NOT abort at `RouterProjector::project` (`core/projectors.rs:456`) and does NOT refuse activation on the grounds that the binary is expired. The data is NOT stranded: activation (an INPUT/admission concern gated by the fleet ceiling) proceeds independently of the own-production-block. Throughout, `con send` STILL refuses (production remains blocked); local reads succeed (MAN-10).
- **Defends:** TIME-26 "blocked withholds OUTPUT not INPUT/admission" extended to own-EXPIRY (MAN-09/10): own-production-block must NOT also gate replay activation of pending facts. ADMISSION "Pending facts ACTIVATE on the next wipe+replay once the ceiling rises to cover their tag" holds even on an expired binary; Invariant (4) REPLAY DETERMINISM (ceiling-independent over retained facts) and (5) "local data is safe (replays after update)". Prevents the failure mode of stranding received data forever on an expired node.
- **Refs:** MAN-09/10 (own-expiry blocks production, permits reads+replay), TIME-26 (output-not-input), REPLAY-07/08 + MAN-27/TIME-29 (pending activation on ceiling rise); `ReleaseManifestEntry.expires_at` + skew margin M; ceiling = min over still-usable releases (relO drop); new `message:2` tag + sibling `content/message_v2/` projector in `FACT_ROUTES`; `RouterProjector::project` Err@`core/projectors.rs:456` (the hard error pending activation must replace); `drain_pending_projection` (`core/pipeline/project_pending_facts.rs:248`); `con replay`/`content-count`/`messages`/`state-summary`; `content::message` `TYPE_CONTENT_MESSAGE = 50` (`content/message/encode.rs:22`); design rule 8 (replay local/deterministic).

### MAN-GAP19b — On the activating replay, the own-expired node activates pending facts WITHOUT re-enabling shared production (no signed/network leak through the activation seam)  `replay-cli`
- **Setup:** Same own-expired (`T > Ex + M`), production-blocked node as MAN-GAP19a, holding the pending `message:2` fact, with the fleet ceiling now risen (relO expired) to cover its tag. The runtime is opened from `MATCH_RUNTIME`; the four `COMMAND_EXCLUDED_HANDLER_ROUTES` (`send_bootstrap_connection_request`, `send_facts_on_connection`, `send_network_frame`, `receive_network_frame`) plus the deterministic `runs_during_replay=true` handlers (`create_key_wrap`/`unwrap_key_wrap`, HANDLER_ROUTES #8/#9) are wired.
- **Action:** Run `con replay` canonical and instrument the pass: observe whether activation of the pending fact triggers any (a) network frame send, (b) `sync::shared_fact` (tag 162) advertisement of the now-activated row, (c) fresh trusted-time observation, or (d) signing of a NEW shared production fact; and re-check `con send` immediately after replay.
- **Expect:** Activation re-materializes the read-model row ONLY. Zero network frames sent, zero new `sync::shared_fact` advertisements emitted for the activated row, zero fresh-time observations, zero newly-signed shared facts (design rule 8). Deterministic `create_key_wrap`/`unwrap_key_wrap` re-emissions during replay recreate only their existing deterministic facts (idempotent, dedupe to a no-op) and are NOT treated as new shared production to be refused — the rebuild is not corrupted. After replay, `con send` STILL refuses with the same "release expired, update required" block: the activation did NOT silently lift the own-expiry production block or re-enable the binary. The post-replay network barrier (rule 8: full replay+purge finishes before any network resumes) holds, and because the binary is expired the shared-production gate stays closed even after the barrier.
- **Defends:** The activation seam must NOT become a backdoor that re-enables production on an expired binary — getting this wrong "re-enable[s] production on an expired binary." Separates INPUT activation (allowed) from OUTPUT/production (still blocked). Invariant (3) CEILING MONOTONICITY / EXPIRED PEERS ARE OUT (an expired release stays out of the visibility/production guarantee); design rule 8 (replay signs no new shared facts, sends no frames); coverage-r1 prose item #7 (blocked-mode × deterministic replay-recreated facts must not be withheld-as-production).
- **Refs:** MAN-09 (own-expiry production block), TIME-28/MAN-31 (replay runs while blocked; deterministic recreation not treated as production), design rule 8 (Part I above rule 8: "Replay must not observe fresh time, send network frames ... or sign new shared facts"); `COMMAND_EXCLUDED_HANDLER_ROUTES` (`registry.rs:512-517`); `create_key_wrap`/`unwrap_key_wrap` (HANDLER_ROUTES #8/#9, `runs_during_replay=true`); `sync::shared_fact` tag 162; `con send` block path; `con replay`/`intent-registry`.

### MAN-GAP19c — Multi-fact / cross-scope: own-expired node activates a pending file:2 + its slices AND a pending auth fact on the same ceiling-rise replay, order-independently  `replay-cli`
- **Setup:** Own-expired (`T > Ex + M`), production-blocked node holding a MIX of pending above-ceiling facts received before expiry: (1) a `file:2` container fact (new tag, sibling `content/file_v2/`) plus its dependent above-ceiling `file_slice:2` facts, and (2) a pending above-ceiling auth fact (e.g. a `user_profile_v2` / new `auth::*` tag whose intro_version is above the old ceiling). All are pending opaque, unprojected, uncounted (`con content-count`/`con files`/`con users` exclude them). The fleet ceiling rises (relO and any other non-capable blocker past `expires_at + M`) to cover BOTH new tags; the kept-forever v2 projectors and sibling `_v2/` dirs exist for each. Capture pre-replay `con state-summary`.
- **Action:** Run `con replay` canonical, then `con replay --reverse`, then `con replay --scramble --seed N` (equivalently `con replay-check`) on the own-expired node; capture `con state-summary` after each pass.
- **Expect:** On every pass the pending `file:2` + `file_slice:2` and the pending auth fact ACTIVATE: each routes to its OWN-tag kept-forever adapter, the file's slices resolve against their now-activated `file:2` parent via context-match wakeups regardless of admission order, the auth fact materializes its row, and the cross-scope dependency cascade converges. The post-replay `state_hash` is IDENTICAL across canonical / reverse / scramble passes (order-independent activation), and includes the newly-activated content AND auth rows. Own-expiry never selectively gates one scope's activation over another, and never aborts the replay. `con send` remains refused on every pass (production stays blocked). No fact is mis-routed (a v2 fact never hits a v1 projector).
- **Defends:** The own-expiry × pending-activation independence (TIME-26 output-not-input) holds across SCOPES (content container+slice, auth) and across MULTI-FACT dependency cascades, and is order-independent (Invariant (4) REPLAY DETERMINISM, REPLAY-04/05 reverse+scramble equivalence). Confirms an expired node does not strand whole scopes of received data; activation is uniformly an admission/ceiling concern, not a per-scope production gate. Defends Invariant (1) VISIBILITY (a now-ceiling-active fact becomes projectable/displayable) under the awkward own-expired state.
- **Refs:** MAN-GAP19a/b; REPLAY-02/04/05 (mixed-version + reverse/scramble determinism), REPLAY-07/08 (pending survive+activate); `content::file` `TYPE_CONTENT_FILE = 54` + `content::file_slice` `TYPE_CONTENT_FILE_SLICE = 55` (the file_slice→file parent cascade, inventory §1); proposed `auth::user_profile_v2` new tag (inventory §1 notes this family is NOT-yet-existing — RED until it lands); sibling `_v2/` projector dirs in `FACT_ROUTES`; context-match wakeups (`core::pipeline::context`); `con replay`/`--reverse`/`--scramble`/`replay-check`/`state-summary`/`files`/`users`; design rule 8.
### TIME-GAP110a — staleness timer ignores a flood of inbound `frame_observation` receives (no false freshness refresh)  `guardrail`
- **Setup:** (proposed, once trusted_time/staleness exist) `con` daemon with last *signed* observation at `T_last`; staleness window `S`; local time advanced to `now > T_last + S` so the node has crossed into staleness block BLOCKED MODE per TIME-16. No fresh signed registry fact, canary, or embedded-metadata bump has arrived. The store is otherwise healthy and an established connection exists.
- **Action:** deliver a sustained flood of inbound established-connection frames over the `receive_network_frame` intent path (`connection::receive_network_frame::ReceiveNetworkFrameHandler::handle`), each carrying a large/recent `received_at_local_ms` (e.g. `now`, far above `T_last`). Each classifies via `connection_frame::classify_frame` and produces a `connection::frame_observation` fact (`connection_frame::observed_frame_effect` → `frame_observation::create::fact_from_observation`, tag 173) whose `received_at_local_ms` is the attacker/socket-supplied receive time. Re-evaluate the staleness gate after the flood projects.
- **Expect:** the staleness timer is computed ONLY from the greatest *signed* observation (embedded metadata / signed registry fact / signed canary per design rule 3); it does NOT read `ConnectionFrameObservationFact.received_at_local_ms` (nor the `connection_frame_observation` local context offered by `frame_observation::project`). The node stays BLOCKED — `now - T_last` still exceeds `S` — and shared production stays withheld; the flood of `frame_observation` facts admits/projects normally (local-only) but moves neither the staleness deadline nor `trusted_time`.
- **Defends:** model "Staleness window S without refresh ... => BLOCKED MODE"; design rule 3 ("greatest trusted time learned from embedded release metadata, signed registry facts, or signed canaries" — an unsigned local receive time is none of these). Closes the gap that TIME-06 only structurally asserts `frame_observation` is local-only and TIME-16 never crosses staleness with the `frame_observation` receive path. Liveness/downgrade-bypass surface: an attacker who can deliver frames must not be able to forge time freshness.
- **Refs:** `connection::frame_observation` tag 173 (`frame_observation/layout.rs:9`, `RECEIVED_AT_OFFSET`), `ConnectionFrameObservationFact { received_at_local_ms }` (`frame_observation/fact.rs`), `observed_frame_effect` (`connection_frame.rs:192-205`), `ReceiveNetworkFrame.received_at_local_ms` / handler (`connection/receive_network_frame.rs:31,142-159`), `app.rs:62-71` (inbound `received_at_local_ms` is raw socket metadata); TIME-06, TIME-16; design rule 3.

### TIME-GAP110b — blocked-mode exit is NOT triggered by `frame_observation` receive time (only a fresh SIGNED observation leaves blocked mode)  `guardrail`
- **Setup:** (proposed) `con` currently in BLOCKED MODE — entered either via TIME-15 (backward-rollback beyond tolerance) or TIME-16 (staleness). `trusted_time` persisted at `TT`. An established connection exists; no fresh signed observation has been admitted.
- **Action:** admit a flood of inbound established-connection frames whose `frame_observation` facts carry `received_at_local_ms` values both `>= TT` and plausible w.r.t. the local clock (i.e. shaped to look like a "fresh, plausible" signal). Then run the blocked-mode evaluation / attempt a shared-production create such as `con send "hi"` (`content::message`, tag 50).
- **Expect:** the node STAYS BLOCKED and `con send` is still refused with the blocked-mode error; the blocked-mode exit predicate consults only fresh signed sources, never the `connection_frame_observation` local context or any `received_at_local_ms`. `trusted_time` is unchanged at `TT` (a `frame_observation` receive is not a signed observation, so it cannot satisfy plausibility/freshness — consistent with TIME-18 requiring a fresh *signed* observation and TIME-19 forbidding exit via stale/replayed observations). The received `frame_observation` facts remain local-only and uncounted toward time.
- **Defends:** model "blocked mode (shared production withheld) ... leaving blocked mode after a fresh signed observation"; design rule 3. This is the `frame_observation`-specific instance TIME-19 leaves open ("TIME-19 forbids stale-observation exit, but not via the frame_observation path specifically") — prevents a frame-delivery downgrade/liveness bypass that prematurely re-enables shared production.
- **Refs:** `frame_observation::project` (`frame_observation/project.rs:38-59`, offers only a `FactScope::Local` `connection_frame_observation` range context, no read-model row, asserts local scope at :46), `observed_frame_effect` (`connection_frame.rs:192-205`); `content::message` tag 50, `send` (MATCH_COMMANDS #25); ties to TIME-15/TIME-16/TIME-18/TIME-19; design rule 3.

### TIME-GAP110c — `received_at_local_ms` is never folded into `trusted_time`'s monotonic-max (parity with the logical-clock backdoor guard)  `guardrail`
- **Setup:** (proposed) `con` with `trusted_time` persisted at `TT` and NORMAL mode about to cross into staleness; the logical `clock` (`core::clock`, `CLOCK_KEY`) is a separate store key per TIME-35. No new signed observation pending.
- **Action:** deliver inbound frames producing `frame_observation` facts whose `received_at_local_ms` greatly exceeds `TT` (e.g. `TT + 10*S`). Read the persisted `trusted_time` and re-evaluate the ceiling.
- **Expect:** `trusted_time` stays `TT` (the monotonic-max fold is over SIGNED observations only; the unsigned `received_at_local_ms` is not a fold input, exactly as TIME-08 keeps a smaller signed obs from lowering it and TIME-35 keeps the local `clock` from forging it). The ceiling does not advance off a `frame_observation` flood, and the staleness deadline is unmoved. A `frame_observation` whose `received_at_local_ms` is wildly future cannot inflate `trusted_time` to a value that would prematurely expire a blocker (`trusted_time > blocker.expires_at + M`) and leak an above-ceiling capability.
- **Defends:** "TRUSTED TIME = monotonic max of signed observations" + skew-margin ceiling-advance gate; treats `frame_observation.received_at_local_ms` as a non-source for `trusted_time` on par with the logical clock (TIME-35) — both are unsigned/local and must not be backdoors into time-gated ceiling advance. Closes the cross of TIME-06 (structural local-only) with the ceiling/trusted_time computation (the unpinned half of coverage gap #10).
- **Refs:** `frame_observation` tag 173 `received_at_local_ms` (`frame_observation/layout.rs:9-11,26-30`); proposed `trusted_time` key distinct from `CLOCK_KEY` (`clock.rs:16`); TIME-06, TIME-08, TIME-30, TIME-35; design rule 3 and rules 1-2 (ceiling = min over still-usable releases at trusted_time, advance only at `trusted_time > blocker.expires_at + M`).
### GUARD-GAP111a — connection::close projected in BLOCKED MODE emits its close offers + drives the ephemeral-secret purge, and the blocked-mode gate classifies none of it as withheld shared production  `guardrail`
- **Setup:** (proposed, once blocked mode + the blocked-mode production gate exist) `con` in BLOCKED MODE (entered via staleness window `S` lapse or a clock rollback beyond tolerance, per TIME-15/TIME-16). An established connection at rest: a local `connection::response` (tag 44, `FactScope::Local`) row in `CONNECTION_RESPONSE_ROWS`, the initiator + responder `connection::ephemeral_secret` facts (tag 43, `FactScope::Local`) E1 and E2 named by that response's `initiator_ephemeral_secret_fact_id` / `responder_ephemeral_secret_fact_id`, both with rows in `CONNECTION_EPHEMERAL_SECRET_ROWS`. The ceiling currently does NOT cover some future tag, so the store also holds at least one pending above-ceiling fact (TIME-27 shape). No frame send is attempted.
- **Action:** Issue the retire-before-replay close: `connection::close::commands::close(ctx, connection_id)` mints the local tag-45 fact (`Fact::new(FactScope::Local, closed_at_ms, ...)`), submit it via `Runtime::submit_fact`, then run the projection pass so `ConnectionCloseProjector::project_typed` and the woken `ConnectionResponseProjector` / `ConnectionEphemeralSecretProjector` (close-gate arm) all run, while the node stays in BLOCKED MODE the whole time.
- **Expect:** Submission and projection are PERMITTED in blocked mode (TIME-25): the blocked-mode production gate does NOT refuse the close fact and does NOT suppress its projection output. `ConnectionCloseProjector` emits exactly its `connection_response` standing need plus `connection_closed_offer(close_id, connection_id)` and the two `ephemeral_secret_closed_offer(close_id, E1)` / `(close_id, E2)` offers (close.rs:29-39, close/project.rs:76-86) — and the blocked-mode classifier treats these context offers as an operational-safety/connection-lifecycle action, NOT as "shared production withheld". On the woken pass, `ConnectionResponseProjector::closed_output` deletes the `CONNECTION_RESPONSE_ROWS` row and `purge_self(response_id)`; `ConnectionEphemeralSecretProjector` (close gate, ephemeral_secret/project.rs:69-87) for BOTH E1 and E2 deletes the `CONNECTION_EPHEMERAL_SECRET_ROWS` row and `purge_self(fact.id)`. All three retired/secret facts are gone from the store after commit; the pending above-ceiling fact is untouched (still opaque, still retained). Because `connection::close`, `connection::response`, and `connection::ephemeral_secret` are all `FactScope::Local` and never travel over a frame (close/fact.rs doc; close/commands.rs:32), NO outbound frame is produced and nothing is counted as shared production — distinguishing this from the frame-seal path that TIME-25 DOES withhold.
- **Defends:** TIME-25 ("connection::close / retirement remains permitted in blocked mode … an operational safety action, not shared production") crossed with the blocked-mode production gate (TIME-20..24) and the secret-hygiene purge (CONN-21); INVARIANT (6) SAFETY FLOOR (ephemeral secrets purged before upgrade even while blocked).
- **Refs:** `connection/close.rs:22-39` (`CONNECTION_CLOSED_ROLE`, `CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE`, `connection_closed_offer`, `ephemeral_secret_closed_offer`), `connection/close/project.rs:76-86` (`ConnectionCloseProjector`), `connection/close/commands.rs:20-39` (`close`, `FactScope::Local`), `connection/response/project.rs:79-92,389-396` (`closed_output`, `CONNECTION_RESPONSE_ROWS`), `connection/ephemeral_secret/project.rs:69-87` (close gate, `CONNECTION_EPHEMERAL_SECRET_ROWS`, `purge_self`), `core/projectors.rs:356` (`purge_self` is self-only); TIME-25, CONN-19, CONN-21, TIME-27.

### GUARD-GAP111b — ephemeral-secret purge from close does not race the pending-activation replay pass: the close purge runs and commits before the wipe+replay that activates a newly-covered tag  `replay-cli`
- **Setup:** (proposed) Continue from GUARD-GAP111a's pre-replay state: an in-blocked-mode (or mid ceiling-transition) node holding (i) an open connection with response row + E1/E2 ephemeral rows, and (ii) a pending above-ceiling fact whose tag will be covered after the ceiling rises (TIME-29 shape). The retire-before-replay sequence per the model TRANSPORT rule "Retire connections … before replay" is: project the `connection::close` (tag 45) to purge first, THEN raise the ceiling and run wipe+replay.
- **Action:** Drive the two phases in order: phase 1 — submit + project `connection::close` so E1, E2 (tag 43) and the response (tag 44) self-purge and their rows are deleted, and commit; phase 2 — raise the ceiling to cover the pending fact's tag, then run the wipe+replay pass (`con test-replay-deps-reverse` cascade surface today; the upgrade replay conceptually) that re-projects every retained fact via its own tag adapter and activates the formerly-pending fact.
- **Expect:** The two passes are serialized, not interleaved: the close-driven purge fully commits (E1/E2/response bytes removed, `CONNECTION_EPHEMERAL_SECRET_ROWS` + `CONNECTION_RESPONSE_ROWS` rows deleted) BEFORE the pending-activation replay begins, so the replay rebuilds derived state from RETAINED facts only — it never re-derives a `connection_ephemeral_secret` row from a purged secret and never live-tails the retired session (the CONN-20 guarantee). The replay does not resurrect E1/E2: their bytes are gone, the surviving tag-45 `connection::close` fact replays deterministically via its own adapter, and the now-active formerly-pending fact projects to its own rows independently of the retired connection. Replay observes no fresh time, sends no frames, and the ephemeral purge result is order-independent w.r.t. the activation of the pending fact (no read-after-purge of E1/E2 by the activating projector, and no purge-after-activation that could strand a half-retired session).
- **Defends:** Model TRANSPORT "Retire connections … before replay" sequenced ahead of pending activation; INVARIANT (4) REPLAY DETERMINISM (order-independent, ceiling-independent, recreates only deterministic facts from retained bytes) crossed with ADMISSION pending-activation (TIME-29); CONN-20 (no phantom live connection after close+replay); CONN-21 secret hygiene preserved across the activation pass.
- **Refs:** `connection/ephemeral_secret/project.rs:69-87` (close-gate purge of E1+E2), `connection/response/project.rs:389-396` (`closed_output` purge), `connection/close/project.rs` (`ConnectionCloseProjector`), `core/projectors.rs:356` (`purge_self`), `core/projectors.rs` `RouterProjector::project` (per-tag adapter, projectors.rs:448-459), `sync::cascade_test_fact::cli` `test-replay-deps-reverse`; CONN-19, CONN-20, CONN-21, CONN-28, TIME-28, TIME-29.

### GUARD-GAP111c — a forged/global connection::close cannot smuggle a secret purge through the blocked-mode operational-safety exemption  `projector-unit`
- **Setup:** (proposed) Blocked-mode node with the same open connection (response row + E1/E2 ephemeral rows). Craft a `connection::close` fact submitted with `FactScope::Global` (or local but with NO matching `connection_response` context for its named `connection_id`) — i.e. an attempt to exploit the TIME-25 "close is always allowed in blocked mode" exemption to drive a purge of another session's secrets.
- **Action:** Project the forged close via `ConnectionCloseProjector::project_typed` in blocked mode.
- **Expect:** Projection refuses to emit any close context: the global-scope variant errors `"connection close fact must have local scope"` (close/project.rs:48-50); the no-context variant returns only the standing `connection_response` need with NO `connection_closed_offer` / `ephemeral_secret_closed_offer` (close/project.rs:63-65). Consequently neither `ConnectionResponseProjector` nor `ConnectionEphemeralSecretProjector` is woken, E1/E2 are NOT purged, and the response row survives. The blocked-mode operational-safety exemption that permits retirement (TIME-25) is scoped to a properly local, context-proven close and is NOT a backdoor for a peer-injected close to tear down a session or destroy ephemeral secrets — matching the CONN-22 retirement-authority gate, now asserted to hold under blocked mode.
- **Defends:** TIME-25 retirement exemption is gated by the same local-scope + `connection_response`-context authority check as in NORMAL mode (no blocked-mode widening of the close authority surface); INVARIANT (6) SAFETY FLOOR (retirement authority is local + context-gated); secret hygiene not weaponizable.
- **Refs:** `connection/close/project.rs:47-53` (structural local-scope check), `:55-65` (context need, no-offer-without-context), `:76-86` (offers only on the proven path); `connection/close.rs:41-61` (`exact_local_need`/`exact_local_offer` use `FactScope::Local`); CONN-22, TIME-25, CONN-21.
### SYNC-GAP20a — `sync_status` root_fingerprint folds `context_have`, so it diverges across two converged peers that recorded different anchor sets for the same owner (while the on-wire compare summary stays equal)  `projector-unit`
- **Setup:** One in-memory `Store` per simulated node, both seeded with `CORE_SCHEMA_SOURCE + FACTS_SCHEMA_SOURCE` (the `store()` helper in `shared_fact/rows.rs` tests). On BOTH nodes record the SAME single owner fact `U` via `record_sync_contribution(store, &ShareFactWithSync{ workspace_id: W, owner_fact_id: U.id, timestamp_ms: U.timestamp, state: SyncShareState::Upsert, context_have }, Some(&U))`. Node A passes `context_have: vec![anchor_v1.id]` (a capable node that decoded a v2 owner and advertised its v1 dependency anchor — the SYNC-05 projector path). Node B passes `context_have: vec![]` (same owner learned without its dependency closure: anchor pending / purged / received deps-less). `U.id` and `U.timestamp` are byte-identical on both; the ONLY difference is the advertised `context_have`.
- **Action:** (1) Call `sync_status(&store_a)` and `sync_status(&store_b)` and compare `root_count` and `root_fingerprint`. (2) Separately, build the on-wire summary over the SAME single fact on each node: `sync::compare::create::summarize_range(&[&U])` (the path SYNC-13 exercises) and compare those two `RangeSummary` values.
- **Expect:** (1) `root_count` is EQUAL (both = 1) but `root_fingerprint` DIFFERS between A and B: each level-64 leaf's `summary.fingerprint` equals its `contribution_fingerprint`, which folds `blake3("topo:sync-contribution:v1:" || workspace_id || owner_fact_id || timestamp_be || len_be || context_have...)` (rows.rs:509-525) — A's leaf folds `[anchor_v1.id]`, B's folds the empty list, so the XORed roots in `sync_status` (rows.rs:821-835) are unequal. This proves `con sync-status root_fingerprint` is NOT closure-independent. (2) In contrast `summarize_range(&[&U])` is IDENTICAL on both: it folds ONLY `blake3("topo:sync-range-summary:v1:" || timestamp_be || fact.id)` (compare/create.rs:245-261) — no `context_have`, no version. The single test thus crosses the two fingerprint algorithms the suite conflates: the persisted root is closure-sensitive; the on-wire summary is closure-/version-independent.
- **Defends:** Distinguishes the two fingerprint algorithms (persisted `contribution_fingerprint`-folds-`context_have` vs on-wire `(timestamp,id)` summary); corrects the over-broad reading of Invariant 2 that SYNC-26 attaches to `sync-status`; mechanism: `sync_status` root XORs leaf `contribution_fingerprint`s, so closure divergence under versioning (SYNC-05) flows into the root.
- **Refs:** `shared_fact/rows.rs:509` `contribution_fingerprint`, `:280-307` `upsert_sync_contribution` (extends + recomputes leaf), `:821-835` `sync_status` (XOR of level-64 leaf summary fingerprints), `:39/:43` `NegentropyLeafRow.contribution_fingerprint`, `:213` `record_sync_contribution`; `share_fact_with_sync.rs:45-52` `ShareFactWithSync.context_have`; `compare/create.rs:245-261` `summarize_range` / `RangeSummary`; contrast SYNC-13/SYNC-26/SYNC-27.

### SYNC-GAP20b — a `root_fingerprint` mismatch on an identical id set (closure divergence only) does NOT trigger a perpetual compare/have/need round — convergence is decided by the on-wire `(timestamp,id)` summary, not `sync-status`  `multinode-network`
- **Setup:** Two daemons in ONE shared workspace (`accept_workspace_invite(&alice,&bob,&workspace,alice_port,"bob","bob-phone")`, `create_local_content_key` each, `spawn_daemon` both). Engineer the divergent-closure-but-identical-ids end state of SYNC-GAP20a end to end: bob `send`s a v2 owner `U` plus its dependency anchor; bob `sync-range ... --with-deps` to `endpoint_id(&alice)`. Arrange that alice receives `U` AND the anchor but, on alice, `U`'s `share_fact_with_sync` upsert is projected with a DIFFERENT `context_have` than bob recorded (e.g. alice's projector advertised `[]`/a different anchor id because the anchor was pending/late when `U`'s projector ran on alice, while bob advertised the anchor). After exchange both nodes hold the SAME shareable id set for `W` (`shareable_facts_for_connection` returns equal id sets on both).
- **Action:** (1) `con --db alice sync-status` and `con --db bob sync-status`; capture `root_count` and `root_fingerprint`. (2) Then drive the actual reconciliation: have each side issue `sync-range` over the common range and let the negentropy compare/have/need loop run to quiescence; poll `fact_count` and the count of outstanding `sync::need_id`(167)/`sync::have_id`(166) facts on each node.
- **Expect:** (1) `root_count` MATCHES; `root_fingerprint` DIFFERS (the persisted root folds the divergent `context_have`, per SYNC-GAP20a). (2) Crucially this mismatch does NOT cause an endless reconciliation: the on-wire compare uses `summarize_range`/`range_summary_for_connection` (folds only `(timestamp,id)`), so the two converged peers compute EQUAL on-wire root summaries, the compare matches, and NO new `sync::need_id`/`sync::have_id` are minted — `fact_count` and outstanding control-fact counts reach a fixed point on both nodes within the poll window (no growth, no flap). The test pins that `sync-status root_fingerprint` is a LOCAL diagnostic that may legitimately disagree across closure-divergent peers, and that wire convergence is decided by the id-only summary — guarding against any future change that wired `sync-status root_fingerprint` into the compare/initiate path, which would wrongly trigger a perpetual round on identical id sets.
- **Defends:** Mechanism: the on-wire negentropy summary (`summarize_range`, version-/closure-independent) governs convergence, NOT the persisted `sync_status` root; ADMISSION/closure: a v2 owner's SYNC-05 anchor advertisement can diverge `context_have` between peers without breaking termination; documents `sync-status` as closure-sensitive diagnostic, not a convergence oracle.
- **Refs:** `shared_fact/rows.rs:821-835` `sync_status`, `:852` `range_summary_for_connection`, `:838` `shareable_facts_for_connection`, `:280-291` `upsert_sync_contribution` (merges advertised `context_have`); `compare/create.rs:245-261` `summarize_range` / `response_plan`; `sync::need_id` 167 / `sync::have_id` 166; `share_fact_with_sync.rs` `ShareFactWithSyncHandler`; two-daemon harness + `endpoint_id` / `fact_count` / `shareable_facts_for_connection`; extends SYNC-26 (which only asserts the on-wire-equal case) and E2E-GAP15 (which never crosses into the persisted root).

### SYNC-GAP20c — guardrail: pin that the persisted `contribution_fingerprint` folds `context_have` and the on-wire `summarize_range` does not, so SYNC-26's "version-independent root_fingerprint" claim is scoped to the on-wire summary  `guardrail`
- **Setup:** Pure-function structural test over the two fingerprint sites; no store. Build one owner fact `U` (any tag, e.g. `content::message:2` tag 56). Pick two distinct non-empty `context_have` lists `Ca = [a1]` and `Cb = [a1, a2]` and the empty list `[]`.
- **Action:** (1) Call `contribution_fingerprint(W, U.id, U.timestamp, &Ca)`, `contribution_fingerprint(W, U.id, U.timestamp, &Cb)`, and `contribution_fingerprint(W, U.id, U.timestamp, &[])` (the rows.rs:509 helper, exposed to the test module). (2) Call `summarize_range(&[&U])`. (3) Re-derive what `sync_status` XORs: confirm the level-64 leaf `summary.fingerprint` equals `contribution_fingerprint` (rows.rs:300-307) so the root inherits the `context_have` dependence.
- **Expect:** (1) The three `contribution_fingerprint` outputs are all DISTINCT — proving the persisted leaf is a function of the `context_have` set (and its length prefix `len_be`), not just `(timestamp,id)`. (2) `summarize_range(&[&U]).fingerprint == blake3("topo:sync-range-summary:v1:" || U.timestamp_be || U.id)` and is INVARIANT under any choice of `context_have` (it never sees `context_have`). (3) The level-64 `RangeSummary.fingerprint` written by `upsert_sync_contribution` equals the `contribution_fingerprint`, so `sync_status.root_fingerprint` provably folds `context_have`. This guardrail documents the seam: SYNC-13's and SYNC-26's "fingerprint = XOR over (timestamp,id); version-independent" is TRUE for `summarize_range` but MUST NOT be asserted of the persisted `sync_status` root; any refactor that makes them share one fingerprint must update this test.
- **Defends:** VERSIONING KNOB / Invariant 2 boundary: the on-wire sync summary is version-/closure-independent (the genuine uniformity guarantee) while the persisted negentropy leaf intentionally folds dependency-closure context; prevents the suite from conflating the two algorithms (the explicit THIN flag in 90-coverage-r2.md).
- **Refs:** `shared_fact/rows.rs:509-525` `contribution_fingerprint` (domain tag `topo:sync-contribution:v1:`, folds `workspace_id||owner_fact_id||timestamp_be||len_be||context_have...`), `:300-307` leaf `RangeSummary{count:1, fingerprint: contribution_fingerprint}`, `:821-835` `sync_status` XOR, `:527` `xor_fingerprint`; `compare/create.rs:245-261` `summarize_range` (domain tag `topo:sync-range-summary:v1:`, folds only `timestamp_be||fact.id`); cross-ref SYNC-13, SYNC-26, SYNC-27.
### SYNC-GAP21a — re-upserting an owner with a now-purged anchor dropped from `context_have` does NOT shrink the persisted leaf set, and the leaf `contribution_fingerprint` (hence `root_fingerprint`) stays pinned to the phantom anchor  `rows-unit`
- **Setup:** A `protocol::sync::shared_fact::rows` unit test using the existing `tests::store()` + `tests::fact()` + `tests::upsert()` helpers. `workspace_id = [9; 32]`. One owner fact `owner = fact(workspace_id, 42, 1)`. Pick two distinct context anchor ids: `anchor_purged = [7; 32]` (the anchor that will later be purged/retired) and `anchor_keep = [5; 32]` (a surviving anchor). First record the owner WITH both anchors advertised: `record_sync_contribution(&store, &upsert(workspace_id, &owner, vec![anchor_keep, anchor_purged]), Some(&owner))` returns `true`. Capture `before = sync_status(&store).expect("status")` and `before_ctx = negentropy_context_have_for_leaf(&store, workspace_id, owner.id)` (sorted/deduped, so `vec![anchor_keep, anchor_purged]`).
- **Action:** Simulate the owner's projector re-advertising AFTER `anchor_purged` was purged/retention-tightened/chop-now-retired — i.e. a fresh upsert for the SAME owner+timestamp whose `context_have` no longer mentions the purged anchor: `let shrunk = record_sync_contribution(&store, &upsert(workspace_id, &owner, vec![anchor_keep]), Some(&owner)).expect("re-upsert with reduced context_have")`. (Same `owner_fact_id`/`timestamp_ms`, so it hits the `upsert_sync_contribution` merge path, not retract.)
- **Expect:** PINS the monotone-accumulate-never-shrink bug. `shrunk == false` (the merge of `{anchor_keep, anchor_purged}` with `{anchor_keep}` sort+dedups back to `{anchor_keep, anchor_purged}`, so `new_fingerprint == old_leaf.contribution_fingerprint` and the early `Ok(false)` at rows.rs:296-298 fires). `negentropy_context_have_for_leaf(&store, workspace_id, owner.id) == before_ctx` — the purged `anchor_purged` is STILL present (set never shrank, rows.rs:283-285). `sync_status(&store) == before` — the `root_fingerprint` did NOT change even though the projector tried to drop a purged anchor, so the persisted negentropy index keeps a phantom `context_have` id and the node's self-consistency across a purge is now an asserted (currently-failing-to-shrink) property. Document that the ONLY existing way to clear `anchor_purged` is a full-leaf `SyncShareState::Retract` (rows.rs:366-414) which also drops the surviving owner — there is no per-anchor downward re-derivation.
- **Defends:** Pins the unfixed `upsert_sync_contribution` monotone-grow at rows.rs:280-285 (read existing `context_have`, `extend`, `sort`, `dedup` — never removes); failure mode (a) from the gap — a single node's `root_fingerprint` (`sync_status`, rows.rs:821-836, XOR of level-64 node fingerprints) is invariant across an anchor purge because the leaf `contribution_fingerprint` (rows.rs:509-525, folds every `context_have` id) still references purged material. Complements REPLAY-GAP11/AUTHZ-GAP16 (authority-anchor purge at the projector layer) and SYNC-GAP12c (closure BFS via `negentropy_context_have_for_leaf`), neither of which pins this persisted-index consequence.
- **Refs:** `protocol/sync/shared_fact/rows.rs:262-285` (`upsert_sync_contribution` read+extend+sort+dedup), `:286-298` (`contribution_fingerprint` + early `Ok(false)` on unchanged fingerprint), `:509-525` (`contribution_fingerprint` folds `context_have`), `:821-836` (`sync_status`/`root_fingerprint`), `:1285-1301` (`negentropy_context_have_for_leaf`), `:366-414` (`retract_sync_contribution` — only full-leaf removal), `:617-651` (existing `sync_contribution_is_idempotent_and_monotonically_adds_context` — establishes the grow-only baseline this test extends to the purge case); MODEL TRANSPORT "Retire connections … before replay", INVARIANT (6) SAFETY FLOOR, MODEL ADMISSION purge/retention path; SYNC-GAP12c, REPLAY-GAP11, AUTHZ-GAP16.

### SYNC-GAP21b — a node that recorded the owner BEFORE the anchor purge and a node that recorded it AFTER compute DIFFERENT leaf fingerprints / `root_fingerprint` despite holding the identical surviving fact ids  `rows-unit`
- **Setup:** A `protocol::sync::shared_fact::rows` unit test building TWO independent stores via `tests::store()`, `pre` and `post`, both `workspace_id = [9; 32]` with the SAME owner `owner = fact(workspace_id, 42, 1)`, the SAME surviving anchor `anchor_keep = [5; 32]`, and a purgeable anchor `anchor_purged = [7; 32]`. Into `pre` (the node that recorded the owner while the anchor still existed) record `record_sync_contribution(&pre, &upsert(workspace_id, &owner, vec![anchor_keep, anchor_purged]), Some(&owner))`. Into `post` (a node that first received the owner AFTER the anchor was purged, so the owner's projector advertised the reduced set) record `record_sync_contribution(&post, &upsert(workspace_id, &owner, vec![anchor_keep]), Some(&owner))`. Neither store ever sees a retract; after the conceptual purge both nodes hold exactly the same SURVIVING fact ids (`owner` + `anchor_keep`).
- **Action:** Compute `let pre_status = sync_status(&pre).expect("pre"); let post_status = sync_status(&post).expect("post");` and the per-leaf views `negentropy_context_have_for_leaf(&pre, workspace_id, owner.id)` vs `negentropy_context_have_for_leaf(&post, workspace_id, owner.id)`, and the workspace root summaries `range_summary_for_workspace(&pre, workspace_id, TimestampRange::ROOT)` vs the `post` equivalent.
- **Expect:** PINS the cross-node divergence (failure mode (b)). `pre`'s leaf `context_have` is `vec![anchor_keep, anchor_purged]` while `post`'s is `vec![anchor_keep]` — different sets, so the two leaves hash to DIFFERENT `contribution_fingerprint`s (rows.rs:509-525 length-prefixes and folds each id). Therefore `pre_status.root_fingerprint != post_status.root_fingerprint` and `pre`'s `range_summary_for_workspace(.., ROOT).fingerprint != post`'s, even though `root_count == 1` on both and both hold identical surviving facts. This is a converged pair that the negentropy compare (`range_summary_for_*` → `sync::compare`) reports as DIVERGENT, the safety-relevant "stranded in endless compare rounds" outcome. The test asserts the divergence today (documenting the bug) and is the regression target for a fix that would make `post` and `pre` agree once the purged anchor is re-derived out of `pre`'s leaf.
- **Defends:** Failure mode (b) from the gap — order-of-receipt-relative-to-purge changes the persisted leaf and thus `root_fingerprint`, violating the spirit of INVARIANT (4) REPLAY DETERMINISM ("order-independent … recreates only deterministic facts") and INVARIANT (2) RENDERING UNIFORMITY (two nodes holding the same retained facts at the same protocol version should agree). Directly exercises the monotone-grow at rows.rs:280-285 across two nodes; not covered by SYNC-GAP12a/b/c (which fix one node's closure) nor AUTHZ-12..15 (projector/authority layer).
- **Refs:** `protocol/sync/shared_fact/rows.rs:280-285` (merge grows only), `:286-291` (`contribution_fingerprint` over the merged set), `:509-525` (fingerprint definition — order-insensitive only because of sort+dedup, but SET-sensitive), `:821-836` (`sync_status`), `:866-885` (`range_summary_for_workspace` XORs covering-node fingerprints — what `sync::compare` consumes), `:1285-1301` (`negentropy_context_have_for_leaf`); INVARIANT (4) REPLAY DETERMINISM, INVARIANT (2) RENDERING UNIFORMITY, MODEL TRANSPORT "endless compare rounds" hazard; SYNC-GAP12a, SYNC-GAP12b, SYNC-GAP12c, AUTHZ-12, AUTHZ-13, AUTHZ-14, AUTHZ-15.

### SYNC-GAP21c — wipe+replay does NOT heal the phantom anchor: re-projecting only the surviving facts via their own tag adapters cannot reproduce the pre-purge leaf, so a replayed `pre`-style node's `root_fingerprint` is unstable across the purge/replay transition  `rows-unit`
- **Setup:** A `protocol::sync::shared_fact::rows` unit test modeling the upgrade/purge transition. Build `pre = tests::store()` with `owner = fact([9;32], 42, 1)`, surviving `anchor_keep = [5; 32]`, purged `anchor_purged = [7; 32]`; record `record_sync_contribution(&pre, &upsert([9;32], &owner, vec![anchor_keep, anchor_purged]), Some(&owner))` and capture `pre_pre_purge = sync_status(&pre)`. Then build `replayed = tests::store()` representing the SAME node after a wipe+replay that runs AFTER the purge: replay only re-projects the surviving facts, so the owner's projector now advertises only `anchor_keep` — record `record_sync_contribution(&replayed, &upsert([9;32], &owner, vec![anchor_keep]), Some(&owner))` and capture `replayed_status = sync_status(&replayed)`.
- **Action:** Compare `pre_pre_purge.root_fingerprint` (the index the node served BEFORE purge+replay) against `replayed_status.root_fingerprint` (what the same retained facts rebuild to AFTER purge+replay), and assert `negentropy_context_have_for_leaf(&replayed, [9;32], owner.id) == vec![anchor_keep]` (the rebuilt leaf no longer carries the purged anchor). For contrast, also drive a `SyncShareState::Retract` of the owner on `pre` followed by a fresh `vec![anchor_keep]` upsert (rows.rs:366-414) and show THAT path DOES reach the `replayed` fingerprint — i.e. only a full-leaf wipe, not the in-place merge, can shrink the set.
- **Expect:** PINS that the persisted negentropy index is NOT a deterministic function of the retained facts across the purge boundary: `pre_pre_purge.root_fingerprint != replayed_status.root_fingerprint` (the pre-purge index folded `anchor_purged`; the post-purge rebuild cannot, because the purged anchor fact id is gone from the owner's advertised `context_have`). The replayed leaf is correctly `vec![anchor_keep]`, proving the fingerprint instability is caused by the live index's monotone accumulation (rows.rs:280-285), not by replay. The retract+re-upsert contrast confirms the index reaches the replay-consistent value ONLY when the whole leaf is dropped first (rows.rs:394-411), establishing the shape of any future per-anchor downward re-derivation fix and confirming INVARIANT (4)'s "ceiling-independent / rebuild from retained facts" is currently violated by a stale live index that disagrees with its own clean replay.
- **Defends:** The fingerprint consequence of the gap across the wipe+replay/upgrade transition — INVARIANT (4) REPLAY DETERMINISM ("wipe+replay rebuilds derived state … recreates only deterministic facts") crossed with the purge/retention path: a live `root_fingerprint` that "secretly references purged material" diverges from the same node's clean replay. Pins rows.rs:280-285 as the divergence source and rows.rs:366-414 (retract) as the only existing healing path. Adjacent to but distinct from SYNC-GAP12c (closure BFS correctness) and REPLAY-GAP11 (authority-anchor purge replay).
- **Refs:** `protocol/sync/shared_fact/rows.rs:280-298` (merge + unchanged-fingerprint short-circuit), `:308-360` (leaf/context-row rewrite — writes the grown set), `:366-414` (`retract_sync_contribution` — full-leaf removal, the only shrink path), `:417-453` (`update_node_path_in_tx` XOR fold into node summaries), `:509-525` (`contribution_fingerprint`), `:821-836` (`sync_status`/`root_fingerprint`); INVARIANT (4) REPLAY DETERMINISM, INVARIANT (6) SAFETY FLOOR (purged material must not remain folded into a served fingerprint), MODEL ADMISSION "pending facts activate on the next wipe+replay" transition; SYNC-GAP12c, REPLAY-GAP11, AUTHZ-GAP16.
### SYNC-GAP22a — Security-deprecation canary fires BETWEEN the compare-response plan and the requested-fact send: discontinuous ceiling JUMP re-derives the in-flight round (no +M gate)  `multinode-network`
- **Setup:** Floor 6, ceiling 6. Still-usable set {mobile `6..=6` (the blocker, NOT yet past `expires_at = T`), desktop `6..=7`}. Peer A (desktop, head 7) and peer B share a workspace over an established `connection::response` (tag 44) connection `C`. A's shareable index (`SHAREABLE_FACT_ROWS` / `NEGENTROPY_LEAF_ROWS`, recorded by `record_sync_contribution`) holds an in-range v1 owner `O1` (`content::message:1`, tag 50) AND an owner `U` (`content::message_v2`, intro_version 7) that is above-ceiling at 6 — `U`'s bytes are retained in the index but it is NOT ceiling-active. B's incoming `sync::compare` (tag 165) mismatches a leaf range covering both `O1` and `U`'s timestamps. trusted_time is well below `T + M` (mobile's natural expiry is NOT imminent — this trigger must NOT be confused with timed expiry). The signed `must_update` canary (proposed durable local fact, sibling to `auth::local_secret_retirement`) naming the mobile release is staged but not yet applied.
- **Action:** Drive ONE round in two steps. (1) Run `SendSyncCompareResponseHandler::handle` on B's compare at ceiling 6: `shareable_facts_for_connection(store, C)` + `response_plan_with_summaries(..., |range| range_summary_for_connection(store, C, range))` + `expand_fact_ids_with_context_for_connection(store, C, &plan.send_fact_ids)` select the send set under ceiling 6 — `O1` is named (in-range, ceiling-active) while `U` is excluded because at ceiling 6 it is above-ceiling and never minted into the round. The round lands a `sync::need_id` (tag 167) for `O1` (NOT for `U`). (2) BEFORE running `SendRequestedFactHandler::handle` on that `O1` need-id, APPLY the signed `must_update` canary naming the mobile release (per MAN-16/CEIL-12: a canary for ANOTHER release acts as an instantaneous ceiling INPUT). Recompute the still-usable set and ceiling: mobile leaves the set IMMEDIATELY — NOT at `T + M`, with NO skew margin — and the ceiling jumps 6 → 7 discontinuously. `U` (intro 7) is now ceiling-active.
- **Expect:** The mid-round canary jump does NOT cause the half-completed round to smuggle `U` to B. `SendRequestedFactHandler::handle` answers ONLY the explicitly requested id (`O1`): it loads `O1` via `persisted_fact`, confirms `shareable_fact_for_connection(store, C, O1).is_some()`, passes `require_sendable_fact(&O1)` (a v1 fact admissible at 6 stays admissible at 7 — VISIBILITY is monotone), and ships `O1` byte-identically. `U` is NOT back-filled into a round whose closure was selected under ceiling 6 — `SendRequestedFactHandler` has no need-id for `U`. `U` becomes a syncable member ONLY on the NEXT compare/seed pass that runs WHOLLY at ceiling 7: that pass calls a FRESH `response_plan_with_summaries` whose `range_summary_for_connection` / shareable index is now evaluated against the canary-recomputed ceiling, so `U`'s id enters the plan and a new `sync::have_id`/`need_id` exchange ships it. Convergence is correct across the DISCONTINUOUS transition: B ends with `O1` from the canary-straddling round, `U` from the subsequent wholly-post-canary round — never a torn round that emits `U` without re-deriving the plan under the new ceiling. The non-time-gated SYNC-GAP12a reasoning re-holds: the proof does NOT rely on the `+M` skew window (there is none here), only on "the plan is the unit of ceiling evaluation and `SendRequestedFact` answers by id."
- **Defends:** ADMISSION (an above-ceiling-at-plan-time fact is not smuggled into an in-flight round even when the ceiling jumps with NO skew margin); CEILING MONOTONICITY (3) for a DISCONTINUOUS canary-driven rise; convergence-across-a-mid-sync-transition for a non-time-gated trigger; fills the Matrix C `sync × security-deprecation canary` cell (previously EMPTY) — the canary analog of SYNC-GAP12a, which only covered a smooth `+M`-gated blocker expiry.
- **Refs:** `sync/send_compare_response.rs` `SendSyncCompareResponseHandler::handle` (`shareable_facts_for_connection`, `response_plan_with_summaries`, `range_summary_for_connection`, `expand_fact_ids_with_context_for_connection`); `sync/send_requested_fact.rs` `SendRequestedFactHandler::handle` (`persisted_fact`, `shareable_fact_for_connection`, `require_sendable_fact`); `sync::need_id` 167 / `sync::compare` 165; `content::message_v2` intro 7 vs `content::message:1` 50; CEIL-12 / MAN-13 / MAN-16 (canary recomputes ceiling UP immediately, no `+M`); SYNC-GAP12a (the smooth-expiry analog this re-proves for a discontinuity).

### SYNC-GAP22b — Canary deprecating the responder's OWN release fires mid-round: the in-flight requested-fact send is WITHHELD (blocked-mode shared production), the need/have round strands cleanly  `multinode-network`
- **Setup:** Floor 6, ceiling 7 (mobile already expired earlier; still-usable {desktop `6..=7`}). Peer A is the desktop responder running release `relX` and is mid-round answering B: A has already run `SendSyncCompareResponseHandler::handle` at ceiling 7 and emitted a `sync::have_id` (166) advertising an in-range owner `O` (`content::message:1`, tag 50, shareable on `C`); B has replied with a `sync::need_id` (167) naming `{C, O}`. A signed `must_update` canary naming relX itself (security-deprecation of A's OWN release, per MAN-13) is staged but not yet applied. trusted_time is healthy (relX NOT past its own `expires_at`).
- **Action:** (1) Confirm at ceiling 7 that A would ship `O`: `SendRequestedFactHandler::handle` on the `{C, O}` need-id loads `O`, confirms `shareable_fact_for_connection(store, C, O).is_some()`, `require_sendable_fact(&O)` passes. (2) APPLY the canary naming relX (recompute still-usable: relX is removed → A enters BLOCKED MODE — shared production withheld; local reads + replay still run, per the model's staleness/deprecation rule and MAN-13 "shared production BLOCKED IMMEDIATELY"). (3) Re-drive `SendRequestedFactHandler::handle` on the SAME in-flight `{C, O}` need-id under the now-blocked production state.
- **Expect:** The in-flight send is WITHHELD: with relX security-deprecated, A's shared-production path refuses to emit the `send_facts_on_connection` / outbound `connection::frame_*` carrying `O` — the canary short-circuits relX out of the still-usable set at once (no waiting for `expires_at`, distinct from the slow path). The half-completed round does NOT push `O` onto the wire after the deprecation; it strands cleanly with NO partial/torn frame and NO error that corrupts B's state (B simply never receives the answer to its need-id and will re-advertise on a later seed). Local reads on A still resolve `O` (blocked mode withholds SHARED production only — `messages` / `content-count` over retained facts still work; replay still rebuilds). The need/have round is re-derivable: once relX is updated out-of-band to a non-deprecated release, A's next `SendSyncCompareResponseHandler` pass resumes shared production and answers B's outstanding need. No above-ceiling smuggling is even reachable — the gate here is the OWN-release deprecation withholding ALL shared production, which must dominate any in-flight send already planned under the pre-canary state.
- **Defends:** SAFETY FLOOR (6) + separation 2: an OWN-release security-deprecation canary withholds shared production IMMEDIATELY and that withholding overrides an in-flight requested-fact send planned under the pre-canary state; blocked-mode invariant (shared production withheld, local reads + replay intact); fills the Matrix C `sync × security-deprecation canary` cell for the OWN-release direction (the responder, not just the ceiling-input case of SYNC-GAP22a). Contrast MAN-13 (own-release block at the `con send` CLI) — here the block must also catch the SYNC responder's in-flight `SendRequestedFactHandler` path.
- **Refs:** `sync/send_requested_fact.rs` `SendRequestedFactHandler::handle` (`require_sendable_fact`, `shareable_fact_for_connection`, `send_facts_on_connection_intent`); `sync::need_id` 167 / `sync::have_id` 166; signed `must_update` canary (proposed durable local fact, sibling to `auth::local_secret_retirement`); `registry.rs` `COMMAND_EXCLUDED_HANDLER_ROUTES` (`send_facts_on_connection` is the gated egress); MAN-13 (own-release canary blocks shared production immediately); SYNC-GAP22a (the ceiling-input / other-release direction).

### SYNC-GAP22c — Grace-window extension lands mid-round: it HOLDS the ceiling a naive timer would have raised, keeping a would-be-activated fact above-ceiling so it is NOT smuggled into the in-flight round (reverse-direction discontinuity)  `multinode-network`
- **Setup:** Floor 6, ceiling 6. Still-usable {mobile `6..=6` `expires_at = T` (the blocker), desktop `6..=7`}. Peer A (desktop, head 7) is mid-round answering B over connection `C`. A's shareable index holds in-range v1 owner `O1` (`content::message:1`, tag 50) AND owner `U` (`content::message_v2`, intro 7, above-ceiling at 6, bytes retained). B's `sync::compare` (165) mismatches a leaf range covering both. trusted_time is approaching `T` such that, on a NAIVE timer with no grace handling, A would cross `T + M` between the plan and the send and would treat `U` as newly ceiling-active. A re-signed mobile manifest entry (`MAN-06` monotonic-union grace extension) moving `expires_at` to `T2 > T` is staged and reaches A (the capable producer) at `t_ext < T` — BEFORE the original deadline (the safe-grace case, CEIL-23).
- **Action:** (1) Run `SendSyncCompareResponseHandler::handle` at ceiling 6: the plan names `O1` (ceiling-active) and EXCLUDES `U` (above-ceiling at 6); a `sync::need_id` (167) for `O1` lands. (2) APPLY the grace extension (mobile `expires_at` → `T2`) so A honors the extended deadline. (3) Advance trusted_time ACROSS the ORIGINAL `T + M` (where a naive timer would have raised the ceiling to 7) but keep it BELOW `T2 + M`. (4) Run `SendRequestedFactHandler::handle` on the in-flight `O1` need-id, and then run a FRESH `SendSyncCompareResponseHandler` seed pass.
- **Expect:** The grace extension HOLDS the ceiling at 6 across the original `T + M` (CEIL-23: a producer that received the extension before the original deadline does not raise the ceiling while the extended blocker is still live). Therefore `U` stays above-ceiling / pending: the in-flight round ships ONLY `O1` (byte-identical via `require_sendable_fact`), and crucially the SUBSEQUENT fresh `response_plan_with_summaries` / `range_summary_for_connection` pass — recomputed against the grace-HELD ceiling 6 — STILL excludes `U` (its id is NOT entered into the new plan, NOT advertised in a `sync::have_id`). This is the OPPOSITE-direction discontinuity from SYNC-GAP22a: a naive timer would have raised the ceiling and smuggled `U` into the round; the grace extension must instead KEEP the ceiling down so a fact a timer would have activated is NOT smuggled in. `U` activates only after trusted_time later crosses `T2 + M` (or mobile is canaried). Negative control on monotonicity: a LATE extension arriving AFTER the original deadline (CEIL-24) cannot un-advance — but that is out of scope here; this test pins the SAFE-grace mid-round hold.
- **Defends:** VISIBILITY (1) and CEILING MONOTONICITY (3) under a grace-extension discontinuity that HOLDS (rather than raises) the ceiling mid-round; ADMISSION (a fact a naive timer would have activated is NOT smuggled into an in-flight round when a grace extension holds the ceiling); fills the Matrix C `sync × grace extension` cell (previously EMPTY) — the reverse-direction analog the smooth-expiry SYNC-GAP12a never exercised. Confirms `range_summary_for_connection` / shareable plan are recomputed against the grace-HELD ceiling between plan and send, not against a naive timer.
- **Refs:** `sync/send_compare_response.rs` `SendSyncCompareResponseHandler::handle` (`response_plan_with_summaries`, `range_summary_for_connection`, `expand_fact_ids_with_context_for_connection`); `sync/send_requested_fact.rs` `SendRequestedFactHandler::handle` (`require_sendable_fact`); `sync::need_id` 167 / `sync::compare` 165; `content::message_v2` intro 7 vs `content::message:1` 50; CEIL-23 / CEIL-24 / MAN-06 (grace extension moves `expires_at` LATER and holds the ceiling; monotonic union; late-extension cannot un-advance); SYNC-GAP12a (the smooth-expiry analog whose reasoning is re-proven here for a held, non-time-gated ceiling).
### CONTENT-GAP23a — activating file_slice_v2 (new BAO geometry) MUST NOT validate against a RETAINED v1 content::file parent's root_hash  `replay-cli`
- **Setup:** Node at a ceiling covering only the v1 content families. A v1 `content::file` (tag 54, `TYPE_CONTENT_FILE`) `F` is authored and projected: `CONTENT_FILES` row present, v1 geometry `blob_bytes`/`total_slices`/`slice_bytes`/`root_hash` set by `con send-file` at the v1 256 KiB slice geometry (`FILE_SLICE_PLAINTEXT_BYTES`). Its projector has published the standing `ContextOffer::range(fact.id, "content_file", scope, F.file_id, F.file_id)` (`content/file/project.rs:190-196`). The node then RECEIVES over sync an above-ceiling `file_slice_v2` fact `S` — a proposed new-tag sibling of `content::file_slice` (tag 55), intro_version = N+1, sibling `content/file_slice_v2/` dir, carrying the SAME `file_id` as `F` but a NEW BAO geometry: its `proof` slot was BAO-extracted against a v2-geometry encrypted root (e.g. 512 KiB plaintext slices, a re-sized `FILE_SLICE_BAO_PROOF_BYTES` slot) that does NOT equal `F.root_hash`. Per ADMISSION `S` is PENDING (pending opaque, unprojected, undisplayed, uncounted — NOT routed to a missing projector, NOT hitting `core/projectors.rs:456`). CRITICALLY, only the v1 `F` (tag 54) is retained for this `file_id`; no `file_v2` parent of the v2 geometry exists.
- **Action:** A fleet-wide signed manifest raises the ceiling so `file_slice_v2`'s tag is ceiling-active (its kept-forever v2 projector + sibling dir present and routed); trusted_time advances past `blocker.expires_at + M`. Wipe derived state and replay all retained facts via the per-tag historical adapter (`drain_pending_projection`). `S` now routes to `ContentFileSliceV2Projector` and is marked pending.
- **Expect:** `S` resolves its parent need and finds ONLY the v1 `F`. It MUST NOT count: it either (i) PARKS — because the v2 projector emits its parent need under its OWN geometry role (e.g. `content_file_v2`, not the shared `content_file` role at `content/file_slice/project.rs:68-74`), so the v1 `F`'s `content_file` offer never matches and there is no retained v2 parent to satisfy it (PROJ-17 park: `return Ok(ProjectionOutput::new().need(file_v2_need))`, no row, no offer, no error); OR (ii) if the v2 projector deliberately shares the `content_file` role and so decodes `F` (decode succeeds — `F` IS tag 54, `message_project::decode_typed_fact(..., file::TYPE_CONTENT_FILE, ...)` at `content/file_slice/project.rs:78-84` returns Ok), it MUST then REJECT at BAO verification: `verified_slice_ciphertext(&slice, &file)` calls `crypto::bao_verify_slice(&F.root_hash, S.proof.bytes(), slice_start, slice_len)` (`content/file_slice/project.rs:101,218-230`), and because `S.proof` was extracted against a v2 root != `F.root_hash`, verification returns Err ("file slice bao proof verification failed") — fail-closed, no `FILE_SLICES` row. In NEITHER case is a slice row materialized against the wrong-geometry parent. Replay completes (Invariant 4: no `Err` abort of the whole replay; a returned per-fact Err is surfaced for `S` alone or `S` parks). `con save-file` reconstructs `F` from v1 slices ONLY; `con files`/`con content-count` are unchanged by `S`; `con state-summary` counts `S` under retained-facts and parked/pending-or-rejected, never under `FILE_SLICES`.
- **Defends:** The unpinned boundary "a v2 slice cannot borrow a v1 parent's root_hash for verification" — the file-family analog of the version-knob rule applied to the BAO root. Content-integrity/safety: a slice whose ciphertext was proven against the v2 tree must NEVER be admitted by checking it against the v1 tree's root (cross-geometry proof acceptance = an unproven-ciphertext admission hole). Invariant 4 (replay deterministic, per-tag adapter, must not abort); Invariant 1 (visibility deferred/dropped, never half-projected against the wrong parent); CONTENT-14 (each tag-55 slice verifies its proof against the parent tag-54 root_hash) extended across the geometry boundary.
- **Refs:** `content/file_slice/project.rs:68-77` (`content_file` range need on `slice.file_id`), `:78-84` (`decode_typed_fact(parent, file::TYPE_CONTENT_FILE, ...)` — succeeds for the v1 parent), `:92-100` (`file_id`/signer/`slice_index < total_slices` equality checks the v1 parent passes), `:101,218-230` (`verified_slice_ciphertext` -> `crypto::bao_verify_slice(&file.root_hash, slice.proof.bytes(), ...)`); `content/file/project.rs:190-196` (`content_file` ContextOffer keyed by `file_id`); `content/file/layout.rs` `TYPE_CONTENT_FILE=54`, `root_hash`/`slice_bytes`/`blob_bytes`/`total_slices`; `content/file_slice/fact.rs` `FILE_SLICE_BAO_PROOF_BYTES`; `core/projectors.rs:456` unknown-tag Err (must NOT fire — `S` is routed), `:356` `purge_self`; sibling CONTENT-14, CONTENT-15, CONTENT-16, REPLAY-GAP11a.

### CONTENT-GAP23b — file_slice_v2 PARKS on its missing v2 parent rather than satisfying its need with the present v1 parent (own-geometry role isolation)  `projector-unit`
- **Setup:** Construct a projection fixture directly (no network). Retain a v1 `content::file` `F` (tag 54) projected with `root_hash = R1`, v1 geometry (`slice_bytes`=256 KiB, `total_slices`=K1, `blob_bytes`=B1), publishing the `content_file` range offer on `F.file_id` (`content/file/project.rs:190-196`). Also retain (NOT yet present) — i.e. deliberately do NOT retain — any v2 parent. Build a single `file_slice_v2` fact `S` for the SAME `file_id`, `slice_index=0`, with a `proof` slot extracted against a v2-geometry root `R2 != R1` (e.g. `crypto::bao_outboard`/`bao_extract_slice` over a 512 KiB-geometry encrypted blob). Ceiling already covers `file_slice_v2`; `ContentFileSliceV2Projector` is routed.
- **Action:** Invoke `ContentFileSliceV2Projector::project(S, context)` once with a `ProjectionContext` whose offers include `F`'s `content_file` offer (the v1 parent is in range for `file_id`). Then drive the fixpoint (`drain_pending_projection`) to quiescence with only `F` retained.
- **Expect:** `S` does NOT consume `F`. The correct v2 design emits its parent need under a geometry-distinct role (e.g. `content_file_v2`) so `F`'s `content_file` offer is NOT a match; `S` returns `Ok(ProjectionOutput::new().need(<v2 parent need>))` and PARKS (PROJ-17: no `FILE_SLICES` row, no `share_fact_with_sync` offer, no error). At fixpoint `S` is still parked (no retained fact provides the v2-role parent). Assert: no `RowMutation::InsertValues(content_file_slice_row(...))` is emitted for `S`; `S` emits at least one unmet need; `verified_slice_ciphertext` is NEVER reached for the (R1, S.proof) pair (so `crypto::bao_verify_slice` is not even invoked against R1). This pins the role-isolation half of the boundary: a v2 slice's parent dependency is keyed to its OWN geometry's parent fact, so a retained v1 parent can never silently satisfy it. (Contrast CONTENT-GAP23a clause (ii): if a v2 implementation instead reuses the `content_file` role, this test's role-isolation assertion fails and GAP23a's fail-closed BAO check is the only remaining defense — pinning that AT LEAST ONE of the two guards must hold.)
- **Defends:** Role/geometry isolation: the version knob applied to the parent-context need, not just the fact tag — a v2 slice must NEED a v2 parent, never borrow the v1 parent's offer. Prevents the silent cross-geometry match at the context layer before BAO verification is even consulted. Invariant 1 (deferred, never half-projected); Invariant 4 (deterministic park at fixpoint); CONTENT-16 (v1 slices keep their BAO meaning while v2 is isolated).
- **Refs:** `content/file_slice/project.rs:68-77` (the v1 `content_file` range need pattern the v2 projector must NOT reuse verbatim against a v1 offer), `:200-214` (`share_fact_with_sync` + `content_file_slice_row` materialize path that must NOT run), `:75-77` (park `return Ok(ProjectionOutput::new().need(file_need))`); `content/file/project.rs:190-196` (`content_file` offer); `core/context.rs:253` `ContextNeed::range` / `:309` `ContextOffer::range` (role-keyed matching); `core/projectors.rs:331` `ProjectionOutput::need`, `:489` `project_typed`; sibling CONTENT-GAP23a, CONTENT-16, REPLAY-GAP11a (orphan-slice park).

### CONTENT-GAP23c — symmetric guard: an activating v1 file_slice (tag 55) MUST NOT validate against a RETAINED file_v2 parent's new-geometry root  `replay-cli`
- **Setup:** The mirror of GAP23a, ceiling-active in the other direction. Ceiling now covers v2 file geometry: a `content::file_v2` parent `F2` (new tag, sibling `content/file_v2/`, intro_version = N+1) is retained and projected with a v2-geometry `root_hash = R2` (e.g. 512 KiB slices). A v1 `content::file_slice` fact `S1` (tag 55, `TYPE_CONTENT_FILE_SLICE=55`) for the SAME `file_id` is retained — its `proof` was extracted against a v1-geometry root `R1 != R2`. (Reachable via: a peer at the operational floor sent v1 slices for a file the local node holds at v2 geometry, or a v1 slice was pending-then-activated while only a v2 parent is retained for that `file_id`.) The v1 `ContentFileSliceProjector` is routed (it is kept forever); `F2`'s projector publishes ITS parent offer.
- **Action:** Wipe derived state and replay all retained facts via the per-tag adapter; `S1` (tag 55) routes to the kept-forever v1 `ContentFileSliceProjector` and is marked pending while `F2` (file_v2) is the only parent retained for `file_id`.
- **Expect:** `S1` MUST NOT count against `F2`. The v1 slice projector emits its `content_file` need (`content/file_slice/project.rs:68-74`) keyed to the v1 `content::file` role; because `F2` is a DIFFERENT tag publishing under its own `content_file_v2` role (geometry-distinct offer), `F2` does NOT match the v1 slice's `content_file` need and `S1` PARKS (`return Ok(ProjectionOutput::new().need(file_need))`, no row, no error). Should an implementation instead let `F2` satisfy the `content_file` role, the v1 slice's strict decode `decode_typed_fact(parent, file::TYPE_CONTENT_FILE=54, ...)` (`content/file_slice/project.rs:78-84`) MUST FAIL with "file slice parent context is not a content file" because `F2`'s first tag byte is the file_v2 tag (!= 54) — the `.map_err(|_| ...)` at :84 fires fail-closed; no BAO verification against `R2`, no `FILE_SLICES` row. Replay completes (Invariant 4). `con files` shows `F2` at v2 geometry; `S1` contributes no slice row; `con save-file` does not reconstruct a blob from a wrong-geometry parent.
- **Defends:** The boundary is symmetric — neither a v2 slice against a v1 parent (GAP23a/b) NOR a v1 slice against a v2 parent may share a root_hash across geometries. Pins that the strict `TYPE_CONTENT_FILE=54` tag check at `content/file_slice/project.rs:84` is load-bearing for safety, not just hygiene: it stops a v1 slice from BAO-verifying its v1-geometry proof against a v2-geometry root. Invariant 5 (v1 slice reader kept forever, meaning preserved, but only against its own-tag parent); Invariant 4; content-integrity (no cross-geometry proof acceptance in EITHER direction).
- **Refs:** `content/file_slice/project.rs:78-84` (strict `decode_typed_fact(..., file::TYPE_CONTENT_FILE, ...)` + `.map_err(|_| "file slice parent context is not a content file")`), `:68-74` (`content_file` need), `:101,218-230` (BAO verify against parent `root_hash` — must not run for `F2`); `content/file/layout.rs` `TYPE_CONTENT_FILE=54` vs proposed `content/file_v2/layout.rs` new tag; `content/file/project.rs:190-196` (per-geometry `content_file` offer role); `core/projectors.rs:456` unknown-tag Err (must NOT fire — both tags routed), `:489` `project_typed`; sibling CONTENT-GAP23a, CONTENT-GAP23b, CONTENT-13, CONTENT-17 (file_v2), CONTENT-34.
### AUTHZ-GAP24a — ceiling-crossing wipe+replay across a hypothetical v2 admin read-model derivation re-derives a BYTE-IDENTICAL admin row from the SAME retained tag-139 grant  `replay-cli`
- **Setup:** Single `con` node holding a retained delegated admin grant: workspace `auth::workspace` W (tag 131), root bootstrap `auth::admin` A1 (tag 139, `authority_fact_id == workspace_id`), target `auth::user` U (tag 14), and a delegated `auth::admin` A2 (tag 139, `authority_fact_id == A1.id`, `user_fact_id == U.id`, signed by A1) — all admitted while ceiling-active. The binary at HEAD additionally carries a HYPOTHETICAL v2 admin READ-MODEL DERIVATION at intro_version V+1 (a richer/restated way of computing the `admin_rows` row from the SAME tag-139 wire shape — input surface UNCHANGED, no new fact tag, `auth::admin` route still tag 139). The fleet ceiling is still V (a still-usable release blocks V+1). Capture the pre-crossing `admin_rows` row for A2 by decoding it via `decode_admin_row` (`auth/admin/rows.rs:38`): record key = `workspace_id||A2.id` (64 bytes, `admin_key` rows.rs:23) and the exact `ROW_VALUE_BYTES = 8+32*3 = 104` value (`created_at_ms||public_key||authority_fact_id||user_fact_id`, `auth/admin/layout.rs:18,83`). Record the surfaced actor set {A1 (root), A2 (delegated)}.
- **Action:** Advance trusted_time past the blocker's `expires_at + M`, recompute the ceiling so it crosses V+1 (activating the v2 admin read-model derivation), then wipe derived state and replay all retained facts to fixpoint (each fact via the historical adapter keyed by its OWN tag 139). Re-decode the post-crossing `admin_rows` row for A2 and re-enumerate the actor set.
- **Expect:** A2's `admin_rows` row is BYTE-IDENTICAL before and after the ceiling crossing — same 64-byte `admin_key` and same 104-byte `encode_row_value` output (`created_at_ms`, `public_key`, `authority_fact_id == A1.id`, `user_fact_id == U.id` all unchanged). The actor set is exactly {A1, A2} both before and after; no row is added, removed, recomputed, re-summed, or widened. The admin grant is AUTHORITY fixed by the retained fact's own bytes + resolved anchors (`project_delegated_admin`, `auth/admin/project.rs:116-165`), NOT a render-correctness derivation that re-applies the QUERY-GAP14a way. The v2 derivation crossing the ceiling does NOT change the surfaced authority.
- **Defends:** INVARIANT (2)+(4) for the AUTH scope + the no-new-authority rule + CEILING MONOTONICITY — an admin row is fact-fixed (authority), so a v2 read-model derivation activating at a higher ceiling must re-derive the identical row from the same tag-139 fact; it must NOT grant/revoke/widen authority by re-derivation the way a content render-fix re-applies. This is the AUTH-scope counterpart of the boundary QUERY-GAP14b pins for CONTENT.
- **Refs:** `auth/admin/project.rs:116-165` (`project_delegated_admin` — actor set from the fact's own bytes + `auth_workspace`/`auth_admin`/`auth_user` anchors), `auth/admin/rows.rs:23,30,38` (`admin_key`/`admin_row`/`decode_admin_row`), `auth/admin/layout.rs:18,83,92` (`ROW_VALUE_BYTES`, `encode_row_value`/`decode_row_value`), `auth/admin/fact.rs:17` (`AdminFact` fields), QUERY-GAP14a (render-fix re-applies — the contrast), AUTHZ-26 (same-version row uniformity).

### AUTHZ-GAP24b — BOUNDARY: on the SAME ceiling-crossing replay a CONTENT render-fix re-sums old facts, but the admin actor set/row is fact-fixed and does NOT re-derive  `replay-cli`
- **Setup:** One node retaining TWO independently-versioned changes in the same store: (1) OLD `content::message` facts (tag 50) subject to the V+3 `message_payload_bytes` render-correctness fix of QUERY-GAP14a (a DERIVATION over retained facts that re-SUMS them at the ceiling); and (2) the same delegated admin graph as AUTHZ-GAP24a (W, A1 root, U, A2 delegated; tag-139 grants) under the hypothetical V+1 v2 admin read-model derivation. The ceiling now crosses BOTH V+1 (v2 admin derivation) and V+3 (content render fix). Capture pre-replay: `con content-count WORKSPACE_ID_HEX` (the `message_payload_bytes:` line, `content/message/cli.rs:380,384`) AND the decoded A2 `admin_rows` row + actor set.
- **Action:** Wipe+replay canonical at the post-crossing ceiling, then re-run `con content-count WORKSPACE_ID_HEX` and re-decode A2's `admin_rows` row and the actor set.
- **Expect:** The two changes resolve on the SAME replay with OPPOSITE rules: (a) the CONTENT render-correctness derivation re-applies uniformly — `message_payload_bytes:` now reports the CORRECTED per-message sum for ALL retained tag-50 facts (their surfaced AGGREGATION is recomputed at the ceiling), exactly as QUERY-GAP14a/b; (b) the AUTH admin row is fact-fixed — A2's `admin_rows` row is byte-identical (same 64-byte key, same 104-byte value) and the actor set stays exactly {A1, A2}, NOT re-summed, NOT widened, NOT recomputed by the v2 derivation crossing V+1. A render-fix changes how retained CONTENT facts are SUMMED; an admin grant's surfaced authority is fixed by the retained tag-139 fact's bytes + anchors and crossing a v2-derivation ceiling does NOT change it.
- **Defends:** INVARIANT (2)+(4)+(5) — draws the explicit AUTH-vs-render boundary on a single replay: a content render derivation (aggregation of retained facts) re-applies at the new ceiling, while an admin authority row is established by the fact itself and re-derives identically. Closes the boundary that QUERY-GAP14b pins for CONTENT but leaves unpinned for the safety-critical AUTH/authority scope.
- **Refs:** `content/message/queries.rs:59,71` (`count_for_workspace`/`message_payload_bytes` re-sum); `content/message/cli.rs:380,384` (`content_count_output`); `auth/admin/project.rs:116-165` (`project_delegated_admin`); `auth/admin/rows.rs:30,38` (`admin_row`/`decode_admin_row`); `auth/admin/layout.rs:83` (`encode_row_value`); QUERY-GAP14b (the CONTENT side of this boundary); inventory §VERSIONING KNOB / §RENDERING UNIFORMITY.

### AUTHZ-GAP24c — admin actor set is ceiling-INDEPENDENT: the SAME retained tag-139 log yields the identical actor set at ceiling V and at ceiling V+1, granting NO new authority by re-derivation  `replay-cli`
- **Setup:** A single retained authority log of ONLY the admin graph (W tag 131, A1 root tag 139, U tag 14, A2 delegated tag 139) — no other facts. The binary at HEAD carries BOTH the V baseline admin read-model and the hypothetical V+1 v2 admin read-model derivation (same input surface, same tag 139, no new fact, no new CLI param). Two wipe+replay passes over the EXACT SAME log: ceiling pinned at V, then ceiling pinned at V+1.
- **Action:** Wipe+replay the log at ceiling V; decode A2's `admin_rows` row and enumerate the actor set -> S_V. Wipe+replay the identical log at ceiling V+1; decode A2's row and enumerate -> S_{V+1}.
- **Expect:** S_V == S_{V+1} exactly: both surface actor set {A1, A2}, and A2's `admin_rows` row is byte-identical (same 64-byte key, same 104-byte value) across both passes. The surfaced authority is driven SOLELY by the retained tag-139 facts and their resolved anchors, NOT by which read-model derivation is ceiling-active. This is the OPPOSITE of QUERY-GAP14c: a CONTENT render derivation is correctly ceiling-driven (old value at V+2, corrected at V+3 over the same log), but an AUTH actor set is ceiling-INDEPENDENT — the v2 admin derivation crossing the ceiling must NOT introduce, revoke, or widen any authority. Granting/revoking authority happens ONLY by a new authority FACT (a new tag-139 grant), never by activating a richer derivation of existing grants.
- **Defends:** the no-new-authority-by-derivation rule + CEILING MONOTONICITY + INVARIANT (4) — pins that the AUTH actor set is fact-fixed and ceiling-independent (unlike the ceiling-driven CONTENT render derivation of QUERY-GAP14c); a v2 admin read-model derivation must never silently change the surfaced actor set on replay, which would forge/revoke authority by re-derivation rather than by a new authority fact.
- **Refs:** `auth/admin/project.rs:77-82` (bootstrap-vs-delegated discriminator), `:85-114` (`project_bootstrap_admin`), `:116-165` (`project_delegated_admin`); `auth/admin/rows.rs:23,38` (`admin_key`/`decode_admin_row`); `auth/admin/layout.rs:18` (`ROW_VALUE_BYTES`); QUERY-GAP14c (the ceiling-DRIVEN content render derivation — the deliberate contrast); AUTHZ-03 (authority changes only by a new fact activating, not by re-derivation).

---

## 20. Coverage matrix (cross-product)

### Coverage Matrix — Adversarial Completeness Pass Round 2

Built over **version{new,old,transition,mixed} × surface{create,cli,query,projector,sync,connection,replay,manifest} × scope{content,auth,connection,sync,cross}** for the poc-10 protocol-versioning test sections (`00-inventory.md`, `01..18-*.md`) PLUS the round-1 gap files (`95-gap-r1-00..11.md`, each carrying 3 sub-gaps a/b/c against the 11 round-1 prose items).

Cell legend:
- Test IDs (e.g. `CREATE-02`, `E2EX-10`, `KEYS-GAP10a`) are the existing/round-1 tests covering that intersection.
- `—` = intersection not meaningfully applicable (e.g. a "manifest" surface in the "connection" scope is the carrier-gate, covered under connection).
- **THIN** = covered by < 2 tests or only at a high-altitude/property level.
- **GAP** = no test covers it; flagged in prose + structured output.

The single-axis cells are saturated after round 1. The remaining weaknesses are in **multi-fact / multi-version / multi-node interaction cells** and in a handful of **fingerprint / index-layer / wire-detail** cells that the cluster sections asserted at too coarse a grain. Those are hunted in the prose + structured output.

---

## Matrix A — version × surface (scope-agnostic roll-up; round-1 GAP rows folded in)

| surface \ version | new (capable, below ceiling) | old (non-capable, still-usable) | transition (ceiling rises mid-life) | mixed (v1+v2 coexisting) |
|---|---|---|---|---|
| **create** | CREATE-02/03, CONTENT-02/10/17/24, E2EX-04, E2E-20 | CREATE-13, E2E-07/08/09, CONTENT-01 | CEIL-15, E2EX-09, CONTENT-07, E2E-26, CEIL-GAP18a/b/c | CREATE-01, REPLAY-02, CONTENT-04 |
| **cli** | CLI-02/04/09/11/26, ROUTE-19, AUTHZ-18 | CLI-01/14/21/28, AUTHZ-19 | CLI-03/15, QUERY-06/22, E2EX-28 | CLI-05/30, ROUTE-20, CONTENT-08 |
| **query** | QUERY-05/07/08/20, CONTENT-33 | QUERY-01/03/14/19, E2E-18 | QUERY-06/16, E2E-22, QUERY-GAP14a/b/c | QUERY-23, SYNC-13/26, E2EX-01, **THIN: sync_status fingerprint folds context_have** |
| **projector** | ROUTE-05/12/25, PROJ-26, AUTHZ-02 | PROJ-01/02/03/05/28, CONTENT-01 | ROUTE-08/13, PROJ-27, E2EX-27 | ROUTE-10/11, PROJ-15, REPLAY-02 |
| **sync** | SYNC-09/29, ROUTE-26/28, E2E-11 | SYNC-12/16/18, E2E-13 | SYNC-11, ROUTE-27, SYNC-GAP12a/b/c | SYNC-05/06/07/13/14/25, E2E-10/12, E2E-GAP15a/b/c |
| **connection** | CONN-09/23, E2EX-26, ROUTE-24 | CONN-03/04/05/06/24, E2E-30 | CONN-17/28, E2EX-30, SYNC-GAP12b, GUARD-GAP111b | CONN-01/02/11, FRAME-19 |
| **replay** | ROUTE-08/09, REPLAY-07/08, E2EX-10 | PROJ-15, REPLAY-26, AUTHZ-10 | REPLAY-08, MAN-27, AUTHZ-03, KEYS-04, REPLAY-GAP11a/b, MAN-GAP19a/b/c | REPLAY-02/04/05/17/32, SYNC-21, REPLAY-GAP13a/b/c |
| **manifest** | MAN-09/13, CEIL-09/14, GUARD-05..08 | MAN-08/21, CEIL-25 | MAN-06/11/12/16, CEIL-04/07/12/23/24 | MAN-04/19/23/32, GUARD-30 |

## Matrix B — surface × scope (version-agnostic roll-up)

| surface \ scope | content | auth | connection | sync | cross (multi-scope) |
|---|---|---|---|---|---|
| **create** | CREATE-01..12, CONTENT-* | CREATE-13..21, AUTHZ-* | CREATE-22..25, CONN-* | CREATE-26..32 | CREATE-33/34/35, GUARD-09, CEIL-GAP18* |
| **cli** | CLI-01..14/19..21/27..30 | CLI-15..18, AUTHZ-18/19 | CONN-03/19 | CLI-25, SYNC-25 | CLI-22/23/24, GUARD-24 |
| **query** | QUERY-01..19/23/27 | QUERY-20, AUTHZ-26 | QUERY-26 | QUERY-25, SYNC-26 | QUERY-03/24/25, GUARD-11, QUERY-GAP14* |
| **projector** | PROJ-01/04/12/23/28..30, CONTENT-* | PROJ-02/03/07..10/17..21, AUTHZ-* | PROJ-06, FRAME-*, CONN-13 | PROJ-05, SYNC-01/02/15 | PROJ-13/14/22/24/25, GUARD-17 |
| **sync** | SYNC-03..14/29, CONTENT-34 | SYNC-04(local), KEYS-37/38 | SYNC-08/12, CONN-* | SYNC-01..31, SYNC-GAP12* | SYNC-05/07/25, E2E-10/13, E2E-GAP15* |
| **connection** | FRAME-19/20/22, CONN-10/11 | FRAME-22 | CONN-01..28, FRAME-01..33 | CONN-01/02/24, SYNC-08 | FRAME-22, CONN-12, GUARD-GAP111* |
| **replay** | CONTENT-01/04, REPLAY-17, REPLAY-GAP11a, CONTENT-GAP17* | KEYS-05/14/15/31, AUTHZ-03/10/27, AUTHZ-GAP16*, REPLAY-GAP11b | CONN-20/28, FRAME-33, REPLAY-23/24, GUARD-GAP111b | SYNC-11/21/22, REPLAY-25/30 | REPLAY-32, MAN-23, AUTHZ-27, MAN-GAP19*, REPLAY-GAP13* |
| **manifest** | GUARD-06, MAN-22/23 | GUARD-05, MAN-21 | GUARD-07, MAN-28, CONN-15..17 | GUARD-08 | MAN-01..04/19/20/32, CEIL-*, TIME-08..13, TIME-GAP110* |

## Matrix C — version{transition,mixed} × scope (the high-risk slice; round-1 closures noted)

| scope \ transition trigger | blocker expiry (+M) | security-deprecation canary | grace extension | blocked-mode entry/exit | key/secret lifecycle during transition | multi-node ≥3 ceilings |
|---|---|---|---|---|---|---|
| content | CEIL-15, E2EX-09/10, CONTENT-04/07, CONTENT-GAP17a/c | CEIL-12, MAN-13/16 | CEIL-23/24, MAN-06 | TIME-20..22, CONTENT-33, QUERY-GAP14* | — | E2E-GAP15a/b/c |
| auth | AUTHZ-03, E2E-26, AUTHZ-GAP16a/b/c | AUTHZ-16, MAN-21..23 | **THIN** | AUTHZ-28, TIME-23, REPLAY-GAP13* | AUTHZ-GAP16* (anchor purge), KEYS-GAP10* | **THIN** (E2E-GAP15 is content) |
| connection | CONN-17/28, E2EX-30, SYNC-GAP12b | CONN-15 | CONN-16 | CONN-18, GUARD-GAP111a/b/c | CONN-19/21 | — |
| sync | SYNC-11, ROUTE-27, SYNC-GAP12a/b/c | **GAP — canary mid-sync recompute of summary** | **GAP — grace ext × in-flight compare** | TIME-24, SYNC-22 | — | E2E-GAP15a/b/c |
| cross | MAN-11/27, CEIL-19..22, MAN-GAP19* | CEIL-22, MAN-16 | CEIL-23/24 | TIME-28/29, MAN-31, REPLAY-GAP13* | KEYS-GAP10* | E2E-GAP15* |

---

## Thin / missing cells (prose)

Round 1 closed the 11 big interaction items (key×ceiling, pending-dep-purge, ceiling-rises-mid-sync, blocked×deterministic-replay, three-ceiling relay, anchor-purge×activation, retention×mixed-version, two-conjunct carrier skew, own-expiry×activation, frame_observation time-backdoor, close×blocked/replay). Round-2 re-reading found the following NEW thin/missing cells — all are wire-detail or fingerprint-grain interactions the cluster sections asserted at too coarse a level, plus two transition×sync cells Matrix C still shows empty:

1. **`sync_status` root_fingerprint folds `context_have`, not just `(timestamp,id)` (sync/query, mixed)** — GENUINE GAP. `summarize_range` (compare/create.rs:245) folds only `(timestamp, fact.id)` — version-independent, as SYNC-13/SYNC-26 claim. But the PERSISTED leaf `contribution_fingerprint` (shared_fact/rows.rs:509) folds `(workspace_id, owner_fact_id, timestamp_ms, context_have[])`, and `sync_status` (rows.rs:821-835) XORs those leaf fingerprints into `root_fingerprint`. So `con sync-status` `root_fingerprint` is NOT version/closure-independent when two converged nodes recorded DIFFERENT `context_have` sets for the same owner (e.g. a node that decoded a v2 owner and advertised its v1 anchor vs a node where the owner's anchor was absent/pending when its projector ran). SYNC-26 explicitly asserts equality "fingerprint = XOR over (timestamp,id); version-independent" — that is true for the on-wire compare summary but FALSE for the persisted sync-status root. Untested seam between the two fingerprint algorithms.

2. **Accumulated `context_have` keeps a purged anchor id in the leaf fingerprint forever (sync, mixed+transition)** — GENUINE GAP. `upsert_sync_contribution` (rows.rs:280-285) reads the existing leaf's context_have and EXTENDS (sort+dedup) — it never shrinks. So once an owner's projector advertised a context anchor, that anchor id stays in the contribution fingerprint even after the anchor fact is purged/retired/tombstoned. Two nodes that hold the same owner+same ids but learned the owner on opposite sides of an anchor purge compute different `root_fingerprint`s, and a single node's `root_fingerprint` does not change when the anchor is later purged (the index does not re-derive context_have downward). No test pins the monotone-accumulate-never-shrink behavior of context_have against the purge/retention path.

3. **`grant-admin` v1→v2 wire bump while the input surface is unchanged: the v2 admin row must NOT silently change the rendered actor set (auth, mixed)** — THIN. AUTHZ-18/19 cover ceiling-selecting the v1 vs v2 grant-admin run-fn and absent-bucket reuse, and AUTHZ-26 covers same-version row uniformity. But no test pins that when ceiling crosses the v2 admin intro and a wipe+replay re-derives rows, the SAME retained tag-139 grant produces a byte-identical admin row under the v2 read-model derivation (i.e. an admin grant is authority, not a render-correctness derivation — it must NOT be re-summed/recomputed the way QUERY-GAP14 re-applies a render fix). The boundary between "authority row is fixed by the fact" and "render derivation re-applies" is pinned for content (QUERY-GAP14b) but never for the AUTH scope.

4. **Grace-extension × in-flight sync compare, and security-deprecation canary × in-flight sync (sync, transition)** — GAP (Matrix C still shows empty). SYNC-GAP12a/b/c cover a ceiling RISE via blocker-EXPIRY mid-round. But neither a grace EXTENSION (CEIL-23/24: blocker.expires_at moved LATER, holding the ceiling) nor a security-deprecation canary (CEIL-12/MAN-13: blocker dropped EARLY, ceiling jumps UP without waiting for +M) has a sync-layer analog. When a canary fires mid-compare-round, the still-usable set recomputes instantly and the shareable index / negentropy summary must be recomputed against the new ceiling between the compare plan and the requested-fact send — distinct from the gradual-expiry SYNC-GAP12a because the jump is discontinuous and not gated by M. No test asserts the in-flight `sync::compare` child plan is re-derived (not stranded) when the trigger is a canary or a grace extension rather than a timed expiry.

5. **file_slice_v2 with a NEW BAO geometry: a v1 slice and a pending v2 slice for the SAME file_id both reference one v1 `content::file` parent root_hash (content, mixed)** — THIN→GAP. CONTENT-15/16 and REPLAY-GAP11a cover v2-slice pending and the purged-parent park. But the BAO-proof-against-parent-root mechanism (CONTENT-14: each tag-55 slice verifies its proof against the parent tag-54 `root_hash`) is not crossed with a v2 slice whose larger plaintext geometry implies a DIFFERENT root_hash/tree shape for the SAME `file_id`. On activation the v2 slice projector must verify against a v2-geometry root — but the retained parent is a v1 `content::file` with a v1 root_hash. Either the v2 file descriptor must also be present (a v2 parent), or the v2 slice parks; no test pins that a v2 slice cannot validate against a v1 parent's root_hash (a cross-geometry proof must FAIL or PARK, never count). Safety-adjacent (a forged-geometry slice must not be admitted against the wrong parent).

6. **Two same-version releases whose presentation chrome differs at the BYTE level vs the QUERY-09/10 value-vs-formatting classifier (query, new)** — THIN. QUERY-09/10 split value-changing fixes (gated) from formatting-only fixes (free). But the classifier itself is never exercised against a change that touches a value-bearing substring AND chrome in one diff (e.g. `format_bytes` changing both the unit string "B"→"KiB" AND rounding the number). The mixed diff must be classified value-changing (gated) — the conservative side. No test pins the classifier's behavior on a mixed formatting+value diff; a too-lenient classifier would let a value change ship as "formatting-only" without a protocol bump, breaking RENDERING UNIFORMITY across releases at the same ceiling.

7. **Empty/degenerate `context_have` and self-referential context_have in the share contribution (sync, mixed)** — THIN. SYNC-05/06 cover a v2 owner with one v1 anchor and a v1 owner with one v1 anchor. No test covers an owner whose advertised `context_have` includes ITS OWN id, or duplicate/unsorted ids, against the `input.context_have.sort(); .dedup()` normalization in `share_fact_with_sync_intent` (share_fact_with_sync.rs:55-56) — the dedup/sort is what makes the fingerprint order-independent, and a self-referential or duplicated anchor must normalize to a stable fingerprint. Property-grain coverage missing (SYNC-31 covers range/summary order-independence but not context_have normalization).

The remaining single-axis cells and the round-1 interaction items are well-covered. The genuine NEW gaps below (structured output) are items 1, 2, 4, 5, and one combined item for the authority-render boundary (#3). Items 6 and 7 are noted as THIN but lower-severity (single-node, classifier/normalization detail) and folded into the GUARD/SYNC structured entries where they sharpen an existing gap.

---

## 21. Handler-unit triage

A handler is impure (reads store state via `HandlerContext`, performs an effect),
so a mocked `handler-unit` test can prove a fake invariant by fabricating state.
All 106 `handler-unit`-tagged tests are triaged below into trusted forms. The
finding: **~half were mis-tagged pure tests already in the trusted classes, the
rest resolve to black-box, and none survive as mocked handler tests.** After this
triage every behavioral test is pure-unit, black-box, multinode, or
fault-injection; only the structural `guardrail` cluster sits outside the
proof-of-record set.

**P — mis-tagged pure → re-tag `projector-unit`/`pure-unit` (trusted). 52 tests.**
Assertion is on a pure function — a constructor (`create::*`), authenticator
(`authenticate_*`), layout decoder, frame classifier (`is_bootstrap_*`,
`classify_frame`), batcher (`fact_batches`, `require_sendable_fact`), version
resolver, or projector — with no store state and no effect. Trusted **provided
input facts are built via the real owning-module encoder, never byte literals.**
IDs: MAN-28, MAN-33, CREATE-17, CREATE-30, CREATE-33, CLI-02, CLI-03, CLI-04,
CLI-15, CLI-26, QUERY-22, PROJ-24, PROJ-25, CONN-06, CONN-07, CONN-08, CONN-09,
CONN-10, CONN-11, CONN-25, CONN-26, CONN-27, FRAME-09, FRAME-13, FRAME-14,
FRAME-19, FRAME-20, FRAME-21, FRAME-22, SYNC-14, SYNC-19, SYNC-29, CONTENT-03,
CONTENT-11, CONTENT-16, CONTENT-19, CONTENT-25, CONTENT-29, AUTHZ-05, AUTHZ-06,
AUTHZ-07, AUTHZ-09, AUTHZ-21, AUTHZ-25, AUTHZ-29, KEYS-03, KEYS-08, KEYS-09,
KEYS-12, KEYS-13, KEYS-40, E2EX-17.

**A — stateful-deterministic → black-box `con` + observe fact/row + `replay-check`. 25 tests.**
Handler reads real store state and emits a deterministic fact/row; drive it with
a real command and observe the result (and the `state-summary` hash); prove
idempotence/order-independence via `replay-check`. Includes the `require_fact`
"never fabricate" backstops (observe the absence of the fact).
IDs: CREATE-19, CREATE-27, CREATE-29, CREATE-31, REPLAY-10, REPLAY-11, REPLAY-12,
REPLAY-13, REPLAY-14, REPLAY-15, REPLAY-16, REPLAY-25, SYNC-03, SYNC-04, SYNC-05,
SYNC-06, SYNC-17, SYNC-20, SYNC-30, KEYS-06, KEYS-07, KEYS-10, KEYS-11,
KEYS-GAP10b, FRAME-12.

**BX-M — manifest / ceiling mechanism → black-box vs the manifest/ceiling-observability CLI. 14 tests.**
(Subtype of A.) Ingest a signed manifest/canary fact via `con`, then dump the
computed ceiling or attempt `con send` and observe. The signature-verify and
monotonic-union cores are additionally pure-unit.
IDs: MAN-01, MAN-02, MAN-03, MAN-04, MAN-05, MAN-06, MAN-11, MAN-14, MAN-15,
MAN-16, MAN-24, MAN-25, MAN-26, E2EX-08.

**B — effectful (send/receive) → multinode black-box + fact-committed-before-effect. 9 tests.**
The effect is a network send/receive; prove the observable consequence across ≥2
real `con` nodes, and that any nondeterministic choice is committed as a fact
before reliance.
IDs: CREATE-28, CREATE-32, CONN-23, SYNC-07, SYNC-16, SYNC-18, SYNC-23, SYNC-24,
E2E-GAP15b.

**C — atomicity / ordering / blocked-mode → black-box fault injection. 6 tests.**
Commit-before-send, blocked-mode-during-replay, connection-retirement-before-
replay. Prove by crash/restart + observing recovery via replay, or via the
blocked-mode CLI path — never a mocked ordering assertion.
IDs: CONN-05, E2EX-23, E2EX-30, REPLAY-GAP13a, REPLAY-GAP13b, REPLAY-GAP13c.

### Handlers flagged to shed logic

None require significant shedding. The triage confirms the algorithms already
live in pure modules — `create::*` constructors, `compare::create::response_plan`,
`fact_batches` / `frame_policy`, and the projectors — while handlers do
`require_fact` → call-pure-fn → return facts/intents. The two
orchestration-heaviest are `SendSyncCompareResponseHandler` (closure expansion is
already factored into `compare::create::response_plan` /
`expand_fact_ids_with_context_for_connection`) and `ShareFactWithSyncHandler`
(contribution/fingerprint logic already in row helpers). Add a `GUARD` test that
fails if a handler grows beyond require/call/return so this stays true.

### Trust accounting after triage

With P re-tagged to the pure classes and A/B/C/BX-M expressed black-box, all 106
move into the proof-of-record set. Combined with the 355 already-trusted tests,
that leaves only the structural `guardrail` cluster (125) and a few `property`
tests outside proof-of-record — and `guardrail` is trusted in its own right (it
asserts on source/registry shape, which cannot be faked by fabricated state).

Purge-completeness and forward secrecy — earlier flagged as artifact-only — are
also black-box via the `purge-audit <id>` command (Plan §2, Phase 1b): create →
purge → assert the id and every derived row/index/blob is gone. Forward secrecy
adds "no surviving `key_wrap`/path-node targets the retired coordinate," also
presence-checkable. The only artifact-property residue left outside black-box is
crypto-primitive soundness, which is out of scope (trusted to the AEAD/DH
primitive). Atomicity/ordering invariants are stated in Plan §2 ("Atomicity and
crash-consistency") and proven by the `C`-bucket fault-injection tests.
