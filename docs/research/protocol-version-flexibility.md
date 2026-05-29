# Protocol Version Flexibility Design

This note records the poc-10 protocol evolution design. The current runtime
uses immutable canonical fact bytes, deterministic fact ids, fixed wire layouts,
scope-owned codecs, and connection frames with a public `TRNS` tag plus version
byte. Version flexibility should preserve those properties instead of turning
core into a compatibility layer.

The product use case is version diversity inside one product, not broad
interoperability between independent projects. Users can delay upgrades,
platform releases can be staggered, approval processes can hold back one
platform, and a broken release can strand some users. poc-10 can deprecate
sufficiently old clients, but until that deprecation boundary is crossed the
protocol should preserve a workspace-wide visibility invariant: anything a user
does in a workspace must become visible to everyone in that workspace.

That invariant turns new features into explicit compatibility decisions. A new
content type is safe only if it either degrades gracefully to an older content
type or is unavailable for creation until all active, or visibly relevant,
clients in the workspace have upgraded. Otherwise a user can create state that
some teammates cannot see, which is a protocol failure rather than a UI gap.

## Local Reference

- `docs/research/references/cambria-ink-switch.html` is a downloaded copy of
  the Ink & Switch Cambria essay from `https://www.inkandswitch.com/cambria/`.
- `docs/research/references/cambria-ink-switch.pdf` is a local PDF rendering of
  the same page. The public page did not expose a first-party PDF download, so
  this file preserves the readable paper format for offline review.
- Academic citation: Geoffrey Litt, Peter van Hardenberg, and Orion Henry.
  "Cambria: Schema Evolution in Distributed Systems with Edit Lenses." PaPoC
  2021. DOI: `https://doi.org/10.1145/3447865.3457963`.

Cambria's useful lesson for poc-10 is not to lens arbitrary core bytes. The
useful lesson is to isolate translation at the data-shape boundary, keep a
single source of truth for each evolution edge, and avoid scattered "if old
version" parsing inside semantic code. For poc-10 that boundary is the owning
fact or frame layout module.

## Minimal Design

The minimal design is for one product with a bounded support window for old
clients. Each feature or scope has one canonical production write protocol.
Older fact versions keep version-addressed read/replay adapters, and old
clients may write old facts only during their support window. After
deprecation, old write protocols are disabled, but old read/replay adapters
remain as long as retained facts require them.

The operating goal is simple: a production user must not be able to create
workspace-visible state that any non-deprecated relevant client cannot see.
This supports large internal changes such as TreeKEM, file encoding changes,
disappearing-message policy changes, indexing/query rewrites, and fact or
intent reshaping without breaking supported users.

Rules:

- **Gate production writes for multi-client-visible features.** A feature that
  affects multiple clients may ship with read support and write implementation
  in the same release, but production write UI and command creation stay behind
  a runtime gate. Write paths may exist in alpha, dogfood, integration tests,
  and fixtures. The production gate opens automatically when the feature's
  unsupported client versions are deprecated or expired, or earlier if there is
  a true legacy-visible fallback.
- **Replay derived state on upgrade.** Every non-ephemeral fact is a durable
  input to deterministic projection. On upgrade, derived tables, indexes,
  materialized rows, query caches, and compatibility rows may be discarded and
  rebuilt by replaying durable facts through the current projector registry.
- **Keep old signed facts.** Author-signed facts remain the provenance source
  until purged by workspace retention policy. Admin or workspace authorities
  must not convert them into new facts that appear signed by the original
  author. Policy facts may change interpretation, retention, or purge decisions,
  but not authorship.
- **Keep replay inputs complete.** Durable facts, durable local facts, or
  explicit replay needs must represent every input needed to rebuild state or
  schedule durable work. Local secrets, device keys, pending durable intents,
  user-visible download progress, correctness-affecting daemon checkpoints, and
  feature-relevant platform observations must survive until purge or expiry.
- **Treat transport state as ephemeral.** Socket state, live sessions,
  in-flight connection handshakes, and similar process state can be dropped on
  upgrade and rebuilt by reconnecting from durable facts and queues.
- **Preserve version-addressed meaning.** Old-format facts can be replayed by
  new implementations of old-version adapters, and those adapters may emit
  current rows. Adapter selection remains version-addressed, and adapters
  preserve the old fact's semantic contract unless an explicit policy/version
  fact or `effective_from` boundary changes interpretation.
- **Make purge fact-driven.** Retention and purge rules vary by workspace.
  Durable facts are purged only when the data they describe is also purged by
  policy. Purge, retention, deletion, and disappearance decisions must be
  expressed as facts before target facts or payloads disappear, so replay cannot
  resurrect data that policy says is gone.
- **Make durable follow-up work idempotent.** Replay projectors may declare
  missing durable work, but must not execute it directly. For example,
  replacement key-wrap coverage is derived as a durable need and fulfilled by
  normal runtime handlers using deterministic coverage keys. If required
  material was purged or is unavailable, replay leaves an unsatisfied need
  rather than fabricating coverage.

The minimal default is global compatibility epochs plus production write gates
and replay-on-upgrade. Per-feature deprecation horizons are useful if a single
epoch becomes too blunt. Legacy-visible fallback facts are allowed only when the
fallback preserves the user's visible intent. Expand/contract storage migration
is a fallback for state that is not purely fact-derived or is too expensive to
replay on every upgrade.

Operationally, deprecation should be data, not a manual UI flag. Each feature
declares the minimum reader epoch or version required for production writes.
The runtime compares that requirement to product deprecation policy and local
observed client capabilities, then returns a create-gate reason such as
`waiting_for_deprecation`, `ready`, `ready_with_legacy_fallback`, or
`blocked_by_policy`. If the product goes a long time without a release, gates do
not open merely because time passed; they open when the unsupported version is
actually expired or when the feature has a safe fallback. Long release pauses
therefore delay new production writes, but they should not break existing reads,
replay, or local migrations.

## One-Client-Family Compatibility Design

This is the useful richer design for poc-10. One app provider signs every
client release that participates in the privacy contract. Desktop, mobile,
daemon, and test clients may run different provider-signed releases; arbitrary
forks and third-party clients are outside the contract unless the provider signs
their manifest. The point is rapid feature deployment without letting a durable
action disappear on older non-deprecated clients.

### Release Registry

The provider publishes a signed releases-registry fact. Each entry contains:

- `release_id`, `manifest_hash`, `status`, `not_before`, and `deprecated_after`
- per scope/fact family: `fallback_fact_version`, `canonical_fact_version`,
  optional view versions, lens ids, and replay adapter ids
- sync and ephemeral support: bootstrap envelope, protocol versions, and minimum
  accepted version

Each endpoint publishes a signed capability fact:
`endpoint_id`, user/device id, `release_id`, `manifest_hash`, platform,
capability epoch, and expiry. A capability fact counts only if its release entry
is provider-signed and not deprecated. Unknown, forked, or exotic version claims
do not create write obligations.

Each feature adds a manifest entry: `feature_id`, scope, visibility domain
(`local_user`, `device_set`, `dm_participants`, `channel_members`,
`workspace`), canonical fact, fallback fact, canonical-to-fallback lens,
fallback placement rule, optional view lenses, and compatibility class.

### Durable Facts

Every durable shared fact family must define a permanent fallback format when it
is introduced. The fallback is the validation anchor until the fact family is
purged or retired. For a calendar event, the fallback might be a status fact:
`actor=A, verb=created_calendar_event, title=Team sync, time=Friday 10am`. For a
new private space, the fallback might be only `actor=A, verb=created_space` in
an authorized parent scope.

For every open-ended durable write, the handler emits one representation set:

- `set_cert`: author signature over set public key, command id, author, scope,
  audience, feature id, and release-registry id
- `fallback_fact`: signed by the author or set key
- `canonical_fact`: signed by the author or set key; commits to `fallback_id`
  and `canonical_to_fallback_lens`
- optional view facts for non-deprecated releases when they improve old-client
  UX; each commits to `fallback_id` and the lens used

Projectors accept the canonical fact only after these checks pass: registry id
is accepted, set certificate verifies, fallback fact is admitted, scope and
audience match the fallback placement rule, and lensing canonical to fallback
reproduces `fallback_id`. Readers display the newest verified sibling they
understand and suppress lower-fidelity rows only after these checks pass.

If no fallback can preserve visibility without leaking across access boundaries,
the feature uses the minimal gate/deprecation path. A private channel fallback
cannot go to the whole workspace unless the workspace is allowed to know that
the channel exists; otherwise use an equal-audience scope or per-member facts.

### Optional Multi-Version Views

Intermediate view facts are UX siblings, not validation anchors. They may be
emitted at write time or later in response to a signed capability/request fact,
like key-wrap requests. Only the author or certified set key can answer because
the sibling must be signed into the representation set. If the author is gone,
missing intermediate views are not a correctness failure; fallback plus
canonical remains valid.

Using mandatory multi-version publishing as the source of truth requires a
hash-linked frontier DAG:

```text
Capability frontier:

F0: active [fallback], deprecated []             (feature introduced)
 |
 v
F1: active [fallback, v2], prior F0              (v2 released)
 |
 v
F2: active [fallback, v3], deprecated [v2], F1   (v3 released, v2 expires)

Representation set for command C:

C@fallback  <----depends-on----  C@v2  <----depends-on----  C@v3
   |                              |                          |
 frontier F0                   frontier F1                frontier F2
```

That is too close to a consensus problem for the one-client-family baseline:
late endpoints can reveal capability facts the writer did not know about, old
authors may be unavailable to sign missing siblings, and the system must decide
which frontier applied to each command. The permanent fallback avoids that by
making one durable compatibility anchor exist from the beginning.

### Planner Contract

Command constructors and intent handlers call:

```text
plan_compat(feature_id, visibility_domain, audience, durability, now)
```

Inputs are the feature manifest, releases registry, endpoint capability facts,
and deprecation policy. Output is one of:

- `DurableOpen`: emit fallback, canonical, and listed optional views
- `DurableClosed`: emit fallback plus the highest common view for the current
  participant/device set, unless the feature marks future replay unnecessary
- `Ephemeral`: use bootstrap until capabilities authenticate, then highest
  common ephemeral format
- `Blocked`: no fallback, unauthorized fallback placement, missing capability,
  stale endpoint fact, or deprecated release

Core can compute the highest common version from participant/device ids,
endpoint capability facts, the registry, and deprecation policy. Scope modules
own version semantics and lenses; core only computes the intersection. Handlers
record the planner output hash or manifest ids in `set_cert`.

### Sync And Ephemeral Traffic

Sync, connection bootstrap, and 1:1 ephemeral traffic have exactly two
participants for one session. Use this fixed flow:

1. Start with the invite's bootstrap sync-control version, clamped to the local
   non-deprecated floor.
2. Authenticate the peer and exchange endpoint capability facts.
3. Verify both releases against the provider registry.
4. Select the highest mutually supported session protocol not below either
   minimum accepted version.
5. Bind both capability facts and the selected protocol into the session
   transcript.

The selected sync version controls only the session algorithm and envelopes. It
does not reinterpret durable fact semantics. A newer sync version may batch set
siblings, but it still transfers the same canonical fact bytes and checks access
control per sibling fact and scope.

### Recommended Baseline

- Provider-signed release registry plus endpoint capability facts.
- Durable shared writes publish fallback plus canonical, with optional UX views.
- Canonical facts validate by lensing back to the permanent fallback id.
- All write paths use `plan_compat`; feature code does not choose versions.
- Sync and ephemeral traffic use authenticated highest-common selection.
- Forks and third-party clients are outside the contract unless provider-signed.

## Common Implementation Rules

Both designs should follow the existing ownership rules:

- Core routes by stable tags and registered handlers; it does not translate
  protocol data.
- Each fact or frame module owns its versioned codecs, compatibility tests, and
  any typed translation into current projector inputs or rows.
- Connection bootstrap advertises supported scope capabilities as data, then
  handlers choose facts and frame shapes that the peer can open.
- Unknown future capabilities are ignored unless they are required for a fact or
  frame the local node is about to send.
- Old canonical bytes stay hash-stable. Translation happens when opening,
  projecting, querying, or executing commands, never by rewriting the fact
  before identity is computed.
- Read support and write support are separate capabilities. The minimal design
  uses production write gates when supported readers cannot open a feature. The
  one-client-family design avoids gates only when the planner can publish a
  permanent fallback plus newest canonical representation, or a highest-common
  representation for a closed participant set.
- Non-ephemeral facts should replay into deterministic state on upgrade.
  Replayed projectors may rebuild derived tables and indexes, but must not
  perform IO or side effects.
- Replay inputs must be complete. Facts, durable local facts, or explicit
  durable needs must retain the material required to rebuild state or schedule
  follow-up durable work until that material is purged or retired.
- Adding a feature id requires a manifest entry with a compatibility class:
  `epoch_gated`, `legacy_fallback`, `permanent_fallback`,
  `multipublish_view_versions`, `participant_ready`, or `internal_only`.
- A feature cannot create a new workspace-visible fact family without either a
  minimal gate, a legacy fallback mapping, or a one-client-family
  permanent-fallback degradation plan.

The minimal design is the best fit for poc-10 now because it gives a principled
way to ship substantial internal changes without breaking supported clients.
The one-client-family compatibility design adds faster feature deployment while
keeping privacy and compatibility tied to provider-signed clients.
