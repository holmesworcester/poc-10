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

This is the relevant richer design for poc-10. It assumes one app provider
ships every client that participates in the privacy and compatibility contract.
Provider-signed desktop, mobile, daemon, and test clients may be on different
versions, but arbitrary forks or third-party clients are outside the contract
unless the provider signs their release manifest. This matters for privacy: a
client that enforces weaker local policy, weaker display rules, or weaker
retention can become the weak link even if the wire protocol accepts it.

The useful goal is not open interoperability. The useful goal is rapid feature
deployment inside one client family while keeping the workspace visibility
invariant: every non-deprecated client sees either the rich behavior it
understands or a durable fallback that is authorized for the same audience.

Goals:

- Ship read support, fallback display, and test write paths early, then allow
  production writes when the compatibility planner can produce a valid plan.
- Keep version policy centralized in a provider-signed release registry and a
  deprecation list.
- Give developers a planner API instead of making every feature hand-roll
  version choice.
- Use permanent fallback facts as validation anchors for durable shared state.
- Use highest-common version selection for closed participant sets, sync
  sessions, and ephemeral events.

### Release Registry

The provider publishes a signed releases registry. Each release entry names the
release id, manifest hash, deprecation state, supported scope and fact-family
versions, permanent fallback formats, canonical rich formats, optional
intermediate view formats, sync bootstrap floor, and ephemeral protocol
versions.

Clients publish signed endpoint capability facts that reference one registry
entry and manifest hash. Only provider-signed release entries create compatibility
obligations. Unknown, forked, or exotic version claims do not force writers to
publish more facts; they are unsupported unless the provider adds them to the
registry.

Deprecation is also data. When a release is deprecated, it leaves highest-common
selection and no longer receives new optional intermediate view facts. Existing
old-version adapters remain as long as retained facts require them.

### Durable Facts

Every durable shared fact family should be introduced with a permanent fallback
format. The fallback is the validation anchor for that fact family and remains
available until the fact family itself is purged or retired. It can be a compact
status/event fact, such as "Alice created a calendar event: Team sync", or an
explicit unsupported-activity fact in an authorized parent scope.

For open-ended audiences such as a workspace, the writer publishes one
author-certified representation set containing:

- the permanent fallback fact
- the newest canonical rich fact
- optional intermediate view facts for non-deprecated releases, only when they
  materially improve old-client UX

The canonical rich fact commits to the fallback fact id, origin command, author,
scope, audience, representation-set key, release manifest ids, and lens path.
To display the rich fact, a client validates that the rich fact and fallback have
the same provenance and that downgrading the rich fact through the declared lens
produces the committed fallback id. That is the key invariant: different
versions cannot become semantically different content.

Readers display the newest verified sibling they understand and suppress lower
fidelity rows only after the representation-set proof succeeds. If a client
understands only the fallback, it displays the fallback. If no fallback can
preserve visibility without leaking across access boundaries, the feature must
use the minimal gate/deprecation path instead of pretending to be compatible.

Fallback placement is part of the feature design. A fallback for a private
channel, space, or calendar cannot simply publish to the whole workspace if the
new object has narrower membership. It must go to an already-readable scope with
the same audience, to per-member fallback facts, or to a parent scope that is
authorized to reveal only that something happened.

### Optional Multi-Version Views

Multi-publishing every non-deprecated release view can improve old-client UX,
but it is not the validation backbone. Intermediate view facts are optional
siblings. They may be produced at write time or later in response to a signed
capability/request fact, much like key-wrap requests and responses. Only the
original author or an author-certified representation-set key can answer because
the response must be signed into the representation set.

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

### Version Selection

Core can provide a protocol-neutral version selector. Given participant or
device ids, their signed endpoint capability facts, a scope or feature id, the
provider releases registry, and local deprecation policy, core returns the
highest common release view version for that participant set or a concrete list
of missing, stale, or unsupported participants. Scope modules still own the
semantics of each version and the degradation lenses; core only computes the
intersection.

Feature code should use a compatibility planner built on that selector. The
planner returns:

- for open-ended durable audiences: permanent fallback plus newest canonical,
  with optional intermediate view siblings
- for closed durable participant sets: the highest common version, or fallback
  plus the highest common version if future devices need replay
- for ephemeral events and sessions: the bootstrap/fallback format until
  capabilities are authenticated, then the highest common ephemeral format
- on failure: the participants, devices, or release manifests that prevent a
  compatible write

Event-creating intents and command handlers should emit the representation set
described by the planner and record the plan hash or manifest ids in the
representation-set proof.

### Sync And Ephemeral Traffic

Sync, connection bootstrap, and 1:1 ephemeral traffic are special because the
audience is fixed for the session. There is no need to publish every
non-deprecated version. Until peers authenticate capabilities, control traffic
uses the lowest non-deprecated bootstrap envelope. After authentication, peers
select the highest mutually supported session protocol allowed by both release
manifests and deprecation policy.

An invite link may name the bootstrap sync-control version, workspace manifest
hash, and endpoint/capability fact family for first contact. The invite is only
an entry point: it must be bound to the workspace admission proof and cannot
force a version below the local non-deprecated floor. After admission, signed
endpoint capability facts become the source of truth for future connections.

The selected sync version controls only the session algorithm and envelopes. It
does not reinterpret durable fact semantics. A newer sync version may batch
representation-set siblings more efficiently, but it still transfers the same
canonical fact bytes and checks access control per sibling fact and scope.

### Recommended Baseline

- Maintain a provider-signed releases registry and deprecation list.
- Require provider-signed endpoint capability facts for compatibility decisions.
- Introduce every durable shared fact family with a permanent fallback format.
- Publish fallback plus newest canonical facts for open-ended durable audiences.
- Treat intermediate release-view facts as optional UX siblings, not validation
  anchors.
- Use a shared compatibility planner for event-creating intents and command
  handlers.
- Use highest-common selection for closed participant sets, sync sessions, and
  ephemeral events.
- Keep forks, third-party clients, and true multi-protocol sessions outside the
  baseline privacy and compatibility contract unless the provider signs their
  release manifests.

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
  permanent fallback, a newest canonical representation, or a highest-common
  participant-set representation.
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
