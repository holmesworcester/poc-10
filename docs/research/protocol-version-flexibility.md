# Protocol Version Flexibility Research

This note records examples that are relevant to poc-10's protocol evolution
surface. The current runtime uses immutable canonical fact bytes, deterministic
fact ids, fixed wire layouts, scope-owned codecs, and connection frames with a
public `TRNS` tag plus version byte. Version flexibility should preserve those
properties instead of turning core into a compatibility layer.

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

## Industry Patterns

### libp2p protocol IDs and fallback

libp2p gives application protocols string IDs with a version component such as
`/my-app/amazing-protocol/1.0.1`. A dialer can offer multiple protocol IDs in
order, and the first mutually supported protocol is used. Listeners can also
register match functions for non-exact matching, such as accepting a compatible
major version.

Fit for poc-10: high. This maps directly to connection bootstrap or daemon
capabilities: advertise supported frame and fact-family versions, pick a common
version per connection, and dispatch to a scope-owned versioned codec.

Constraint for poc-10: negotiated aliases must not change canonical fact bytes
after hashing. A V1 fact should remain a V1 fact. If it is projected into a
current read model, that projection belongs in the owning projector or a
module-local translator.

Source: `https://libp2p.io/docs/protocols/`.

### Ethereum devp2p capabilities

Ethereum's RLPx handshake exchanges named capabilities and versions in the
`Hello` message. Shared capabilities are used concurrently on one connection;
capabilities that are not shared are ignored, and when multiple versions of the
same capability are shared the highest version wins. The base `p2p` capability
also ignores extra fields and version differences for forward compatibility.

Fit for poc-10: high. This is the closest operational model for multiple
protocol scopes on one authenticated connection. poc-10 could negotiate
connection-frame shape, sync shape, and content fact families independently
instead of treating the whole node as one monolithic protocol version.

Constraint for poc-10: "highest shared wins" is safe only when both sides have
registered deterministic decoders and tests for every advertised version.

Source: `https://raw.githubusercontent.com/ethereum/devp2p/master/rlpx.md`.

### BitTorrent Extension Protocol

BEP 10 adds an extension handshake after the standard BitTorrent handshake.
Peers advertise extension names and assign per-peer extension message IDs.
Unknown names are ignored, extension support can be changed during a connection,
and message IDs are local to each peer.

Fit for poc-10: medium. The "ignore unknown extension names" and "renegotiate
without reconnecting" ideas are useful for optional handlers or telemetry-like
features.

Constraint for poc-10: per-peer numeric IDs are a poor fit for canonical fact
bytes because poc-10 fact ids are hashes of stable bytes. Use stable fact tags
or versioned scope tags for facts; reserve per-connection negotiation for
transport framing and optional intent behavior.

Source: `https://bittorrent.org/beps/bep_0010.html`.

### QUIC version negotiation

QUIC uses a version field in the long header. If a server receives an
unsupported version on a possible new connection, it can send a Version
Negotiation packet listing supported versions. QUIC also reserves invariant
packet properties so an endpoint can recognize negotiation packets without
understanding the future version.

Fit for poc-10: medium-high for the connection-frame public header. The
existing `TRNS` tag plus version byte already resembles a version-independent
envelope. A future incompatible `TRNS` version can fail before decryption and
trigger a bootstrap retry or explicit unsupported-version fact.

Constraint for poc-10: QUIC-style negotiation is coarse. It selects an envelope
version, not a semantic fact-family version. It should complement, not replace,
scope-level capability negotiation.

Source: `https://www.ietf.org/rfc/rfc9000.html`.

### Kafka and Confluent Schema Registry

Confluent Schema Registry models schema evolution with compatibility policies:
backward, forward, full, and transitive variants. New schema versions are
checked against prior versions before they are accepted.

Fit for poc-10: medium. This is a strong testing and release-gate pattern:
before registering a new fact layout or changing a row value layout, require
tests that prove supported older bytes still decode, reject invalid changes, or
project into the intended current rows.

Constraint for poc-10: a central registry service is not appropriate for
local-first peers. The useful piece is the compatibility policy matrix and test
discipline, not the service topology.

Source:
`https://docs.confluent.io/platform/current/schema-registry/fundamentals/schema-evolution.html`.

### Signal release expiration and old-device pressure

Signal is a useful product precedent because it optimizes for reliability and
security within one product, not protocol diversity across many vendors. Signal
documents that releases expire after 90 days, that some functionality requires
all devices on an account to support current updates, and that sufficiently old
operating systems can still open the app but cannot send or receive until the
OS is upgraded.

Fit for poc-10: high as a product policy pattern. A hard client deprecation
date lets the protocol stop carrying old compatibility paths forever. Before
that date, feature creation should be gated by explicit workspace capability
state or should write a legacy-visible fallback.

Constraint for poc-10: expiration alone is too coarse for workspace-level
feature safety. poc-10 still needs a per-workspace active-client view so a
workspace can use a feature early when all relevant devices have upgraded, while
another workspace waits until the global deprecation boundary.

Sources:
`https://support.signal.org/hc/en-us/articles/9021007554074-Open-Signal-on-your-phone-to-keep-your-account-active`
and
`https://support.signal.org/hc/en-us/articles/5109141421850-Supporting-Older-Operating-Systems`.

## Minimal Design

The minimal design assumes one product, one canonical production write protocol
per feature or scope, and a bounded support window for old clients. Older fact
versions still have retained read/replay adapters, and old clients may continue
writing old facts during their support window. After deprecation, old write
protocols are disabled, but old read/replay adapters remain as long as retained
facts require them. The design gates new feature creation until any client that
lacks the feature would already be deprecated. Once that boundary is crossed,
migration happens seamlessly: new binaries can write the new facts, projectors,
intents, commands, rows, indexes, query plans, and database schema without
preserving old-client write compatibility forever.

This design is meant to make substantial change safe without asking every
feature developer to become a rollout expert. It should support new features and
new internal designs such as TreeKEM, a new file encoding, different
disappearing-message policies, new indexing or query optimization, and
significant intent/fact/projector reshaping without breaking supported users.

Goals:

- Preserve the workspace visibility invariant during every supported transition:
  anything a user can create must be visible to every non-deprecated client in
  that workspace.
- Allow structural migrations of database tables, row layouts, fact families,
  intent kinds, command surfaces, and internal data types behind a principled
  release boundary.
- Let feature code ship early but keep creation embargoed until the deprecation
  date or compatibility epoch makes it safe.
- Ship read/display support before production write support. Write paths can be
  implemented and available in alpha or test builds, but production creation
  stays feature-gated until every relevant supported client can read the new
  state or there is an explicit legacy-visible fallback.
- Make migrations automatic once the boundary is reached, with old clients
  expired or unable to create new workspace state.
- Keep every non-ephemeral fact replayable into deterministic state. On upgrade,
  a client can discard derived tables and rebuild them by replaying durable
  facts through the current registered projectors.
- Test all combinations that can occur during the transition period: old binary
  with old data, new binary before the feature epoch, alpha writer with prod
  readers, prod binary with write gate disabled, new binary after the epoch,
  peers on both sides of the supported-version line, and upgrade order
  permutations for active workspaces.
- Keep developer ergonomics simple: a feature owner declares a required
  compatibility epoch and, optionally, a fallback. Shared runtime code owns the
  gate, reasons, telemetry, transition tests, and deprecation checks.

Minimal baseline: read-before-prod-write.

Every feature with new visible protocol state should land in two phases. First,
supported clients learn to parse, project, index, query, and display the new
state. During this phase, write support can exist for alphas, integration tests,
dogfood builds, and compatibility fixtures. Production write UI and command
creation remain disabled by a runtime gate. Second, once all relevant
non-deprecated clients can read the state, the production write gate opens.

This keeps implementation honest: the feature is fully testable before launch,
but no production user can create state that supported teammates cannot see.

Minimal baseline: replay-derived-state-on-upgrade.

Every non-ephemeral fact should be a durable input to deterministic projection.
On each upgrade, the runtime may rebuild local deterministic state from the fact
log instead of carrying bespoke table migrations forward forever. Database
tables, indexes, materialized rows, query caches, and compatibility rows become
derived state. Upgrading code can wipe those derived tables, replay facts through
the current projector registry, and produce the current local schema.

This makes structural change easier: old row layouts do not need a long chain of
imperative migrations, and major internal redesigns can be validated by replay.
The test harness should include replay from fixture fact logs produced by every
supported transition version. It should also compare old and new projections for
states that are meant to remain semantically equivalent.

Replay-on-upgrade needs strict boundaries:

- Facts are durable protocol truth; replay must not resend network frames,
  repeat one-time side effects, recreate already-sent key wraps, or consume
  external IO.
- Non-ephemeral local state must be represented as durable local facts, durable
  queues, or derivable rows until its purge or expiry. That includes local
  secrets, device keys, pending durable intents, user-visible download progress,
  correctness-affecting daemon checkpoints, and platform capability or
  permission observations that affect feature eligibility.
- Replay must include the material needed to make progress. Durable facts,
  durable local facts, or explicit replay needs must represent every input
  needed to rebuild deterministic state or schedule required durable work. If a
  device must create replacement key-wrap coverage, the relevant local secret
  material or a durable need for that material must survive until the secret is
  intentionally purged or retired.
- Socket state, live sessions, in-flight connection handshakes, and other
  transport process state are ephemeral. They do not need to survive upgrade;
  they must be safe to drop and rebuild by reconnecting from durable facts and
  queues.
- Ephemeral facts and caches are safe only when losing them cannot remove
  user-visible work, secret material needed for future decryption, or durable
  obligations.
- Projectors must be deterministic over facts plus explicit context. Old-format
  facts can be replayed by new implementations of old-version adapters, and
  those adapters can emit current rows. Adapter selection must remain
  version-addressed, and each adapter must preserve the old fact's semantic
  contract unless an explicit policy/version fact or `effective_from` boundary
  changes the interpretation.
- Retention and purge rules vary by workspace and must be represented as durable
  facts or explicit absence semantics so replay can reconstruct the intended
  current state from the remaining log. Some fact families, especially auth,
  may be retained forever in the current model.
- Durable facts are purged only when the data they describe is also purged by
  policy. Purge, retention, deletion, and disappearance decisions must be
  expressed as facts before target facts or payloads disappear, so replay cannot
  resurrect data that policy says is gone.

Replay-on-upgrade also changes how poc-10 can handle old protocol versions. For
the minimal design, poc-10 does not need Cambria-style lenses at first. It can
keep old versioned codecs and projectors as replay adapters, for example
`protocol/v1/auth/key_wrap` and `protocol/v2/auth/key_wrap`. Those modules
decode their canonical fact bytes and project into the current local rows. The
project can accumulate supported replay adapters for the support window and
still patch old adapters for security or validation fixes.

This accumulation should be bounded by product policy where possible, but
workspace retention policies mean some adapters may be long-lived. Once a
protocol epoch is past the deprecation and retention horizon for every
workspace that can contain those facts, the old replay adapter can be removed if
no remaining durable facts need it. Auth-like forever facts may require keeping
their replay adapters indefinitely unless a new protocol explicitly retains the
old signed bytes as evidence.

Durable conversion is constrained by signatures. The minimal design keeps old
author-signed facts as the provenance source. An admin or workspace authority
must not be able to convert an author-signed fact into a new fact that appears
to be signed by the original author. That would create impersonation authority.
For author-signed facts, old signed bytes and the matching replay adapter remain
the source of truth until the fact is purged under its workspace retention
policy. The minimal design does not rely on signer-authored supersession to
retire old content because signers may be offline, gone, or on old devices.
Policy facts can publish interpretation, retention, or purge decisions, but
those facts should not claim to be replacement author signatures.

Lens-like conversion rules become useful only as projection rules or as
provenance-preserving transformations. They can say how old signed facts project
into current rows. They should not let a third party rewrite authorship. Until
then, old adapters are easier and safer than lenses because they preserve the
original canonical bytes, hash identity, and author signature.

Projectors that normally cause non-ephemeral facts through intents need a replay
contract. Replay projectors may declare missing durable work, but they must not
execute it directly. For example, if a new key-wrap format is required, replay
can derive "recipient X lacks key-wrap coverage for secret Y under format Z" as
a row or need. The normal runtime then schedules idempotent key-wrap creation
outside replay. Each produced key-wrap fact has a deterministic coverage key, so
all clients converge without creating unbounded duplicates.

That coverage derivation is only complete if the replay surface also preserves
the material needed to satisfy it. A client that still owns the relevant secret
must have that secret as a durable local fact, a decryptable durable local
secret, or an explicit durable need for secret recovery. Replay should not
discover after upgrade that required key material was treated as disposable
cache. If the material was intentionally purged or the device is no longer
authorized to hold it, replay should leave a durable unsatisfied need rather
than fabricating coverage.

Creating many new key-wrap facts can be intended after an upgrade if the new
format is required for future reliability or security. The safety condition is
that creation is idempotent and coverage-based, not replay-count-based: replay
should ask "is required coverage present?" rather than "did this projector run?"

Deleting old non-ephemeral facts should also be fact-driven. If old key-wraps or
other obsolete facts should disappear, create a retirement, supersession, or
purge-policy fact that the old target projectors observe. Deletion should not be
an implicit side effect of replay. Old clients either still see the old facts
during the support window, or they are past the deprecation boundary before the
contract step removes or ignores them.

Minimal option A: global compatibility epochs.

Each release train defines a `min_supported_epoch` and a `current_epoch`.
Features declare `requires_epoch = N`. Until the product policy expires all
clients older than `N`, creation is disabled everywhere, even if many workspaces
have already upgraded. After the expiration date, clients older than `N` cannot
write, and the runtime can migrate local databases and start writing the new
canonical facts.

This is the simplest way to avoid frontend flag sprawl. It is conservative and
may delay features because one platform approval delay or a broken release holds
the epoch back.

Minimal option B: per-feature deprecation horizons.

Each feature declares the oldest client version or protocol epoch it requires.
The product can deprecate old clients per feature family rather than advancing a
single global epoch for everything. This allows, for example, a new file
encoding to wait for file-capable clients while unrelated indexing changes ship
under a different horizon.

This reduces unnecessary waiting but needs clearer policy metadata and more
transition tests than option A.

Minimal option C: expand-then-contract storage migrations.

During the support window, new binaries write old-compatible durable state plus
new shadow rows or facts. Old clients continue to operate on the old shape. At
the epoch boundary, the runtime either replays durable facts into the new schema
or runs the contract migration, removes old rows or compatibility projectors,
and makes the new representation canonical.

This is the fallback for state that cannot be rebuilt cheaply on every upgrade
or for transition periods where old and new binaries need side-by-side local
representations. Pure derived database and index changes should prefer
replay-on-upgrade.

Minimal option D: legacy-visible fallback facts.

When a feature has a true graceful downgrade, it can create an old content fact
plus extension facts for upgraded clients. Old clients render the old content;
new clients render the richer extension and suppress duplicate display. This
lets safe one-person or low-risk features arrive earlier without violating
visibility.

This option should be opt-in. If the fallback is lossy or confusing, the feature
should use an epoch gate instead.

Recommended minimal path: make read-before-prod-write and
replay-derived-state-on-upgrade the default rules, then start with option A.
Use option C only when replay is too expensive or the state is not purely
fact-derived. Add option D only for features with an honest old-client
rendering. Option B is useful once the project has enough feature families that
a single epoch becomes too blunt.

## Maximal Design

The maximal design assumes a much more chaotic future: forks, multiple clients,
different product protocols, independent apps using protocol scopes modularly,
several simultaneous protocols on the same network, and many devices with
different capabilities in one workspace. In this world, compatibility is not
only a release boundary. It is a permanent protocol feature across facts,
intents, projectors, commands, frame envelopes, and read models.

Goals:

- Allow facts, intents, projectors, and commands from different versions to
  coexist and interoperate where a module declares a safe relation.
- Allow protocol scopes to be used independently by other applications without
  forcing the whole poc-10 product release train.
- Support multiple simultaneous protocols on the same connection or network,
  with explicit capability negotiation and versioned dispatch.
- Make one-person features available immediately when they affect only that
  user's devices.
- Make fixed-group features available as soon as every included participant can
  see them on all relevant devices, such as both parties in a DM.
- Support different desktop and mobile feature sets, including advanced
  platform-specific features, while maintaining graceful degradation for clients
  that do not support the richer view.
- Keep the visibility invariant scoped to the participants affected by the
  feature: if a user can create visible state for a group, every included
  participant has either a native view or an explicit legacy view.

Maximal option A: capability facts per device, workspace, and scope.

Every active device publishes signed capability facts naming supported product
versions, protocol scopes, fact-family versions, intent kinds, command features,
platform affordances, and expiration policy. Projectors derive readiness rows
per workspace, conversation, participant set, and feature.

This gives precise availability but creates a new consistency surface: the
runtime must decide which devices count as active, when stale capability facts
expire, and how to handle offline devices.

Maximal option B: versioned scope manifests and dispatch.

Each protocol scope registers multiple versions of its facts, intents,
projectors, commands, and read-model adapters. Core routes by stable scope and
version tags, while scope-owned adapters translate to a current semantic model
when possible. Unknown capabilities are ignored unless a feature marks them as
required.

This is the devp2p/libp2p pattern applied inside poc-10. It gives strong
modularity, but every supported version becomes part of the test matrix.

Maximal option C: explicit degradation lenses.

For each feature that can be visible to older clients, the owning module
declares a downgrade relation: new state to old visible state, old edits back to
new state when possible, and cases where old edits must be rejected or converted
to a limited operation. Cambria is the conceptual model, but the lens should
operate on typed facts and commands, not arbitrary core bytes.

This enables early feature availability but is only correct when the
degradation relation preserves user intent clearly enough.

Maximal option D: participant-set readiness gates.

Instead of gating by whole workspace, the runtime computes readiness for the
exact affected participant set. A DM feature can become available when both
parties and all their active devices support it. A private draft feature can be
available to one user immediately. A workspace-wide policy feature waits for
workspace-wide support or legacy-visible fallback.

This matches real product expectations, but it requires the feature manifest to
state the visibility domain: `local_user`, `device_set`, `dm_participants`,
`channel_members`, or `workspace`.

Maximal option E: multi-protocol sessions.

Connection bootstrap negotiates envelope versions, crypto transcript families,
scope capabilities, and optional subprotocols. A single peer connection can run
several protocol families at once, and handlers choose the newest mutually safe
format per recipient or participant set.

This is the most flexible network model and the highest engineering cost. It is
appropriate only if poc-10 intentionally becomes a protocol platform or supports
long-lived forks.

Recommended maximal path: use option A and option D as product-facing concepts,
then add option B only for scopes that genuinely need independent versioning.
Use option C sparingly for high-value graceful degradation. Defer option E until
there is a real multi-protocol network requirement.

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
- Read support and write support are separate capabilities. Production write
  gates require reader readiness; alpha and test write paths may exist before
  production write is enabled.
- Non-ephemeral facts should replay into deterministic state on upgrade.
  Replayed projectors may rebuild derived tables and indexes, but must not
  perform IO or side effects.
- Replay inputs must be complete. Facts, durable local facts, or explicit
  durable needs must retain the material required to rebuild state or schedule
  follow-up durable work until that material is purged or retired.
- Adding a feature id requires a manifest entry with a compatibility class:
  `epoch_gated`, `legacy_fallback`, `participant_ready`, or `internal_only`.
- A feature cannot create a new workspace-visible fact family without either a
  fallback mapping, a participant/readiness gate, or an epoch gate.

The minimal design is the best fit for poc-10 now because it gives a principled
way to ship substantial internal changes without breaking supported clients.
The maximal design is a reserve architecture for a future where protocol scopes
are modular, forked, or independently deployed. Signal is the closest
product-policy example for the minimal design: old clients can be tolerated for
a bounded window, but once they block reliability or security, they need a hard
upgrade boundary. libp2p and Ethereum devp2p are the closest protocol examples
for the maximal design: explicit capabilities, versioned dispatch, fallback
selection, and no semantic compatibility logic in the transport core.
