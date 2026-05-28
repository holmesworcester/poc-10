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
- Avoid production write gates. New features should become writable immediately
  by publishing every representation needed by supported readers.
- Support different desktop and mobile feature sets, including advanced
  platform-specific features, while maintaining graceful degradation for clients
  that do not support the richer view.
- Keep the visibility invariant scoped to the participants affected by the
  feature: if a user can create visible state for a group, every included
  participant has either a native view or an explicit legacy view.

The following items are tactics, not mutually exclusive options. The maximal
design works only by combining several of them: version manifests define what
exists, lenses define how representations relate, multi-publish creates signed
durable siblings, suppression chooses one readable sibling for display, and
handshake/sync keeps the sibling set available without leaking across access
boundaries.

Maximal tactic A: capability facts per device, workspace, and scope.

Every active device publishes signed capability facts naming supported product
versions, protocol scopes, fact-family versions, intent kinds, command features,
platform affordances, and expiration policy. Projectors derive readiness rows
per workspace, conversation, participant set, and feature.

This gives precise availability but creates a new consistency surface: the
runtime must decide which devices count as active, when stale capability facts
expire, and how to handle offline devices.

Maximal tactic B: versioned scope manifests and dispatch.

Each protocol scope registers multiple versions of its facts, intents,
projectors, commands, and read-model adapters. Core routes by stable scope and
version tags, while scope-owned adapters translate to a current semantic model
when possible. Unknown capabilities are ignored unless a feature marks them as
required.

A version does not need to be a linear integer. In the maximal design it can be
a content-addressed node in a scope version graph: the hash of the fact schema,
command semantics, projector contract, and lens edges that define that protocol
shape. Product releases publish stable aliases such as `messages/release-v3`
that point to graph nodes. The lens graph may include experimental commits,
forks, platform-specific branches, and intermediate conversion nodes, but
durable multi-publish targets only supported release aliases.

This gives strong modularity, but every supported version becomes part of the
test matrix.

Maximal tactic C: explicit degradation lenses.

For each feature that can be visible to older clients, the owning module
declares a downgrade relation: new state to old visible state, old edits back to
new state when possible, and cases where old edits must be rejected or converted
to a limited operation. Cambria is the conceptual model, but the lens should
operate on typed facts and commands, not arbitrary core bytes.

This enables early feature availability but is only correct when the
degradation relation preserves user intent clearly enough.

Maximal tactic D: multi-publish view versions.

For durable shared facts, writers publish a representation set: the richest fact
plus bounded fallback view facts for supported reader versions that cannot
display the rich fact. Clients project the newest readable representation in
that set and ignore lower-fidelity siblings for display. This is not "latest
plus one lowest-common fallback" if intermediate versions preserve more meaning.
If supported clients exist on v1, v2, and v3, and v2 can display a better
downgraded view than v1, the writer may publish v3, v2-view, and v1-view facts
together.

The set is tied together by a stable representation-set identity. A concrete
form is an author-certified representation-set public key: the author signs a
certificate binding that key to the originating command commitment, author,
scope, audience, command nonce, supported release view versions, and lens graph
root. Each representation also names its release view version or version-graph
node, the lens path used to derive it, and any sibling fact ids that were known
when it was created. Newer representations can refer backward to older sibling
ids; older representations cannot know future ids, so suppression is handled by
projection context.

The representation-set identity is not trusted by name alone. Suppression needs
a signed proof that the richer representation is allowed to dominate the older
one: same author or author-certified representation-set public key, same scope
and audience, same origin command commitment, a version-graph dominance
relation, and a hash chain or manifest entry that names the older fact id. A
separate representation-set manifest can list all sibling fact ids after they
are computed, or each richer representation can hash-reference the older
representation it suppresses.

In practice, a newer representation projects an offer such as
`newer_representation_available(group_id, version, fact_id)`. Older
representation projectors keep a matching need; when the offer arrives, they
purge only their materialized rows and emit a suppression offer such as
`representation_suppressed(old_fact_id, by_fact_id)`. The signed old fact stays
in the durable log until retention or version-deprecation purge removes it.

This turns dual-publish into bounded multi-publish across still-supported
release view versions. The bound is the support policy: when a version is
deprecated, writers stop producing that view version forever, and existing
compatibility view facts for that deprecated version are purged by fact-driven
deprecation policy. The richest/source representation is not purged merely
because an older view version expired. Ephemeral communication can choose a
lowest-common-denominator representation from handshake capabilities instead of
publishing every supported view.

The benefit is signing provenance. The author or the author-certified
representation-set key signs every published representation at creation time,
so older clients do not need an authority to rewrite authorship later.
Cambria-style downgrade rules help generate the view facts from the rich
command, but the signed outputs are ordinary facts.

Maximal tactic E: suppress fallbacks with richer context.

Fallback and rich facts may share a stable `presentation_group_id` for batching
and UI grouping. It can be the hash of an author-certified representation-set
public key, but the id itself is only a hint. It must not authorize suppression
because another writer could copy the same display id without holding the
private key. Older clients display the best view version they understand. Newer
clients wait briefly for facts in the same representation set, validate the
signed representation-set proof, choose the richest readable representation,
and suppress lower-fidelity fallbacks only after that proof succeeds. Sync
should keep facts in the same representation set close together so upgraded
clients do not flash the fallback before the rich view arrives.

A shared per-group secret is not sufficient for durable suppression because any
holder of that secret could impersonate suppression authority for another
member's representation. Group secrets can encrypt or authorize the audience,
but replacement and suppression should be signed by the original author or by a
one-command representation-set private key that the original author certified
for that exact command and set of versions.

If a client sees only the fallback, it should render a clear downgraded card,
such as "Alice created a calendar event: Team sync, Friday 10am" with an info
affordance saying the feature is not fully supported by this client.

Maximal tactic F: access-controlled fallback placement.

Fallback facts must be published only into scopes where the fallback is allowed
to be visible. For a new channel, calendar, or space, the fallback cannot simply
go to the whole workspace if the new object has narrower membership. The feature
must either publish fallback activity into an already-readable parent scope that
is authorized for the same audience, publish per-member fallback facts, or accept
that old clients see only parent-level activity such as "A space was created"
without access to the space's contents.

For entirely new private containers, old clients may be able to display only
creation/update activity in the parent workspace or channel. The new container's
native contents remain unavailable until a client supports that container scope,
but the fallback preserves visibility that something happened without leaking
more than the old scope authorizes.

Maximal tactic G: sync protocol negotiation and capabilities.

Handshake capabilities should not decide which durable representations a shared
fact needs. A peer on the current connection is only one observer; durable
visibility depends on the audience, future joiners, workspace membership,
release/deprecation policy, and the protocol manifests the workspace accepts.
For the one-product case, the safest durable rule is to publish every
non-deprecated released view version for that fact family. Each release manifest
records the previous release view versions it can read and the version-graph
nodes those releases correspond to.

For heterogeneous clients, forks, or modular protocol users, missing durable
representations should converge deterministically. Devices publish signed
capability or representation-need facts for recognized release aliases or
workspace-accepted protocol manifests. If an existing representation set is
missing one of those accepted view versions, the original author or
author-certified representation-set key can publish the missing sibling later.
Unknown or exotic version claims do not obligate the creator to publish more
facts; protocol admission, quotas, rate limits, and abuse handling are product
policy around the manifest allowlist, not properties of the handshake.

Sync and connection protocols are the participant-aware special case. The
audience is exactly the two peers for the lifetime of the session, so there is
no need to publish every non-deprecated released version. Until each side knows
the other's authenticated capabilities, all control traffic uses the lowest
non-deprecated bootstrap format. After that, session traffic uses the highest
mutually available version allowed by both peers and local deprecation policy.
If the peer set or capabilities change, start a new session and negotiate again.

Different sync protocol versions negotiate through a fixed bootstrap floor:

1. Start every connection in the lowest non-deprecated sync-control envelope
   that all supported clients must understand. This envelope is deliberately
   small: identify the peer, establish or resume session keys, exchange
   capability manifests, and select the sync protocol for the session.
2. After authentication, each side sends a transcript-bound capability manifest:
   supported sync protocol families, supported version graph nodes or release
   aliases, minimum accepted version, preferred version, and feature bits such
   as set reconciliation, chunking, resume tokens, and representation-set batch.
3. Select deterministically from the authenticated manifests: choose the highest
   mutually supported sync version that is not below either side's minimum and
   is allowed by local deprecation policy. If there is no version above the
   bootstrap floor, keep using the floor. If even the floor is not allowed,
   close with an upgrade-required error.
4. Bind both complete manifests and the selected version into the session
   transcript before sending sync data. If an active network attacker strips
   newer capabilities, the transcript check fails or both peers derive different
   selected versions and abort.
5. Run the negotiated sync protocol. That protocol choice controls only the
   session algorithm and envelopes, not the durable meaning of facts. An older
   sync protocol may transfer the same canonical facts less efficiently; it must
   not reinterpret their scope or fact-family versions.

For example, `sync-v1` might exchange raw fact ids and bytes after a basic
set-reconciliation compare. `sync-v2` might add representation-set summaries:
when compare finds that a peer is missing fact `X`, the responder looks up `X`
in a local index built from signed fact contents and projection rows, then
sends the missing authorized sibling facts in the same response. If the session
falls back to `sync-v1`, those siblings may arrive in later requests, but they
remain the same signed facts. Access control is checked per sibling fact and per
scope before sending, because fallback facts may live in a parent scope, a
private container scope, or per-member scopes.

Ephemeral 1:1 or session-only protocols use the same shape: start from the
bootstrap floor, authenticate the capability exchange, then move up to the
highest mutually supported ephemeral format.

Maximal tactic H: participant-set readiness as optimization, not gate.

Instead of gating by whole workspace, the runtime computes readiness for the
exact affected participant set. A DM feature can become available when both
parties and all their active devices support it. A private draft feature can be
available to one user immediately. A workspace-wide policy feature waits for
workspace-wide support or legacy-visible fallback.

Core can provide the deterministic version selector for this without learning
scope semantics. Given participant or device identifiers, their signed
capability/version facts, the scope's accepted release aliases, and local
deprecation policy, core returns the highest common release view version for
that participant set or a concrete list of missing, stale, or unsupported
participants. Scope manifests and lenses still define what that version means
and how facts degrade; core only computes the intersection. A sync or connection
session is the same calculation with exactly two participants after the
capability exchange is authenticated.

In the no-gate maximal design this is only an optimization for closed,
well-known participant sets. If all affected participants can read v3, publish
only v3. If not, publish the needed fallback view versions. For open-ended
audiences such as a workspace that may gain new members or devices later, prefer
the release-manifest rule: publish every non-deprecated released view version,
then converge by adding recognized missing siblings if the accepted manifest set
expands. The feature manifest still needs to state the visibility domain:
`local_user`, `device_set`, `dm_participants`, `channel_members`, or
`workspace`.

Maximal tactic I: multi-protocol sessions.

Connection bootstrap negotiates envelope versions, crypto transcript families,
scope capabilities, and optional subprotocols. A single peer connection can run
several protocol families at once, and handlers choose the newest mutually safe
format per recipient or participant set.

This is the most flexible network model and the highest engineering cost. It is
appropriate only if poc-10 intentionally becomes a protocol platform or supports
long-lived forks.

Recommended maximal baseline:

- Every release ships a graph-addressed scope manifest. The manifest names the
  supported version-graph nodes, release aliases, non-deprecated view versions,
  bootstrap sync floor, and deprecation policy for each scope.
- Every durable shared feature declares its visibility domain and a typed
  degradation lens from the richest command or fact to each non-deprecated
  release view version that domain may require. If no degradation preserves
  visibility, the feature must publish an explicit unsupported-activity fact in
  an authorized parent scope or it is not maximal-compatible for old clients.
- On write, the creator produces one author-certified representation set. For
  open-ended audiences, publish the richest/source fact plus every
  non-deprecated release-view sibling. For closed participant sets, omit a
  sibling only when every included active device can read a richer sibling.
- Projectors verify the representation-set proof, scope, audience,
  version-graph dominance, and hash links before suppressing lower-fidelity
  rows. Readers display the newest verified sibling they understand.
- Sync negotiates the session protocol through the bootstrap floor and the
  highest authenticated common sync version. The chosen sync version may batch
  representation-set siblings, but it transfers the same canonical facts and
  does not define durable compatibility.
- Deprecation stops new writes of that release-view sibling and purges old
  compatibility view facts by policy. Rich/source facts remain until normal
  retention purges them.

Defer true multi-protocol sessions, where one connection concurrently runs
several independent product protocols, until poc-10 actually needs forked or
third-party protocol networks.

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
  maximal design avoids gates by publishing the representations required by
  supported readers.
- Non-ephemeral facts should replay into deterministic state on upgrade.
  Replayed projectors may rebuild derived tables and indexes, but must not
  perform IO or side effects.
- Replay inputs must be complete. Facts, durable local facts, or explicit
  durable needs must retain the material required to rebuild state or schedule
  follow-up durable work until that material is purged or retired.
- Adding a feature id requires a manifest entry with a compatibility class:
  `epoch_gated`, `legacy_fallback`, `multipublish_view_versions`,
  `participant_ready`, or `internal_only`.
- A feature cannot create a new workspace-visible fact family without either a
  minimal gate, a legacy fallback mapping, or a maximal multi-publish and
  degradation plan.

The minimal design is the best fit for poc-10 now because it gives a principled
way to ship substantial internal changes without breaking supported clients.
The maximal design is a reserve architecture for a future where protocol scopes
are modular, forked, or independently deployed.
