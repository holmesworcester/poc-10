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

## poc-10 Product Model

Version flexibility should be modeled as feature readiness, not as manual
frontend release flags. The frontend should ask the local runtime whether a
workspace can create a feature, and the runtime should derive the answer from
protocol facts and product policy.

Developers working on individual features should not need to reason through the
whole rollout matrix each time. The product should provide a small feature
manifest API where the feature owner declares one compatibility policy:

- `legacy_fallback`: creation is allowed before universal support because the
  feature writes an old-content fallback plus extension facts for upgraded
  clients.
- `requires_universal_support`: creation is embargoed until workspace readiness
  says every relevant active client supports the feature, or until old clients
  are expired by policy.
- `internal_only`: the feature changes local behavior or read-model rendering
  without creating new workspace-visible protocol state.

From that declaration, shared runtime code should produce the create gate,
frontend availability state, unsupported-client reason, telemetry label, and
compatibility tests. Feature code should supply the new facts, the old fallback
when required, and the upgraded renderer. It should not hand-roll version
queries, active-device scans, or deprecation checks.

Suggested protocol concepts:

- Device capability facts: each active device periodically publishes product
  version, platform, supported fact-family versions, and supported feature ids
  for a workspace.
- Workspace readiness: a derived row says whether a feature is creatable in the
  workspace. It is true when every relevant active device advertises support, or
  when the product deprecation policy has made unsupported devices unable to
  write or participate.
- Graceful-degradation contract: a feature can be created before universal
  support only if its owning module declares how old clients see it as an older
  content type.
- Feature embargo: a non-degradable feature can ship in binaries and backend
  code before it is usable. The runtime keeps it unavailable until workspace
  readiness or the global deprecation date permits it.
- Expiration policy: clients older than the supported horizon should get a hard
  upgrade path and should not be allowed to create new workspace state after
  expiry.

This avoids per-feature hand-coded frontend flags. The UI can still hide or
disable controls, but the source of truth is a generic
`can_create_feature(workspace, feature)` decision with a visible reason such as
`waiting_for_devices`, `requires_upgrade`, `deprecated_client`, or
`ready_with_legacy_fallback`.

Graceful degradation should be explicit in protocol shape. For example, a new
interactive content feature can be represented as an old content message plus a
new extension fact that references the old message. Old clients render the base
message. New clients render the richer extension and suppress duplicate display
of the base. This preserves stable old fact bytes and makes the fallback durable
instead of depending on old clients understanding a new envelope.

Some features will not have an honest downgrade. In those cases poc-10 should
prefer embargo over lossy fallback. The compatibility metadata should say
`requires_universal_support`, and tests should prove that an unsupported active
device keeps the feature uncreatable for that workspace.

The developer workflow should make the safe path hard to skip:

- Adding a feature id requires a manifest entry with one of the compatibility
  policies above.
- A `legacy_fallback` entry requires tests showing that an old-content read path
  still exposes the user-visible intent and that upgraded clients suppress
  duplicate display.
- A `requires_universal_support` entry requires tests showing that creation is
  blocked while a relevant active device lacks support and allowed once the
  workspace readiness row advances.
- A feature cannot create a new workspace-visible fact family without either a
  fallback mapping or a universal-support gate.

## Recommendation For poc-10

Use a two-level model:

1. Connection-level negotiation picks the transport envelope:
   supported `connection::frame` versions, size classes, crypto transcript
   families, and optional connection features.
2. Scope-level manifests register stable fact families and supported layout
   versions. A new incompatible fixed fact layout should usually get a new
   stable tag or versioned family entry, not a hidden branch inside core.

The implementation shape should follow existing ownership rules:

- Core routes by stable tags and registered handlers; it does not translate
  protocol data.
- Each fact or frame module owns its versioned codecs, compatibility tests, and
  any typed translation into current projector inputs or rows.
- Connection bootstrap advertises supported scope capabilities as data, then
  handlers choose facts and frame shapes that the peer can open.
- Unknown future capabilities are ignored unless they are required for a fact or
  frame the local node is about to send.
- Old canonical bytes stay hash-stable. Translation happens when opening,
  projecting, or querying, never by rewriting the fact before identity is
  computed.

The most appropriate external example for poc-10 is the combination of libp2p
protocol IDs and Ethereum devp2p capabilities: explicit protocol IDs, local
handlers for multiple supported versions, highest-compatible or ordered
fallback selection, and no semantic compatibility logic in the transport core.
Cambria remains useful as the discipline for keeping each graceful-degradation
or translation edge isolated and testable. Signal is the closest product-policy
example: old clients can be tolerated for a bounded window, but once they block
the product from preserving reliability or security, they need a hard upgrade
boundary.
