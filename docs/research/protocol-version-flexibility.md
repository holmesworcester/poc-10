# Protocol Version Flexibility Research

This note records examples that are relevant to poc-10's protocol evolution
surface. The current runtime uses immutable canonical fact bytes, deterministic
fact ids, fixed wire layouts, scope-owned codecs, and connection frames with a
public `TRNS` tag plus version byte. Version flexibility should preserve those
properties instead of turning core into a compatibility layer.

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
Cambria remains useful as the discipline for keeping each translation edge
isolated and testable.
