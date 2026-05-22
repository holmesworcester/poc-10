# Transit / Connection Redesign

Plan for collapsing the `transport` protocol scope into `connection` and
reducing transit to a thin transport envelope. This is forward work, scheduled
**after** the encryption scope decomposition lands.

## Motivation

The `transport` scope carries three smells:

- `transport/transit/` presents itself as a fact family but is not one — it has
  `create.rs`, `frame.rs`, `layout.rs`, `receive.rs` and no `fact.rs`,
  `project.rs`, or `rows.rs`. It is frame-codec machinery.
- `transit/receive.rs` is a ~670-line procedural admission switch that imports
  every other scope (`connection`, `content`, `encryption`, `identity`,
  `sync`) — a cross-scope hub.
- Once the codec moves out and `receive.rs` is deleted, what remains of
  `transport` is one provenance fact and three intents — too thin to be its own
  scope, and all of it is really the data plane of a connection.

## Principle

**Transit is an envelope; facts are the payload. Transit owns zero protocol
semantics.** A frame is a fixed-size container of `(fact_tag, fact_bytes)`
entries — nothing more. Everything semantic is a fact handled by its owning
scope.

The fact pattern supplies four tools; transit should use all of them instead of
procedural code:

| fact-pattern tool          | transit use                                  |
|----------------------------|----------------------------------------------|
| content-addressed fact ids | idempotent receive, for free (see below)     |
| tag-routing via registry   | generic admission, no per-scope switch       |
| projection                 | derived receive state                        |
| intents                    | the network side effect                      |

## Target: dissolve `transport` into `connection`

The `transport` scope is deleted. Six scopes become five. `connection` becomes
the complete story of a peer link — how it is established and how bytes move on
it:

```text
connection.rs
connection/
  ephemeral_secret/        handshake fact families
  request/
  response/
  received_frame/          provenance fact family (was transport/transit_received)
  create_response.rs            handshake intents
  send_bootstrap_request.rs
  receive_transit_frame.rs      transit intents — the core-IO boundary
  send_facts_on_connection.rs
  send_network_frame.rs
```

Notes:

- `transit_received` is renamed `received_frame` — it is the genuine fact here
  (receive provenance), and "transit" stops being a noun in the tree.
- `transit_received/addr.rs` folds into `received_frame/layout.rs` (address
  normalization is byte-level) or into `core::wire`.

## Frame codec → `core::wire`

`frame.rs`, `layout.rs`, `create.rs` are fixed-layout wire machinery for the two
configured frame sizes. The architecture already states transit frames "use the
same fixed-layout wire machinery" and "socket IO belongs in core." The frame
becomes a fully generic tagged-blob container owned by `core::wire`; it carries
no protocol-specific structure.

## Generic, tag-routed inbound admission

`transit/receive.rs` is deleted. The `receive_transit_frame` intent handler
becomes generic: decode the frame into `(tag, bytes)` entries, and for each,
construct a `Fact` and admit it to the pending-fact queue — routed by tag
through the **same registry table core already uses for projection**. The
handler imports no other scope.

Per-fact-family inbound rules ("can this tag arrive over transit, how is its
scope derived") are declared by each family in the registry, next to its
projector registration — symmetric with outbound projection routing.

Bootstrap-specific decoding (`open_bootstrap_request` / `open_bootstrap_response`,
`ConnectionRequestFact` / `ConnectionResponseFact`) is `connection`-scope
knowledge and moves into the `connection` scope.

## Idempotence falls out for free

The hand-built idempotence key on `receive_transit_frame` is unnecessary. The
inner facts are content-addressed — re-admitting a fact already held is a no-op
by fact id. A duplicate frame re-admits its inner facts, all of which already
exist, so nothing happens. Idempotence lands at exactly the right granularity
(per inner fact) with no bespoke keying.

For this reason the raw frame is **not** modeled as a stored fact — it is pure
transport, redundant once opened. The `received_frame` provenance fact is made
content-deterministic (keyed by frame content + connection) so it dedups the
same way.

## Send stays two intents

`send_facts_on_connection` and `send_network_frame` remain **separate** intents.
Reasons:

- **Fan-out.** One `send_facts_on_connection` batches facts under the frame-size
  limit and produces *N* sealed frames — one `send_network_frame` each. The
  1→N relationship needs two intent kinds.
- **Durability class.** `send_network_frame` is ephemeral best-effort IO that
  must not become durable protocol state; `send_facts_on_connection` is the
  durable decision that facts must reach the peer.
- **Idempotence dimension.** `send_facts_on_connection` is keyed by
  (connection, fact-ids / range); `send_network_frame` by
  (routing-key, frame-hash) so identical sealed frames collapse.
- **Retry granularity.** A route-missing failure retries only the socket write,
  not fact loading, batching, and re-sealing.
- **Opaque-bytes IO waist.** `send_facts_on_connection` does protocol and crypto
  (load, batch, seal with the connection secret); `send_network_frame` resolves
  an address and writes opaque bytes. `send_network_frame` is the single thin
  IO boundary touching `core::network`.

Both become `connection` intents; they stay two intents.

## Resulting shape

Outbound and inbound become symmetric, with transit as a thin waist:

```text
projection emits facts -> registry tags them -> core::wire frames them
frame arrives -> core::wire unframes -> registry admits the tagged facts
```

## Sequencing

1. Encryption scope decomposition (in progress, isolated worktree).
2. Fact-family cleanup to the strict 8-file rule across all scopes.
3. This transit / connection redesign.
4. Strict layout guardrail tests (only intents and family manifests directly
   under a scope; only the 8 role files inside a family directory).
