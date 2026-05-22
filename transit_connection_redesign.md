# Transit / Connection Redesign

Plan for collapsing the `transport` protocol scope into `connection` and
reducing transit to a thin transport envelope. Forward work, scheduled **after**
the encryption decomposition and fact-family cleanup (both landed).

This plan was reviewed against the code by an external pass; the corrections
from that review are folded in below.

## Motivation

The `transport` scope carries three smells:

- `transport/transit/` presents itself as a fact family but is not one — it has
  `create.rs`, `frame.rs`, `layout.rs`, `receive.rs` and no `fact.rs`,
  `project.rs`, or `rows.rs`. It is frame-codec machinery.
- `transit/receive.rs` is a ~670-line procedural admission switch that imports
  every other scope (`connection`, `content`, `encryption`, `identity`,
  `sync`) — a cross-scope hub.
- Once the codec moves out and `receive.rs` is decomposed, what remains of
  `transport` is one provenance fact and three intents — too thin to be its own
  scope, and all of it is really the data plane of a connection.

## Principle

**Transit is an envelope; facts are the payload.** The goal is to shrink
transit's protocol surface, not to pretend it has none. Two things are
irreducibly protocol-specific and stay protocol-side: opening a sealed frame
(decryption is connection policy) and deciding how an opened inner fact is
admitted (scope, timestamp, allowlist). What *can* become generic is the inner
loop: once a frame is opened, admitting each inner fact should be a uniform,
table-driven step rather than a hand-written switch.

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
  transit_received/        receive-provenance fact family (kept; see Naming)
  create_response.rs            handshake intents
  send_bootstrap_request.rs
  receive_network_frame.rs      inbound boundary — classifies + opens + admits
  send_facts_on_connection.rs   batch + seal + emit network sends
  send_network_frame.rs         pure socket IO, opaque bytes
```

### Naming

Keep the family module name `transit_received`. Renaming it to `received_frame`
is cosmetic, and the durable context role string `"transport_transit_received"`
(awaited by `connection::request` and `connection::response` projectors) would
then need a migration or re-projection. Not worth it — rename nothing durable.

## Inbound: classify, open, then admit generically

`transit/receive.rs` is decomposed, but the inbound path is **not** uniformly
"unframe via core, route by tag." There are two inbound byte streams and they
differ:

- **Bootstrap frames** — connection request/response bytes sent *raw* over
  `core::network` (see `send_bootstrap_request.rs`, `create_response.rs`).
  Classified by first byte today.
- **Sealed transit frames** — the steady-state data plane. The outer header
  exposes only sender, receiver, connection id, nonce, size class, and
  ciphertext; **inner fact tags are encrypted**. Opening requires peeking the
  connection id, loading the connection fact, decrypting with the
  `connection_secret`, and validating endpoints.

So the inbound intent handler (`receive_network_frame`) does three steps:

1. **Classify** the inbound bytes — bootstrap vs sealed frame.
2. **Open** — for a sealed frame, the connection-specific decrypt/validate; for
   bootstrap, the connection-specific raw decode. Both are connection policy and
   stay in `connection`.
3. **Admit** each opened inner fact — this step *is* made generic.

### A protocol-owned inbound admission registry

The existing `FACT_ROUTES` table (`{tag → projector}`) cannot drive admission:
it routes facts that are *already* in the store, and a `Fact`'s `FactScope` and
timestamp are local metadata not present until insertion (`INSERT OR IGNORE`,
first write wins). Generic admission therefore needs a **new** protocol-owned
table, separate from `FACT_ROUTES`: per inbound-admissible fact tag, a function
that decodes the opened payload and yields `(scope, timestamp, accept/reject)`.
Each fact family declares its own admission entry, next to its projector
registration. `receive_network_frame` consults this table and imports no other
scope — the per-scope knowledge lives with each family, not in transit.

This registry is the real deliverable that replaces the 670-line switch.

## Frame codec: generic primitives to `core`, protocol header stays

Do **not** move the whole transit codec into `core::wire` — `core::wire` must
not know protocol tags, payload structs, crypto, or semantic ranges. Transit's
frame carries a `TRNS` protocol tag, binds connection/endpoint ids into the AEAD
associated data, and enforces sendability (importing connection, identity,
encryption). Split it:

- **To `core`** — only genuinely generic primitives: fixed-size frame buffers
  for the two size classes, and the encrypted-bundle (AEAD seal/open) helper as
  a tag-agnostic primitive.
- **Stays in `connection`** — the transit frame header (`TRNS` tag, endpoint/
  connection ids), the AAD binding, sendability rules, and admission.

## Send stays two intents

`send_facts_on_connection` and `send_network_frame` remain **separate**:

- **Fan-out.** One `send_facts_on_connection` batches facts under the
  frame-size limit and emits *N* `send_network_frame`s.
- **Durability class.** `send_network_frame` is ephemeral best-effort IO that
  must not become durable protocol state; `send_facts_on_connection` is the
  durable decision that facts must reach the peer.
- **Idempotence dimension.** Keyed by (connection, fact-ids/range) vs
  (routing-key, frame-hash).
- **Retry granularity.** A route-missing failure retries only the socket write,
  not load/batch/seal.
- **Opaque-bytes IO waist.** `send_network_frame` resolves an address and writes
  opaque bytes — the single thin boundary touching `core::network`.

### Keep sync range policy in `sync`

`send_facts_on_connection` currently expands shareable timestamp ranges via
`sync::shared_fact`, while `sync` modules emit `send_facts_on_connection`
intents. Moving the handler into `connection` as-is makes `connection` and
`sync` mutually policy-coupled. Instead: `sync` owns range expansion and emits
explicit fact-id batches; `connection` owns only batching, sealing, and
sending. The connection→sync dependency is removed, not relocated.

## Idempotence: inner facts free, provenance needs work

Inner payload facts are content-addressed, so re-admitting them from a duplicate
frame is a no-op — that part is free. But the `transit_received` provenance fact
currently embeds `received_at_local_ms`, and the `receive_*` intent key includes
it, so duplicate deliveries at different times produce distinct provenance ids
and distinct intent keys. To make duplicate receives fully idempotent, the
provenance fact and intent key must drop local receive time (or derive it
deterministically from frame content). This is a required design change, not an
automatic consequence.

## Correction: projectors do not emit facts

Facts are admitted only by intent handlers and commands; core enforces that
projectors cannot emit facts. The inbound flow is therefore: bytes arrive →
`receive_network_frame` handler classifies, opens, and **admits** inner facts →
those facts then project normally. Projectors emit only context and intents.

## Sequencing

1. Encryption scope decomposition — done.
2. Fact-family cleanup to the strict 8-file rule — done.
3. This transit / connection redesign.
4. Remove `transport/transit` and `transport/transit_received` from
   `FAMILY_FILE_RULE_EXCEPTIONS` in the boundary tests once they conform.
