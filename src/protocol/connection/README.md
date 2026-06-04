# Connection Fact Scope

Connection is the peer transport and session scope. We use it to turn invite
and bootstrap material into a local connection id, receive and open sealed
frames, record receipts for transported facts, close sessions, and ask core
networking to move opaque bytes. The scope owns request/response handshake
facts and their wire-transport seal, local handshake secrets, established frame
wrappers, receive receipts, close signals, and connection network handlers.

## Bootstrap vs Membership Connections

There are two ways to make first contact, kept as separate fact families rather
than one polymorphic request:

- **Bootstrap** (`bootstrap_request`/`bootstrap_response`) is first contact with
  an endpoint that does not know us yet. It is authorized by an **invite**: the
  request carries invite proof and the connection secret mixes invite material.
- **Membership** (`connection_request`/`connection_response`) is contact with an
  endpoint that already knows us. It is authorized by **`endpoint_shared`
  membership**: the request is signed by the initiator endpoint signing key and
  validated against the initiator's `endpoint_shared` in a workspace where the
  responder is also a member (the receiver projector parks until that membership
  syncs rather than rejecting). The connection secret is derived from
  Diffie-Hellman only — no invite material — so membership connections survive
  invite-link expiry.

Both paths derive a response id that becomes the connection id. Local lifecycle
facts record which request/response bytes were sent or received, and the
symmetric `connection_established` fact writes the shared connection-row table
keyed by that id, so established frames and sync treat bootstrap and membership
connections identically.

**Transition.** First contact is always bootstrap (the endpoint cannot validate us
yet). Bootstrap sync propagates `endpoint_shared` membership both ways plus a
learned endpoint address (`observed_endpoint_address` rows, fed from received handshake listen
addresses). After that, `choose_connection_mode` resolves to a membership
connection — mutual membership plus a learned address — so reconnects need no
invite. `connect <endpoint>` uses that trigger; `accept <invite>` is always
bootstrap by construction.

## Interface To Core

Data enters core from three places:

- connection commands and auth invite flows create local request, response,
  ephemeral-secret, and close facts;
- the daemon queues `receive_network_frame` local intents from accepted TCP
  frames;
- sync and connection handlers queue outbound frame intents.

Projection and handlers return:

- child facts opened from bootstrap or established frames;
- context offers such as `connection_ephemeral_secret`, `connection_request`,
  `bootstrap_request_sent`, `bootstrap_request_received`,
  `bootstrap_response_sent`, `bootstrap_response_received`,
  `connection_established`, `connection_response_for_request`,
  `connection_fact_receipt`, `connection_closed`, and
  `connection_ephemeral_secret_closed`;
- local and durable intents for response creation, sync seeding, fact batching,
  and socket writes.

Core owns queueing, fact storage, local-intent retry/removal, socket table
mechanics, and transaction boundaries. Connection owns packet classification,
handshake transcript checks, connection secret use, frame sealing/opening, and
which child facts may be emitted from received bytes.

## Managed Row State

Connection owns rows for connection requests, connection responses,
ephemeral handshake secrets, fact receipts, and close cleanup. These rows let
connection handlers find routes, derive send context, avoid resending to an
origin connection, and answer local CLI/status queries.

Connection rows are not the cross-scope transport contract. The reusable
interfaces are connection context roles, queued connection intents, and facts
carried inside sealed frames. Direct row reads by another scope are listed
below.

## Interfaces To Other Scopes

### Context Interface

Auth supplies local endpoint and invite-secret context. Bootstrap frame
projectors use `auth_local_endpoint`; request/response projection uses
`connection_invite_secret`, request-sent lifecycle context, and fact receipts.
Connection publishes context such as `connection_request`,
`connection_established`, `connection_response_for_request`, and
`connection_fact_receipt` so later connection projectors can validate
request/response/frame paths without direct row scans.

### Other Interfaces

Sync decides which fact ids should be sent on a connection by queuing
connection-owned send work. Connection then loads those ids, checks
sendability, batches them into frames, and sends opaque network bytes.
Connection does not decide sync visibility. Content, auth, and sync facts can
travel inside established frames only if they are non-local and not tagged as
private/local. Once opened, they are admitted as ordinary child facts and
validated by their owning projectors.

## Cross-Scope Row Reads

Sync reads connection response and request rows when it computes
connection-specific visibility and asks connection to send fact ids. Auth
workspace status/reporting code may read connection request and response rows
for local diagnostics. Other scopes should use connection context or
connection-owned intents rather than interpreting connection rows.

## Invariants And Responsibility

Local facts remain local. Ephemeral secrets, connection responses, close facts,
receive receipts, established frame wrappers, and local endpoint/private auth
facts are rejected by frame sendability checks.

First-contact handshake facts seal themselves to the recipient endpoint:
`receive_network_frame` admits the typed wire bytes, and the request/response
projector unseals them with the local endpoint secret from `auth_local_endpoint`
context (origin and local receive time recorded on the emitted `fact_receipt`).

Receipts are observational evidence. They do not authorize a request, response,
or child fact by themselves. The target projector validates that the receipt
path, local endpoint, sender endpoint, request id, connection id, and frame hash
match the target fact.

Close is also target-owned. A close fact publishes close context. The
established-connection, response, and ephemeral-secret projectors consume it and
delete/purge their own rows and facts.

## Intent Handlers

`receive_network_frame` is the inbound socket boundary. It has no input facts.
It normalizes origin metadata and admits the typed wire bytes as their fact; it
does no unsealing itself. Each sealed request/response/frame fact is unsealed by
its own projector, which gets the key from a context need (`auth_local_endpoint`
for handshake facts, `connection_established` for established frames). There is no
separate envelope fact and no inline unseal at the boundary.

`maintain_connections` drives outbound bootstrap request sends from
`bootstrap_request_sent` rows. The request command creates invite material,
initiator ephemeral material, the semantic request, and the exact sealed request
bytes in one local lifecycle fact; maintenance re-queues `send_network_frame`
for unanswered rows.

`create_bootstrap_response` is responder-side handshake work. It loads the
request, invite secret, and receive receipt, validates the invite signature and
receipt path, creates responder ephemeral material, builds the canonical
response body, and returns `bootstrap_response_sent` plus
`connection_established` facts. It sends nothing itself (flat-intent rule): the
`bootstrap_response_sent` projector emits the `send_network_frame` local intent
for the exact sealed response bytes.

`send_facts_on_connection` packages facts chosen by sync. It loads the
connection and payload facts, rejects local/private facts, batches small facts
or file slices into frame classes, seals each batch with the connection secret,
and emits local `send_network_frame` intents.

`send_network_frame` is the final outbound socket boundary. It loads the route
key, resolves the endpoint address from lifecycle or established connection
state, validates frame size, stages the opaque bytes, and retries the intent on
socket or route failure.

## Facts

### `bootstrap_request` (tag 42)

Invite-authorized semantic handshake request: the first contact with an
endpoint that does not know us yet. This fact is projected only for
received/global requests after the sealed request frame has been opened.
Projection emits `bootstrap_request_received`, offers `connection_request`,
learns the initiator's return address, and emits `create_bootstrap_response`
once invite, local endpoint, and receipt context validate. Local outbound
request state lives in `bootstrap_request_sent`.

```text
request {
  from_endpoint: x25519:alice_phone
  to_endpoint: x25519:bob_laptop
  nonce: nonce:request
  invite_fact_id: fact:user_invite_alice
  bootstrap_hash: blake3:invite_secret_hash
  invite_signature: sig(invite_secret)
  invite_secret_fact_id: fact:invite_secret_scoped
  initiator_ephemeral_secret_fact_id: fact:ephemeral_alice
  initiator_ephemeral_public_key: x25519:alice_ephemeral
  from_listen_addr: "203.0.113.10:41000"
  to_listen_addr: "198.51.100.20:41000"
}
```

### `ephemeral_secret` (tag 43)

Local X25519 handshake secret. Projection requires local scope and public/private
key consistency, writes `connection_ephemeral_secret_rows`, offers
`connection_ephemeral_secret`, and deletes/purges itself when close context
names it.

```text
ephemeral_secret {
  owner_endpoint: x25519:alice_phone
  ephemeral_private_key: secret:x25519_ephemeral_private
  ephemeral_public_key: x25519:alice_ephemeral
  created_at_ms: 1715000001000
}
```

### `bootstrap_response` (tag 44)

Local semantic response answering a `bootstrap_request` on the initiator side.
Projection validates exact `bootstrap_request_sent`, invite, receipt, and
initiator ephemeral-secret context, then emits `bootstrap_response_received`,
and `connection_established`. The `bootstrap_response_received` projector seeds
sync after `connection_established` context proves the live row exists. The
responder authoring path does not commit a raw local `bootstrap_response`; it
commits `bootstrap_response_sent` plus `connection_established`. Close context
purges the local response fact because it carries connection secret material.

```text
response {
  from_endpoint: x25519:bob_laptop
  to_endpoint: x25519:alice_phone
  request_id: fact:request_alice_to_bob
  invite_secret_fact_id: fact:invite_secret_scoped
  initiator_ephemeral_secret_fact_id: fact:ephemeral_alice
  responder_ephemeral_secret_fact_id: fact:ephemeral_bob
  responder_ephemeral_public_key: x25519:bob_ephemeral
  handshake_hash: blake3:handshake_transcript
  connection_secret: secret:connection_aead_key
}
```

### `close` (tag 45)

Local close signal for one connection id. Projection requires local scope and
`connection_established` context, then offers `connection_closed` for the
connection id and `connection_ephemeral_secret_closed` for both handshake
secrets.

```text
close {
  connection_id: fact:connection_id_ab
  closed_at_ms: 1715000500000
}
```

### `connection_established` (tag 178)

Symmetric local connection state created by successful response authoring on the
responder and successful response receipt on the initiator. Projection offers
`connection_established`, writes the shared live connection row keyed by
`connection_id`, and consumes `connection_closed` to delete the row and purge
itself. Response-received lifecycle projectors seed sync after this context is
available.

### `bootstrap_request_sent` (tag 179)

Local lifecycle fact for an outbound bootstrap request. It contains the semantic
request, request id, initiator ephemeral secret id, peer address, and exact
sealed request bytes. Projection offers `bootstrap_request_sent`, writes the
pending request row used by `maintain_connections`, and remembers the peer
address.

### `bootstrap_request_received` (tag 180)

Local lifecycle fact recording that a sealed bootstrap request was received and
accepted far enough to schedule responder work. Projection offers
`bootstrap_request_received`.

### `bootstrap_response_sent` (tag 181)

Local lifecycle fact for a responder-authored bootstrap response. It contains
the semantic response, response id, responder ephemeral secret id, peer address,
and exact sealed response bytes. Projection offers `bootstrap_response_sent` and
emits one `send_network_frame` local intent keyed by this lifecycle fact.

### `bootstrap_response_received` (tag 182)

Local lifecycle fact recording that a sealed bootstrap response was received and
accepted far enough to establish the connection. Projection offers
`bootstrap_response_received`, needs matching `connection_established` context,
and emits `seed_connection_sync` once the live row is available.

### Fact sealing (each fact seals itself; unseal is a context need)

Sealing is a property of the fact type, not a runtime mode: each connection wire
fact seals itself in its own layout, and there is no seal-mode and no separate
envelope fact. `create.rs` seals a fact for transit when it is generated —
handshake facts (`bootstrap_request`, `connection_request`, the connection
response) are sealed asymmetrically to the recipient endpoint, and established
frames are sealed with the connection secret. On receipt the typed wire bytes
are admitted and a receiving projector unseals it with the key from a context
need — `auth_local_endpoint` (the local endpoint secret) for handshake facts,
`connection_established` (the connection secret) for established frames — exactly as
the established-frame projector already opens frames. The receive boundary admits
the bytes and does no unsealing itself; there is no inline unseal.

### `fact_receipt` (tag 164)

Local observation record for a semantic fact received over a request, response,
or established frame path. Projection offers `connection_fact_receipt` keyed by
`received_fact_id` and writes `connection_fact_receipt_rows`.

```text
fact_receipt {
  received_fact_id: fact:message_hello
  origin_addr: "198.51.100.20:41000"
  local_endpoint_id: x25519:alice_phone
  sender_endpoint_id: x25519:bob_laptop
  receive_path: RECEIVE_PATH_CONNECTION_FRAME
  connection_id: fact:connection_response_ab
  request_id: fact:request_alice_to_bob
  frame_hash: blake3:frame_bytes
  received_at_local_ms: 1715000004000
}
```

### `frame_small` (tag 168)

Local wire fact for one established small encrypted frame. Projection needs a
matching local `frame_observation` plus the referenced local
`connection_established`, opens the frame, emits durable child facts, and emits
one receipt per child.

```text
frame_small {
  frame: bytes:TRNS_small_frame
}
```

### `frame_file_slice` (tag 169)

Local wire fact for an established frame sized for one content file-slice fact.
It uses the same projection path as `frame_small` but the frame layout has a
larger fixed ciphertext slot.

```text
frame_file_slice {
  frame: bytes:TRNS_file_slice_frame
}
```

### `frame_bundle` (tag 170)

Local wire fact for an established bundled frame. Projection opens the bundle
and admits each contained fact with a receipt.

```text
frame_bundle {
  frame: bytes:TRNS_bundle_frame
}
```

### `frame_observation` (tag 173)

Local receive metadata for one frame fact. Projection offers
`connection_frame_observation` context keyed by `frame_fact_id`; the matching
frame projector consumes that context when it needs origin and receive-time
metadata for fact receipts.

```text
frame_observation {
  frame_fact_id: fact:connection_frame_small
  origin_addr: "198.51.100.20:41000"
  received_at_local_ms: 1715000005000
}
```

## Example Fact Graph

```text
outbound initiator dependency graph:
  invite_secret + initiator ephemeral_secret
    -> bootstrap_request_sent
       rows drive maintain_connections until answered
       network output: sealed bootstrap request bytes

inbound responder transport observation:
  remote sealed request bytes
    -> receive_network_frame local intent
    -> projector unseals via auth_local_endpoint context
    -> request + fact_receipt

inbound responder dependency graph:
  request
    needs connection_invite_secret(invite_secret)
    needs auth_local_endpoint(to_endpoint)
    needs connection_fact_receipt(request)
    -> materializes connection_request
    -> create_bootstrap_response(request, invite_secret, receipt)

  create_bootstrap_response
    loads request + invite_secret + fact_receipt
    reads local endpoint state
    -> responder ephemeral_secret + bootstrap_response_sent + connection_established
  bootstrap_response_sent projector
    -> send_network_frame intent
    -> network output: sealed response bytes

inbound initiator transport observation:
  remote sealed response bytes
    -> receive_network_frame local intent
    -> projector unseals via auth_local_endpoint context
    -> response + fact_receipt

inbound initiator dependency graph:
  response
    needs bootstrap_request_sent(request_id)
    needs connection_invite_secret(invite_secret)
    needs connection_fact_receipt(response)
    needs initiator ephemeral_secret
    -> bootstrap_response_received + connection_established

connection_established
  -> live connection row

bootstrap_response_received
  needs connection_established
  -> seed_connection_sync

established connection transfer:
  sync selected facts
    -> send_facts_on_connection
    -> send_network_frame
    -> remote frame_small/frame_bundle/frame_file_slice wire fact
    -> remote frame_observation metadata fact
       need frame_observation + connection_established
       open to child facts + fact_receipts
```

Each handshake fact seals itself in its own layout; the receiving projector
unseals it with the key from a context need (`auth_local_endpoint`). The
`request`, `response`, lifecycle, and `fact_receipt` facts then carry the
dependency edges used by request and response projection. The response id is the
connection id; `connection_established` materializes the live row, and sync and
network send handlers treat that id as the routing key while semantic child
validation stays with auth, content, and sync projectors.
