# Connection Fact Scope

Connection is the peer transport and session scope. We use it to turn invite
and bootstrap material into a local connection id, receive and open sealed
frames, record receipts for transported facts, close sessions, and ask core
networking to move opaque bytes. The scope owns bootstrap wrappers,
request/response handshake facts, local handshake secrets, established frame
wrappers, receive receipts, close signals, and connection network handlers.

## Interface To Core

Data enters core from three places:

- connection commands and auth invite flows create local request, response,
  ephemeral-secret, and close facts;
- the daemon queues `receive_network_frame` local intents from accepted TCP
  frames;
- sync and connection handlers queue outbound frame intents.

Projection and handlers return:

- local row mutations for connection requests, responses, ephemeral secrets,
  receive receipts, and close cleanup;
- child facts opened from bootstrap or established frames;
- context offers such as `connection_ephemeral_secret`, `connection_request`,
  `connection_response`, `connection_response_for_request`,
  `connection_fact_receipt`, `connection_closed`, and
  `connection_ephemeral_secret_closed`;
- local and durable intents for bootstrap sends, response creation, sync
  seeding, fact batching, and socket writes.

Core owns queueing, fact storage, local-intent retry/removal, socket table
mechanics, and transaction boundaries. Connection owns packet classification,
handshake transcript checks, connection secret use, frame sealing/opening, and
which child facts may be emitted from received bytes.

## Interfaces To Other Scopes

### Context Interface

Auth supplies local endpoint and invite-secret context. Bootstrap frame
projectors use `auth_daemon_endpoint`; request/response projection uses
`connection_invite_secret` and `auth_local_endpoint`. Connection publishes
context such as `connection_request`, `connection_response`,
`connection_response_for_request`, and `connection_fact_receipt` so later
connection projectors can validate request/response/frame paths without direct
row scans.

### Other Interfaces

Sync decides which fact ids should be sent on a connection by queuing
connection-owned send work. Connection then loads those ids, checks
sendability, batches them into frames, and sends opaque network bytes.
Connection does not decide sync visibility. Content, auth, and sync facts can
travel inside established frames only if they are non-local and not tagged as
private/local. Once opened, they are admitted as ordinary child facts and
validated by their owning projectors.

## Invariants And Responsibility

Local facts remain local. Ephemeral secrets, connection responses, close facts,
receive receipts, bootstrap receive wrappers, established frame wrappers, and
local endpoint/private auth facts are rejected by frame sendability checks.

Bootstrap wrappers are receive-side bridge facts. They preserve raw sealed
bytes, origin, and local receive time; projection opens them with local endpoint
context and emits semantic request/response facts plus receipts.

Receipts are observational evidence. They do not authorize a request, response,
or child fact by themselves. The target projector validates that the receipt
path, local endpoint, sender endpoint, request id, connection id, and frame hash
match the target fact.

Close is also target-owned. A close fact publishes close context. The response
and ephemeral-secret projectors consume it and delete/purge their own rows and
facts.

## Intent Handlers

`receive_network_frame` is the inbound socket boundary. It has no input facts.
It normalizes origin metadata, classifies the raw frame as sealed bootstrap
request, sealed bootstrap response, or established connection frame, and emits
local receive-wrapper facts.

`send_bootstrap_connection_request` sends a sealed pre-connection request. It
loads the request and initiator ephemeral secret, proves the secret matches the
request, seals the request bytes, stages them through core networking, and
attempts one TCP write. Failed connection attempts are consumed; retry timing is
owned by request projection time wakes.

`create_connection_response` is responder-side handshake work. It loads the
request, invite secret, and receive receipt, validates the invite signature and
receipt path, creates responder ephemeral material, builds the canonical local
response fact, sends a sealed bootstrap response, and returns the responder
ephemeral fact plus response fact.

`send_facts_on_connection` packages facts chosen by sync. It loads the
connection and payload facts, rejects local/private facts, batches small facts
or file slices into frame classes, seals each batch with the connection secret,
and emits local `send_network_frame` intents.

`send_network_frame` is the final outbound socket boundary. It loads the
connection fact, resolves the peer address from the original request and local
endpoint, validates frame size, stages the opaque bytes, and retries the intent
on socket or route failure.

## Facts

### `request` (tag 42)

Semantic handshake request. Local requests are outbound work and may schedule
bootstrap send retries until a response arrives. Global requests are received
bootstrap requests and emit `create_connection_response` once invite, endpoint,
and receipt context validate. Both branches write `connection_request_rows` and
offer `connection_request`.

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

### `response` (tag 44)

Local connection fact. Projection validates request, invite, receipt, and
ephemeral-secret context, writes `connection_response_rows`, offers
`connection_response` and `connection_response_for_request`, and emits
`seed_connection_sync` for received responses. Close context deletes/purges the
response.

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

Local close signal for one connection response fact. Projection requires local
scope and `connection_response` context, then offers `connection_closed` for
the response and `connection_ephemeral_secret_closed` for both handshake
secrets.

```text
close {
  connection_id: fact:connection_response_ab
  closed_at_ms: 1715000500000
}
```

### `bootstrap_request` (tag 171)

Local receive wrapper for one sealed bootstrap request frame. Projection needs
the daemon endpoint, opens the sealed bytes, and emits a global `request` fact
plus a local `fact_receipt`.

```text
bootstrap_request {
  origin_addr: "198.51.100.20:41000"
  received_at_local_ms: 1715000002000
  sealed_request_frame: bytes:sealed_connection_request
}
```

### `bootstrap_response` (tag 172)

Local receive wrapper for one sealed bootstrap response frame. Projection needs
the daemon endpoint, opens the sealed bytes, and emits a local `response` fact
plus a local `fact_receipt`.

```text
bootstrap_response {
  origin_addr: "198.51.100.20:41000"
  received_at_local_ms: 1715000003000
  sealed_response_frame: bytes:sealed_connection_response
}
```

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

Local receive wrapper for one established small encrypted frame. Projection
needs the referenced local connection response, opens the frame, emits durable
child facts, and emits one receipt per child.

```text
frame_small {
  origin_addr: "198.51.100.20:41000"
  received_at_local_ms: 1715000005000
  frame: bytes:TRNS_small_frame
}
```

### `frame_file_slice` (tag 169)

Local receive wrapper for an established frame sized for one content file-slice
fact. It uses the same projection path as `frame_small` but the frame layout
has a larger fixed ciphertext slot.

```text
frame_file_slice {
  origin_addr: "198.51.100.20:41000"
  received_at_local_ms: 1715000006000
  frame: bytes:TRNS_file_slice_frame
}
```

### `frame_bundle` (tag 170)

Local receive wrapper for an established bundled frame. Projection opens the
bundle and admits each contained fact with a receipt.

```text
frame_bundle {
  origin_addr: "198.51.100.20:41000"
  received_at_local_ms: 1715000007000
  frame: bytes:TRNS_bundle_frame
}
```

## Example Fact Graph

```text
outbound initiator dependency graph:
  invite_secret + initiator ephemeral_secret
    -> local request
       needs connection_response_for_request until answered
       time wake -> send_bootstrap_connection_request
       network output: sealed bootstrap request bytes (not a fact)

inbound responder transport observation:
  remote sealed bootstrap request bytes (not a fact)
    -> receive_network_frame local intent
    -> bootstrap_request local wrapper
       needs auth_daemon_endpoint
       opens to request + fact_receipt

inbound responder dependency graph:
  request
    needs connection_invite_secret(invite_secret)
    needs auth_local_endpoint(to_endpoint)
    needs connection_fact_receipt(request)
    -> materializes connection_request
    -> create_connection_response(request, invite_secret, receipt)

  create_connection_response
    loads request + invite_secret + fact_receipt
    reads local endpoint state
    -> responder ephemeral_secret + local response
    -> network output: sealed bootstrap response bytes (not a fact)

inbound initiator transport observation:
  remote sealed bootstrap response bytes (not a fact)
    -> receive_network_frame local intent
    -> bootstrap_response local wrapper
       needs auth_daemon_endpoint
       opens to response + fact_receipt

inbound initiator dependency graph:
  response
    needs connection_request(request_id)
    needs connection_invite_secret(invite_secret)
    needs connection_fact_receipt(response)
    needs initiator ephemeral_secret
    -> materializes connection_response
    -> seed_connection_sync

established connection transfer:
  sync selected facts
    -> send_facts_on_connection
    -> send_network_frame
    -> remote frame_small/frame_bundle/frame_file_slice wrappers
       need connection_response
       open to child facts + fact_receipts
```

The sealed bootstrap request/response bytes are transport observations, not
facts in the dependency graph. The local bootstrap wrapper facts preserve those
bytes until endpoint context can open them. After opening, the semantic
`request`, `response`, and `fact_receipt` facts carry the dependency edges used
by request and response projection. The connection response fact is the
connection id; sync and network send handlers treat that id as the routing key,
while semantic child validation stays with auth, content, and sync projectors.
