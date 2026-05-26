# Auth Fact Scope

Auth facts define the authority graph for a workspace and the local key
material this store may use. The scope owns workspace identity, user identity,
admin grants, invite paths, endpoint membership, recipient keys, removal
frontiers, key-wrap production, key-wrap recovery, and local-only secrets.

The examples below are decoded plaintext shapes. On disk and on the wire each
fact is a fixed binary layout beginning with its type tag; `FactScope` and the
local admission timestamp live in core metadata and are not part of the fact
body.

## Interface To Core

Data enters core as immutable facts returned by auth commands, by auth intent
handlers, or by connection/sync receive paths. Core stores the bytes, assigns
the BLAKE3 fact id, and routes projection by the first-byte type tag registered
in `protocol::registry`.

Data leaves auth projection as:

- row mutations for auth read models and private local material rows;
- context offers such as `auth_workspace`, `auth_user`, `auth_admin`,
  `auth_user_invite`, `auth_device_invite`, `auth_invite_server`,
  `auth_endpoint_shared`, `content_signer`, `auth_local_endpoint`,
  `auth_daemon_endpoint`, `auth_invite_secret`, `connection_invite_secret`,
  `local_signer_secret`, `recipient_key`, `auth_removal_frontier`,
  `wrap_source`, `local_recipient_key`, `local_secret_source`,
  `secret_coverage`, and `local_secret_source_retired`;
- context needs for the same authority graph;
- `share_fact_with_sync`, `create_key_wrap`, and `unwrap_key_wrap` intents;
- derived local facts, especially key-wrap output and unwrapped local secrets.

Core preserves atomicity and replacement. Each projector emits the complete
current needs/offers for its fact; core replaces the previous set and commits
rows, facts, and intents in the same transaction. Auth projectors own all
semantic checks: core never decides whether a user is an admin, whether a
signer may author content, or whether a key wrap is decryptable.

## Interfaces To Other Scopes

Content consumes `content_signer`, `auth_user`, `auth_admin`, and
`secret_coverage` context. It treats auth rows and context as proof that a
message, reaction, file, deletion, or retention policy can be admitted.

Connection consumes local endpoint context and invite-secret context. The
daemon endpoint offer lets sealed bootstrap frames open locally, and
`connection_invite_secret` authorizes bootstrap request signatures.

Sync consumes auth share contributions and auth-owned exact/key-wrap offers.
Auth projectors call the sync helper after a fact is admitted so connection
sync can advertise only facts whose own authority proof has already passed.

Auth also depends on sync for exact-fact dependency context in a few places,
for example retention/key-wrap dependency matching, but auth still validates the
matched payload before trusting it.

## Invariants And Responsibility

Global facts are peer-visible authority statements. Workspace-scoped facts are
visible only inside `FactScope::Scoped { kind: "workspace", id }`. Local facts
must never leave the store, and connection frame send code rejects their tags.

Signatures are natural signatures over canonical signing bytes. Projectors
verify the signature and the context witness that makes the signer meaningful.
A local private key fact never grants remote authority by itself; it only
publishes local context that other projectors may consume.

Key material has two surfaces. Shared facts name recipient keys, frontiers, key
requests, and encrypted wraps. Local facts hold private secrets, publish wrap
sources and secret coverage, and self-purge when retirement context names them.
Changes to key tree coordinates, wrap-source matching, or encrypted message key
coverage belong in auth key-material modules, not in content or sync.

## Intent Handlers

`create_key_wrap` is emitted by recipient-key and key-request projection after
recipient, source-secret, and local signer context are available. The handler
loads the recipient fact, source secret fact, and signer secret fact named in
the intent, validates the coordinate, builds deterministic key-wrap bytes, and
returns one `key_wrap` fact.

`unwrap_key_wrap` is emitted by key-wrap projection when a matching local
recipient key is present. The handler loads the key wrap, local recipient key,
recipient key, and frontier, decrypts the wrapped secret, validates the
resulting local secret id against the wrap coordinate, and returns either a
`local_key_secret` or `local_history_node_secret` fact.

Both handlers use the intent payload as the idempotence key source. If any input
fact is missing, core retries through the normal handler contract.

## Facts

### `workspace` (tag 131)

Creates a workspace namespace. Projection requires global scope and a valid
workspace root signature, then writes `workspace_rows`, offers
`auth_workspace`, and shares the fact with sync.

```text
workspace {
  created_at_ms: 1715000000000
  public_key: ed25519:workspace_root
  name: "Acme Lab"
  signature: sig(workspace_root)
}
```

### `user_invite` (tag 10)

Publishes an invite public key that can sign a `user` fact. Bootstrap invites
are signed by the workspace root; delegated invites are signed by an
endpoint whose user owns the named admin grant. Projection writes
`user_invite_rows`, offers `auth_user_invite`, and shares the fact.

```text
user_invite {
  created_at_ms: 1715000000100
  public_key: ed25519:invite_alice
  workspace_id: fact:workspace_acme
  authority_fact_id: fact:admin_root
  signer_id: fact:endpoint_bob_laptop
  signer_public_key: ed25519:bob_laptop_signing
  signature: sig(bob_laptop_signing)
}
```

### `user` (tag 14)

Creates a user identity inside a workspace. Projection requires the signer to
be the matching `user_invite`, validates workspace and signer key, writes
`user_rows`, offers `auth_user`, and shares the fact.

```text
user {
  created_at_ms: 1715000000200
  workspace_id: fact:workspace_acme
  public_key: ed25519:alice_user
  username: "alice"
  signer_id: fact:user_invite_alice
  signer_public_key: ed25519:invite_alice
  signature: sig(invite_alice)
}
```

### `admin` (tag 139)

Grants admin authority to a public key/user in a workspace. A bootstrap grant
is signed by the workspace root and grants the root user; delegated grants are
signed by a prior admin and target an existing user. Projection writes
`admin_rows`, offers `auth_admin`, and shares the fact.

```text
admin {
  created_at_ms: 1715000000300
  workspace_id: fact:workspace_acme
  public_key: ed25519:alice_user
  authority_fact_id: fact:admin_root
  user_fact_id: fact:user_alice
  signer_id: fact:admin_root
  signer_public_key: ed25519:workspace_root
  signature: sig(workspace_root)
}
```

### `device_invite` (tag 134)

Authorizes an endpoint-shared device binding. A user-signed device invite
points back to the `user_invite` that admitted the user; an endpoint-signed
invite omits that field and uses an already trusted endpoint for the same user.
Projection writes `device_invite_rows`, offers `auth_device_invite`, and shares
the fact.

```text
device_invite {
  created_at_ms: 1715000000400
  workspace_id: fact:workspace_acme
  user_authority_fact_id: fact:user_alice
  user_invite_fact_id: fact:user_invite_alice
  public_key: ed25519:alice_phone_invite
  signer_id: fact:user_alice
  signer_public_key: ed25519:alice_user
  signature: sig(alice_user)
}
```

### `endpoint_shared` (tag 135)

Binds an endpoint id and signing key to a workspace/user. Device endpoints
require `device_invite`; invite-server endpoints require `invite_server`.
Projection writes `auth_endpoint_shared_rows`, offers `content_signer` under
the workspace scope and `auth_endpoint_shared` globally, and shares the fact.

```text
endpoint_shared {
  created_at_ms: 1715000000500
  workspace_id: fact:workspace_acme
  user_authority_fact_id: fact:user_alice
  endpoint_id: x25519:alice_phone
  signing_public_key: ed25519:alice_phone_signing
  endpoint_role: Device
  device_name: "Alice phone"
  signer_id: fact:device_invite_alice_phone
  signer_public_key: ed25519:alice_phone_invite
  signature: sig(alice_phone_invite)
}
```

### `invite_server` (tag 136)

Publishes an invite-server public key for a workspace. Its authority path is
the same shape as `user_invite`: workspace-root bootstrap or delegated admin
endpoint. Projection writes `invite_server_rows`, offers `auth_invite_server`,
and shares the fact.

```text
invite_server {
  created_at_ms: 1715000000600
  public_key: ed25519:invite_server_key
  workspace_id: fact:workspace_acme
  authority_fact_id: fact:admin_alice
  signer_id: fact:endpoint_alice_laptop
  signer_public_key: ed25519:alice_laptop_signing
  signature: sig(alice_laptop_signing)
}
```

### `invite_secret` (tag 129)

Stores the local bootstrap secret behind an invite link. Projection requires
local scope, validates the hash/scope pairing, writes `invite_secret_rows`, and
offers both `auth_invite_secret` and `connection_invite_secret`.

```text
invite_secret {
  bootstrap_hash: blake3:bootstrap_secret_hash
  bootstrap_secret: secret:invite_private_seed
  workspace_id: fact:workspace_acme
  invite_fact_id: fact:user_invite_alice
}
```

### `invite_accepted` (tag 146)

Records local acceptance of an invite link. Projection requires local scope and
a matching scoped `invite_secret`, then writes `invite_accepted_rows`.

```text
invite_accepted {
  workspace_id: fact:workspace_acme
  invite_fact_id: fact:user_invite_alice
  invite_secret_fact_id: fact:scoped_invite_secret
  bootstrap_hash: blake3:bootstrap_secret_hash
  accepted_endpoint_id: x25519:alice_phone
}
```

### `endpoint` (tag 128)

Stores this device's local X25519 and Ed25519 private material. Projection
requires local scope, re-derives public keys from private keys, writes the
local endpoint rows, and offers `auth_local_endpoint` plus the singleton
`auth_daemon_endpoint`.

```text
endpoint {
  endpoint: x25519:alice_phone
  secret: secret:x25519_private
  signing_public_key: ed25519:alice_phone_signing
  signing_secret: secret:ed25519_private
}
```

### `local_signer_secret` (tag 133)

Stores the private signing key for one local signer id. Projection requires
local scope and offers `local_signer_secret` under the workspace scope.

```text
local_signer_secret {
  workspace_id: fact:workspace_acme
  signer_id: fact:endpoint_alice_laptop
  public_key: ed25519:alice_laptop_signing
  private_key: secret:alice_laptop_signing_private
}
```

### `recipient_key` (tag 150)

Publishes the current X25519 recipient public key for an endpoint. Projection
requires workspace scope, signer context, and optional supersession context.
It offers `recipient_key`, marks the previous key as `recipient_superseded`,
shares the fact, and may emit `create_key_wrap` for live wrap sources.

```text
recipient_key {
  workspace_id: fact:workspace_acme
  endpoint_id: fact:endpoint_alice_laptop
  recipient_key: x25519:alice_recipient_v2
  previous_recipient_key_id: fact:recipient_key_v1
  created_at_ms: 1715000000700
  signer_public_key: ed25519:alice_laptop_signing
  signature: sig(alice_laptop_signing)
}
```

### `local_recipient_key` (tag 156)

Stores the local private key matching a shared `recipient_key`. Projection
requires local scope and a matching shared recipient fact. It offers
`local_recipient_key` while live and self-purges when recipient supersession
context appears.

```text
local_recipient_key {
  workspace_id: fact:workspace_acme
  recipient_key_id: fact:recipient_key_v2
  recipient_key: x25519:alice_recipient_v2
  recipient_secret: secret:x25519_recipient_private
}
```

### `removal_frontier` (tag 151)

Names the endpoint that owns a workspace key frontier. Projection requires
workspace scope and either endpoint-shared signer context or local signer
context for the owner endpoint. It offers `auth_removal_frontier` and shares
the fact.

```text
removal_frontier {
  workspace_id: fact:workspace_acme
  owner_endpoint_id: fact:endpoint_alice_laptop
  created_at_ms: 1715000000800
  signer_public_key: ed25519:alice_laptop_signing
  signature: sig(alice_laptop_signing)
}
```

### `local_key_secret` (tag 152)

Stores the local root secret for a removal frontier. Projection requires local
scope, validates the frontier owner, offers frontier-root `wrap_source`,
`local_secret_source`, and full-range `secret_coverage`, and self-purges on
retirement context.

```text
local_key_secret {
  workspace_id: fact:workspace_acme
  frontier_id: fact:frontier_alice
  owner_endpoint_id: fact:endpoint_alice_laptop
  created_at_ms: 1715000000900
  key_secret: secret:xchacha20_root
}
```

### `local_history_node_secret` (tag 153)

Stores a derived local secret for a time/key-tree node below a frontier.
Projection validates the frontier, source secret, optional tombstone, and
coordinate shape. It offers history-node `wrap_source`, `local_secret_source`,
and bounded `secret_coverage`; tombstone nodes also emit retirement context for
the replaced source path node.

```text
local_history_node_secret {
  workspace_id: fact:workspace_acme
  frontier_id: fact:frontier_alice
  owner_endpoint_id: fact:endpoint_alice_laptop
  source_secret_id: fact:local_key_secret_root
  range_start: 28583333
  range_width: 1
  bit_depth: 256
  fact_id_prefix: fact:message_hash_prefix
  tombstone_node_id: zero
  node_secret: secret:xchacha20_leaf
}
```

### `key_request` (tag 154)

Asks a frontier owner to produce a key wrap for a requester recipient key.
Projection requires workspace scope, requester signer context, recipient-key
context, frontier context, and matching wrap-source context. When a local
signer secret is available it emits `create_key_wrap`.

```text
key_request {
  workspace_id: fact:workspace_acme
  requester_endpoint_id: fact:endpoint_alice_phone
  responder_endpoint_id: fact:endpoint_alice_laptop
  frontier_id: fact:frontier_alice
  recipient_key_id: fact:recipient_key_phone
  created_at_ms: 1715000001000
  signer_public_key: ed25519:alice_phone_signing
  signature: sig(alice_phone_signing)
}
```

### `key_wrap` (tag 155)

Carries deterministic encrypted key material for one recipient and one source
secret coordinate. Projection requires workspace scope, signer, recipient, and
frontier context. It writes `key_wrap_rows`, offers `sync_exact_fact` and
`sync_key_wrap`, shares the fact, and emits `unwrap_key_wrap` if local recipient
material exists.

```text
key_wrap {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000001100
  signer_endpoint_id: fact:endpoint_alice_laptop
  frontier_id: fact:frontier_alice
  wrapped_secret_kind: HistoryNode
  wrapped_secret_id: fact:local_history_node_leaf
  wrapped_source_secret_id: fact:local_key_secret_root
  wrapped_tombstone_node_id: zero
  range_start: 28583333
  range_width: 1
  bit_depth: 256
  fact_id_prefix: fact:message_hash_prefix
  recipient_key_id: fact:recipient_key_phone
  sender_wrap_public_key: x25519:deterministic_sender_key
  nonce: nonce:wrap_nonce
  ciphertext: bytes:wrapped_secret
}
```

### `local_secret_retirement` (tag 157)

Records local policy that a secret source should retire. Projection requires
local scope and the target `local_secret_source` context, validates the target
workspace, and offers `local_secret_source_retired`. The target secret projector
owns row deletion and self-purge.

```text
local_secret_retirement {
  workspace_id: fact:workspace_acme
  target_secret_id: fact:local_key_secret_root
  reason_kind: RETIRE_REASON_CHOP
  floor_minute: 28583330
  created_at_ms: 1715000001200
}
```

## Example Fact Graph

```text
workspace_acme
  -> user_invite_alice -> user_alice
  -> admin_root -> admin_alice
  -> device_invite_alice_phone -> endpoint_shared_alice_phone
  -> removal_frontier_alice

endpoint_shared_alice_laptop
  -> recipient_key_laptop
  -> removal_frontier_alice

removal_frontier_alice
  -> local_key_secret_root
  -> local_history_node_leaf
  -> key_wrap_for_phone

recipient_key_phone + key_wrap_for_phone + local_recipient_key_phone
  -> unwrap_key_wrap intent
  -> local_history_node_secret_phone
```

In this graph, shared facts establish workspace authority and recipient
coordinates. Local facts provide private capability. Sync may advertise the
shared facts and key wraps, but it must never advertise the local endpoint,
signer, recipient secret, or key secret facts.
