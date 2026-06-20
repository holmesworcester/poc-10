# Auth Fact Scope

Auth is the workspace authority and local key-material scope. We use it to
decide who can act in a workspace, which endpoint or signer is trusted, which
recipient keys can receive wrapped content keys, and which local secrets may
decrypt or wrap data. The scope owns workspace identity, users, admin grants,
invite paths, endpoint membership, recipient keys, removal frontiers, key-wrap
production/recovery, and local-only secrets.

## Interface To Core

Data enters core as immutable facts returned by auth commands, emitted by
projection, or received through connection/sync paths. Core stores the bytes,
assigns the [BLAKE3](https://www.blake3.io/) fact id, and routes projection by the first-byte type tag
registered in `protocol::registry`.

Data leaves auth projection as:

- context offers such as `auth_workspace`, `auth_user`, `auth_admin`,
  `auth_user_invite`, `auth_device_invite`, `auth_invite_server`,
  `auth_endpoint_shared`, `content_signer`, `auth_local_endpoint`,
  `auth_daemon_endpoint`, `auth_invite_secret`, `connection_invite_secret`,
  `local_signer_secret`, `recipient_key`, `auth_removal_frontier`,
  `wrap_source`, `local_recipient_key`, `local_secret_source`,
  `secret_coverage`, and `local_secret_source_retired`;
- context needs for the same authority graph;
- durable/local intent effects routed by the intent kinds registered for this
  protocol;
- derived local facts, especially key-wrap output and unwrapped local secrets.

Core preserves atomicity and replacement. Each projector emits the complete
current needs/offers for its fact; core replaces the previous set and commits
the emitted effects in one transaction. Auth projectors own all semantic
checks: core never decides whether a user is an admin, whether a signer may
author content, or whether a key wrap is decryptable.

## Managed Row State

Auth owns rows that describe workspace authority, membership, invites,
endpoint membership, recipient keys, removal frontiers, key wraps, and local
private material. Shared rows such as workspace, user, admin, user-invite,
endpoint-shared, recipient-key, removal-frontier, and key-wrap rows support
auth queries and CLI output. Local rows such as endpoint secret, local
signer, local recipient key, local key secret, local history node, invite
secret, and secret-retirement rows are private store state.

These rows are materialized outputs owned by auth. They are not cross-scope
egress by themselves; cross-scope admission should use facts and context unless
the explicit row-read boundary below names the read.

## Interfaces To Other Scopes

### Context Interface

Auth's primary cross-scope interface is context. Content consumes
`content_signer`, `auth_user`, `auth_admin`, and `secret_coverage` offers as
bounded proof that a message, reaction, file, deletion, or retention policy can
continue projection. Connection consumes `auth_daemon_endpoint`,
`auth_local_endpoint`, and `connection_invite_secret`; those offers let sealed
bootstrap frames open locally and let request/connection projection validate
invite signatures.

Auth can consume sync-owned `sync_exact_fact` context when an auth projector is
waiting for a named fact that arrived through replication. Auth publishes
`sync_key_wrap` from accepted concrete `key_wrap` facts, so key-wrap
availability for auth wraps is an auth offer, not a sync-owned offer. These
contexts are only wake/proof locators: auth still decodes and validates the
matched payload before trusting it.

### Other Interfaces

Auth projectors enqueue sync-owned `share_fact_with_sync` intents after a fact
is admitted so connection sync can advertise only facts whose own authority
proof has already passed. When projection consumes validated context, auth
passes those dependency fact ids as the same projector-supplied `context_have`
graph used by other scopes. Sync records that graph without interpreting auth
semantics. Connection and sync may transport auth facts as ordinary fact bytes,
but auth admission still happens only when the owning auth projector runs.

## Cross-Scope Row Reads

Content command and CLI code reads auth workspace, user, admin,
endpoint-shared, and local endpoint rows for user-facing preflight and display.
Those reads do not replace projector admission; received or shared content
still validates auth context. Connection response creation reads the local
endpoint row when building a responder-side response. Sync visibility code reads
auth endpoint-shared rows to decide which shareable facts are visible to a
connection peer.

## Invariants And Responsibility

Global facts are peer-visible authority statements. Workspace-scoped facts are
visible only inside `FactScope::Scoped { kind: "workspace", id }`. Local facts
must never leave the store, and connection frame send code rejects their tags.

Signatures are represented by separate `auth::signature` evidence facts over
canonical target fact ids. Projectors for signer-bearing shared facts first
wait for matching `signature_proof` context, then validate the context witness
that makes the signer meaningful. A local private key fact never grants remote
authority by itself; it only publishes local context that commands can use to
create signature evidence and that projectors may consume.

Key material has two surfaces. Shared facts name recipient keys, frontiers, key
requests, and encrypted wraps. Local facts hold private secrets, publish wrap
sources and secret coverage, and self-purge when retirement context names them.
Changes to key tree coordinates, wrap-source matching, or encrypted message key
coverage belong in auth key-material modules, not in content or sync.

## Authority And Key Material Model

Auth combines workspace identity, endpoint authority, signature-evidenced facts,
recipient public keys, removal frontiers, deterministic key wraps, and local
secret material because those facts form one proof boundary: who can act in a
workspace and what this store is allowed to open or share for that authority.
Content retention and deletion live in `protocol::content`; they interact with
auth keys by emitting purge context that auth projectors can range-match.

### Signature Evidence

Signer-bearing shared facts store signer identity fields, not embedded
signature bytes. Commands emit the target fact and an `auth::signature` fact
that points at the target. The signature projector verifies the signature over
`workspace_id || target_fact_id` and offers `signature_proof(target_fact_id,
signer_public_key)`. Target projectors consume that proof before they validate
workspace, user, admin, endpoint, or invite authority.

```text
signature {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000000100
  target_fact_id: fact:user_invite_alice
  signer_public_key: ed25519:bob_laptop_signing
  signature: ed25519_signature(workspace_acme, user_invite_alice)
}
```

### Fact Family Roles

Auth fact families are grouped by protocol role:

- `workspace` creates the shared namespace for users, endpoints, content, and
  sync.
- `user`, `admin`, `user_invite`, `device_invite`, and `invite_server` form
  shared authority edges for joining and granting workspace authority.
  `invite_secret` (the creator-side local bootstrap secret) and
  `invite_accepted` (the local retained acceptance edge that selects which
  workspace roots this store admits) are local edges.
- `endpoint` and `endpoint_shared` hold local and shared endpoint identity
  material.
- `removal_frontier` names a content-key frontier and its owner.
- `recipient_key` publishes a shared endpoint public key for receiving wraps.
- `local_recipient_key` stores private material paired with one recipient key.
- `key_wrap` is a deterministic shared fact wrapping either a frontier root or
  retained history-node secret to one recipient key. Its integrity comes from
  deterministic coordinate validation and AEAD associated data, not a natural
  signature.
- `key_request` asks an authorized responder for missing key material for one
  frontier.
- `local_key_secret` stores a local opened frontier/root secret.
- `local_history_node_secret` stores a local retained node in the time/trie key
  tree.

Content facts name their frontier, minute, and target fact coordinate in their
encrypted fields. Deletion, expiry, and retention-floor facts make content
unavailable and wake key-purge behavior by publishing content-owned purge
context; they are not auth fact families.

### Content Key Tree

Each frontier has one root secret. Content derives per-message or per-file leaf
keys by walking a deterministic tree:

```text
frontier root -> time node -> in-minute trie node -> content leaf
```

The target coordinate is recoverable from canonical fact fields, so peers can
describe what key coverage they need without decrypting the content first.
Retained history-node secrets let a peer keep decrypting surviving content
after the root and a deleted descendant path have been purged.

Projection represents this with context:

- encrypted content emits a need for secret coverage over its frontier, minute,
  and target coordinate;
- local key material emits offers for the coverage it can derive;
- coverage matching wakes encrypted content when a root, retained node, or leaf
  covers the requested coordinate.

### Key Wraps

Wraps are deterministic and idempotent for a wrap edge:

```text
workspace
frontier
recipient_key
source key material
source coordinate
```

The wrap identity does not include request entropy. A duplicate request
for the same edge converges on the same pending wrap or fact, preventing key
amplification.

Generated wraps use the source fact time. Root wraps use frontier/root source
time; retained-node wraps use the retained node source time. Request time may
be recorded separately as provenance, but it does not affect wrap identity.

### Proactive Sharing

Learning a current recipient key proactively creates deterministic wraps for
current eligible sources, usually before the recipient asks. This makes the
initial share and the key-request response the same operation: materialize the
deterministic wrap edge if authorized and absent.

Superseded recipient keys do not receive old frontiers. Their standing needs
are replaced by supersession cleanup, not by more wrap requests.

### Key Requests

Key requests are facts, not transport privileges. The request projector
validates:

- the requester matches the recipient key being served;
- the responder owns the requested frontier or retained source;
- the requested recipient, frontier, and source all belong to the same
  workspace;
- the source is still shareable: root if available, retained nodes if the root
  has been purged.

For a partitioned valid member joining after deletion, the responder cannot
share a purged root. It wraps all retained path nodes needed to cover surviving
content in the requested frontier.

### Forward Secrecy And Recipient Rotation

When deletion, expiry, or floor advancement purges a frontier root or makes it
unavailable for future sharing, recipient keys rotate. This prevents peers from
continuing to wrap new material to a key that may have been exposed before the
root was retired.

Local private material for a superseded recipient key is purged by exact
supersession proof. Shared superseded public keys remain as context so peers can
reason about why old wraps stopped.

Forward secrecy here is post-compromise secrecy for retired content: after the
retirement transaction commits, remaining local disk state is not enough to
derive the retired leaf. It does not erase plaintext or keys an attacker saw
before retirement.

### Disappearing Messages And Purge

Disappearing content has semantic expiry and floor facts. Those facts wake
content projection and purge handlers through context offers. Late arrivals do
not retroactively change message expiry; content facts keep the retention
policy coordinate they were authored under.

Purge is event-centric:

- semantic deletion, expiry, and floor facts authorize removal;
- projectors emit deterministic purge intents once proof is present;
- purge handlers perform bounded physical deletion of canonical bytes or local
  secret material;
- purge does not authorize remote erasure; it removes only local retained
  material after durable semantic facts preserve what peers need to know.

Deleting one event that used a recipient wrap is a natural trigger for pruning
obsolete recipient key material and stale wrap relevance. Core key correctness
comes from facts, context, projectors, and bounded handlers rather than a
time-only cleanup path.

### Open Content

Opening encrypted content is projector work when all inputs are provided as
context and the operation is deterministic: validate content-message signature
evidence and signer context, find covering local key material, derive or
validate the leaf, decrypt the encrypted fields, and emit opened rows via row
mutations.

Message rows are materialized only after signer, author, and key context let the
projector decrypt the encrypted fields. Message deletion facts materialize their
signed deletion claim independently, and the target message validates that claim
before self-deleting. Files and reactions still depend on opened message
context.

If opening requires broad scans, IO, clock reads, or external mutation, that
step belongs in a bounded intent/handler, not in a generic opening worker.

## Local Key-Wrap Work Facts

`key_wrap_creation` is emitted by recipient-key and key-request projection after
recipient, source-secret, and local signer context are available. It is a local
fact that names the exact recipient fact, source secret fact, signer secret fact,
and wrap-source coordinate. Its projector waits for those same facts as context,
validates the coordinate, builds deterministic key-wrap bytes, and emits one
shared `key_wrap` fact.

`key_wrap_recovery` is emitted by key-wrap projection when a matching local
recipient key is present. It is a local fact that names the exact key wrap,
recipient key, frontier, and local recipient key. Its projector waits for those
facts as context, decrypts the wrapped secret, validates the resulting local
secret id against the wrap coordinate, and emits either a `local_key_secret` or
`local_history_node_secret` fact.

These work facts keep deterministic key-wrap side effects in normal projection:
missing context parks the local work fact through ordinary needs, and committed
projection output owns the resulting facts.

## Facts

### `workspace` (tag 131)

Creates a workspace namespace. Projection requires global scope, matching
workspace-root signature evidence, and local `auth_workspace_accepted` context
from `invite_accepted`, then writes `workspace_rows`, offers `auth_workspace`,
and shares the fact with sync.

The creator path uses the same fact DAG as later joins: the creation command
emits the workspace, a first `user_invite` with workspace-root signature
evidence, a local `invite_accepted` fact for that invite, the first `user`, and
a single bootstrap `admin` grant with temporary workspace-key signature
evidence. After that grant, admin authority flows only through existing admin
facts.

```text
workspace {
  created_at_ms: 1715000000000
  public_key: ed25519:workspace_root
  name: "Acme Lab"
}
```

### `user_invite` (tag 10)

Publishes an invite public key that can authorize a `user` fact. Bootstrap
invites require workspace-root signature evidence; delegated invites require
signature evidence from an endpoint whose user owns the named admin grant.
Projection writes `user_invite_rows`, offers `auth_user_invite`, and shares the
fact.

```text
user_invite {
  created_at_ms: 1715000000100
  public_key: ed25519:invite_alice
  workspace_id: fact:workspace_acme
  authority_fact_id: fact:admin_bob
  signer_id: fact:endpoint_bob_laptop
  signer_public_key: ed25519:bob_laptop_signing
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
}
```

### `admin` (tag 139)

Grants admin authority to a public key/user in a workspace. A bootstrap grant
requires workspace-root signature evidence and targets a real user who joined
through a bootstrap invite with workspace-root evidence; delegated grants
require evidence from a prior admin endpoint and target an existing user.
Projection writes `admin_rows`, offers `auth_admin`, and shares the fact.

```text
admin {
  created_at_ms: 1715000000300
  workspace_id: fact:workspace_acme
  public_key: ed25519:alice_user
  authority_fact_id: fact:workspace_acme
  user_fact_id: fact:user_alice
  signer_id: fact:workspace_acme
  signer_public_key: ed25519:workspace_root
}
```

### `device_invite` (tag 134)

Authorizes an endpoint-shared device binding. A user-authorized device invite
points back to the `user_invite` that admitted the user; an endpoint-authorized
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
}
```

### `invite_secret` (tag 129)

Stores the creator-side local bootstrap secret behind an invite link. Projection
requires local scope, validates the hash/scope pairing, writes
`invite_secret_rows` keyed by
`(bootstrap_hash, workspace_id_or_zero, invite_fact_id_or_zero)`, and offers both
`auth_invite_secret` and `connection_invite_secret`. Accepted-side replay no
longer creates a second invite-secret fact; the accepted link secret is retained
inside `invite_accepted`.

```text
invite_secret {
  bootstrap_hash: blake3:bootstrap_secret_hash
  bootstrap_secret: secret:invite_private_seed
  workspace_id: fact:workspace_acme
  invite_fact_id: fact:user_invite_alice
}
```

### `invite_accepted` (tag 146)

Records local acceptance of an invite link. Projection requires local scope,
validates the retained bootstrap secret/hash at authentication, writes
`invite_accepted_rows`, offers `connection_invite_secret` under the derived
invite-secret id, and offers `auth_workspace_accepted` only for identity-scoped
workspace links. That makes replayed facts sufficient to recover both workspace
interpretation and the bootstrap peer needed by `maintain_connections`.

```text
invite_accepted {
  workspace_id: fact:workspace_acme
  invite_fact_id: fact:user_invite_alice
  bootstrap_hash: blake3:bootstrap_secret_hash
  bootstrap_secret: secret:invite_private_seed
  accepted_endpoint_id: x25519:alice_phone
  bootstrap_endpoint_id: x25519:alice_laptop
  bootstrap_addr: "203.0.113.10:41000"
  user_authority_fact_id: null
  endpoint_role: "device"
  identity_scope: true
}
```

### `endpoint` (tag 128)

Stores this device's local [X25519](https://www.rfc-editor.org/rfc/rfc7748) and
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032) private material. Projection
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
    shares the fact, and may emit `key_wrap_creation` facts for live wrap sources.

```text
recipient_key {
  workspace_id: fact:workspace_acme
  endpoint_id: fact:endpoint_alice_laptop
  recipient_key: x25519:alice_recipient_v2
  previous_recipient_key_id: fact:recipient_key_v1
  created_at_ms: 1715000000700
  signer_public_key: ed25519:alice_laptop_signing
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
    signer secret is available it emits `key_wrap_creation`.

```text
key_request {
  workspace_id: fact:workspace_acme
  requester_endpoint_id: fact:endpoint_alice_phone
  responder_endpoint_id: fact:endpoint_alice_laptop
  frontier_id: fact:frontier_alice
  recipient_key_id: fact:recipient_key_phone
  created_at_ms: 1715000001000
  signer_public_key: ed25519:alice_phone_signing
}
```

### `key_wrap` (tag 155)

Carries deterministic encrypted key material for one recipient and one source
secret coordinate. Projection requires workspace scope, signer, recipient, and
frontier context. It writes `key_wrap_rows`, offers `sync_exact_fact` and
`sync_key_wrap`, shares the fact, and emits `key_wrap_recovery` if local
recipient material exists.

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

### `key_wrap_creation` (tag 158)

Local deterministic work to create one `key_wrap`. Projection requires local
scope and waits for the exact recipient key, local source secret, and local
signer secret named by the fact. When those proofs are present, it validates the
wrap-source coordinate and emits the shared `key_wrap` fact.

```text
key_wrap_creation {
  workspace_id: fact:workspace_acme
  frontier_id: fact:frontier_alice
  recipient_key_id: fact:recipient_key_phone
  source_fact_id: fact:local_history_node_leaf
  signer_secret_fact_id: fact:local_signer_secret_laptop
  owner_endpoint_id: fact:endpoint_alice_laptop
  frontier_created_at_ms: 1715000000800
  source: HistoryNode(range_start=28583333, range_width=1, bit_depth=256)
}
```

### `key_wrap_recovery` (tag 159)

Local deterministic work to recover one wrapped secret. Projection requires local
scope and waits for the exact accepted key wrap, recipient key, removal frontier,
and local recipient key named by the fact. When those proofs are present, it
decrypts the wrap and emits the matching local secret fact.

```text
key_wrap_recovery {
  workspace_id: fact:workspace_acme
  frontier_id: fact:frontier_alice
  recipient_key_id: fact:recipient_key_phone
  key_wrap_id: fact:key_wrap_for_phone
  local_recipient_key_id: fact:local_recipient_key_phone
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
  -> admin_bootstrap_alice -> admin_delegated_bob
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
  -> key_wrap_recovery
  -> local_history_node_secret_phone
```

In this graph, shared facts establish workspace authority and recipient
coordinates. Local facts provide private capability. Sync may advertise the
shared facts and key wraps, but it must never advertise the local endpoint,
signer, recipient secret, or key secret facts.
