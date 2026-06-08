# Content Fact Scope

Content is the workspace data scope. We use it to author, validate, display,
delete, expire, and retain messages, reactions, files, and file slices. The
scope owns encrypted user payload facts, deletion and retention policy facts,
authoring constructors, key/deletion coordinates, and the read models used by
CLI queries.

## Interface To Core

Data enters core through content commands (`send`, `react`, `send-file`,
`delete-message`, `delete-file`, and disappearing-message commands), through
connection receive paths, or through sync replay. Core stores the immutable
fact bytes and invokes the registered projector for each type tag.

Data leaves content projection as:

- context offers such as `content_message_meta`, `content_message`,
  `content_file`, generic core `fact_purged`, `content_retention_floor`,
  and `sync_exact_fact`;
- context needs for auth signer/user/admin proof, key-material coverage,
  parent content facts, deletion facts, retention floors, and time wakes;
- durable intent effects for follow-up work owned by registered protocol
  handlers;
- self-purge effects for facts whose owner row has been deleted by deletion,
  expiry, retention, or parent deletion.

Core owns idempotent storage, replacement context, time-wake scheduling, and
transactional commit. Content owns all semantic admission: scope checks,
signature-evidence checks, parent/deletion validation, encryption-key matching,
BAO proof validation, and read-model row shape.

## Managed Row State

Content owns typed rows for message metadata, opened messages, message
tombstones, reactions, file descriptors, file slices, file/message deletion
records, and retention policies. These rows are read models and local materialized
state for content commands, CLI output, and content-owned follow-up work.

Rows do not leave the content scope as an interface. Content shares facts
through sync-owned work and publishes context offers for dependency/admission
proofs; owned rows stay content state unless the explicit row-read boundary
below names the read.

## Interfaces To Other Scopes

### Context Interface

Auth provides `signature_proof`, `content_signer`, `auth_user`, `auth_admin`,
and `secret_coverage` context. Content never opens encrypted text or admits
signature-evidenced content until those witnesses match the payload. Content publishes
`content_message`, `content_message_meta`, `content_file`, generic core
`fact_purged`, and `content_retention_floor` context so child content,
deletion, retention, and key-material projectors can make bounded progress
without scanning content rows.

### Other Interfaces

Sync receives content share/retract work through sync-owned
`share_fact_with_sync` intents only after the content projector has validated
its own proof. Sync does not decide whether a message, reaction, file, or
deletion is valid. Connection is only a carrier for content fact bytes.
Received connection frames produce ordinary content facts plus receipts; the
content projector then runs the same validation path as local command output.

## Cross-Scope Row Reads

Auth key-maintenance commands read content message, tombstone, and file rows to
decide which frontier material is still needed and which retained path keys can
be wrapped without resurrecting purged roots. Sync and connection should not
infer content validity from content rows; they move fact ids or bytes and let
content projectors validate facts through context.

## Invariants And Responsibility

Message, reaction, file, file-slice, and deletion facts are scoped to their
workspace. Retention policy facts are global facts whose payload names the
workspace/scope and whose projector validates admin or bootstrap authority.

Deletion is target-owned. A deletion projector publishes generic core
`fact_purged` context only after it validates author and target. The target
message/file/reaction/slice projector consumes that context, deletes its own
rows, and purges its own fact bytes. Projectors do not purge someone else's
fact.

Content encodes `fact_purged` coordinates as
`frontier_id || minute || fact_id`. Target encrypted-content projectors publish
exact needs at the coordinates that should wake them: messages watch their own
coordinate, files watch their own coordinate and parent message coordinate, and
reactions/slices watch parent coordinates. Exact deletions publish exact offers
over one coordinate; retention or compaction can publish broader minute-range
offers over the same frontier-scoped key shape. Non-encrypted facts do not
publish these purge needs.

Opened message rows are derived state. The message fact is admitted and shared
after signer/author proof, but `opened_message_rows` are written only when the
matching local secret coverage can decrypt the text. File slices verify BAO
proofs against the descriptor root before writing ciphertext rows.

Signer-bearing content facts store signer identity fields, not embedded
signature bytes. Commands emit the target content fact plus an `auth::signature`
evidence fact. The signature projector verifies the evidence and offers
`signature_proof(target_fact_id, signer_public_key)`, which the content
projector consumes before checking author, signer, parent, deletion, retention,
or key-material context.

```text
signature {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000060000
  target_fact_id: fact:message_hello
  signer_public_key: ed25519:alice_phone_signing
  signature: ed25519_signature(workspace_acme, message_hello)
}
```

Retention has two independent removal paths. Per-message expiry is scheduled by
`content_message_expiry` time wakes. Retention policies publish
`content_retention_floor`, letting message projectors retire older messages
without changing the message fact body.

## Intent Handlers

Content registers no runtime intent handlers. Content commands synchronously
construct facts, and content projectors emit intents owned by other scopes:
`share_fact_with_sync` for sync visibility and auth/connection intents when
those scopes own the follow-up work.

## Facts

### `message` (tag 50)

Encrypted text message. Projection requires workspace scope, signature proof,
signer context, author context, secret coverage, deletion context,
retention-floor context, and time-wake checks. It writes `content_messages`
after metadata validation, writes `opened_message_rows` only after decryption, offers
`content_message_meta` and `content_message`, shares the fact, and self-purges
on deletion/expiry/retention.

```text
message {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000060000
  author_user_id: fact:user_alice
  signer_id: fact:endpoint_alice_phone
  signer_public_key: ed25519:alice_phone_signing
  frontier_id: fact:frontier_alice
  local_history_node_secret_id: fact:history_leaf_alice
  expires_at_minute: 28583336
  retention_policy_id: fact:retention_workspace
  minute: 28583334
  nonce: nonce:message
  ciphertext: bytes:sealed_text
}
```

### `message_deletion` (tag 51)

Authorizes removal of one message. Projection requires signer, target
`content_message_meta`, and author user context, validates the target frontier,
minute, and author, writes `message_deletion_rows`, offers exact
`fact_purged(message, target_minute, target_message_id)`, and shares the
deletion fact.

```text
message_deletion {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000120000
  target_message_id: fact:message_hello
  target_frontier_id: fact:frontier_alice
  target_minute: 28583334
  author_user_id: fact:user_alice
  signer_id: fact:endpoint_alice_phone
  signer_public_key: ed25519:alice_phone_signing
}
```

### `reaction` (tag 52)

Encrypted emoji reaction attached to a message. Projection requires workspace
scope, signature proof, signer, opened target message, target deletion watch,
and author context. Live reactions write `content_reactions` and share the
fact; deleted targets remove the reaction row and self-purge the reaction fact.

```text
reaction {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000180000
  target_message_id: fact:message_hello
  author_user_id: fact:user_bob
  signer_id: fact:endpoint_bob_laptop
  signer_public_key: ed25519:bob_laptop_signing
  nonce: nonce:reaction
  ciphertext: bytes:sealed_emoji
}
```

### `file_deletion` (tag 53)

Authorizes removal of one file descriptor. Projection requires signer, exact
target file, parent message, and author user context. It validates the target
file author and parent message, writes `file_deletion_rows`, offers
exact `fact_purged(file, target_file_minute, target_file_id)`, and shares the
deletion fact.

```text
file_deletion {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000240000
  target_file_id: fact:file_descriptor_budget
  author_user_id: fact:user_alice
  signer_id: fact:endpoint_alice_phone
  signer_public_key: ed25519:alice_phone_signing
}
```

### `file` (tag 54)

Encrypted file descriptor attached to a message. Projection validates descriptor
fields, signature proof, signer, parent message, author, file deletion, and
parent message deletion context. Live files write `content_files`, offer
`content_file` and `sync_exact_fact`, and share the fact. Deletion removes the
descriptor row and self-purges.

```text
file {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000200000
  message_id: fact:message_hello
  author_user_id: fact:user_alice
  signer_id: fact:endpoint_alice_phone
  signer_public_key: ed25519:alice_phone_signing
  file_id: id:budget_pdf
  blob_bytes: 7340032
  total_slices: 28
  slice_bytes: 262144
  root_hash: blake3:encrypted_blob_root
  sealed_metadata: bytes:sealed_filename_mime
}
```

### `file_slice` (tag 55)

One BAO-proven encrypted file slice. Projection requires parent file context,
parent message context, signature proof, valid slice index, BAO proof
verification against the file root hash, and file/message deletion watches.
Live slices write `file_slice_rows` with verified ciphertext and share the
fact. Deleted parents remove the slice row and self-purge.

```text
file_slice {
  workspace_id: fact:workspace_acme
  created_at_ms: 1715000200100
  file_id: id:budget_pdf
  slice_index: 3
  signer_id: fact:endpoint_alice_phone
  signer_public_key: ed25519:alice_phone_signing
  proof: bytes:bao_slice_proof_with_ciphertext
}
```

### `retention_policy` (tag 147)

Disappearing-message TTL policy for a workspace/channel/thread scope. Projection
requires non-zero TTL/time, signature proof, admin or workspace-bootstrap
authority, optional signer context, and optional predecessor policy context. It
rejects regressing `retire_minute`, writes `retention_policy_rows`, offers
`sync_exact_fact` and `content_retention_floor`, and shares the fact.

```text
retention_policy {
  workspace_id: fact:workspace_acme
  supersedes_policy_id: fact:retention_previous
  ttl_minutes: 1440
  retire_minute: 28582000
  scope_kind: SCOPE_KIND_WORKSPACE
  scope_id: fact:workspace_acme
  author_user_id: fact:user_alice
  signer_id: fact:endpoint_alice_phone
  signer_public_key: ed25519:alice_phone_signing
  created_at_ms: 1715000300000
}
```

## Example Fact Graph

```text
auth workspace/user/endpoint/key context
  -> retention_policy_workspace
  -> message_hello
       -> reaction_bob
       -> file_descriptor_budget
            -> file_slice_budget_0
            -> file_slice_budget_1

message_deletion_hello
  -> fact_purged(message, minute_hello, message_hello)
  -> message_hello self-purges
  -> reaction_bob self-purges
  -> file_descriptor_budget self-purges
  -> file_slice_budget_* self-purges
```

This graph shows why deletions are modeled as context rather than direct row
mutation. The deletion fact proves authority once; each target fact owns its
own cleanup when that context matches.
