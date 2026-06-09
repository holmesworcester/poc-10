# Root, Payload, And Ref Facts

## Status

Design note. This is a proposed simplification for future content facts in
poc-10. It assumes signatures are split into their own fact family and that we
do not need compatibility with already-created facts from the current mainline
encoding.

The target is not to make core understand content semantics. The target is to
make roots, signatures, payload opening, and exact DAG refs uniform enough that
future fact readers can upgrade old layouts into current semantic values while
current projectors keep owning authority, context proof, and materialization.

## Summary

Use one shared root shape plus specialized referenced facts:

```text
root fact
  typed manifest: family, version, created_at_ms, refs[MAX_REFS]

payload fact
  generic sealed content bytes for private shared content

local secret fact
  generic local-only secret bytes for private device material

signature fact
  proof over root fact id
```

Derived local state:

```text
opened_payload
  local-only context or fact produced from a payload through an authorized root
```

The simplest root is intentionally small:

```text
root_v1 {
  tag
  family
  version
  created_at_ms    // 0 means deterministic/timeless
  refs[MAX_REFS] {
    role
    index
    target_fact_id
  }
}
```

There is no family-owned byte body in the root, and there is no separate scope
field. Workspace, key domain, author, target, parent, content payload, and local
secret are all normal refs. Public relationship data should be expressed as refs
whenever practical. Shared family-specific content bytes are encrypted by
default unless they are protocol control data or an explicit privacy tradeoff.

For example:

```text
content_message_root
  family: content_message
  created_at_ms
  refs:
    workspace[0] -> fact:workspace
    content[0]  -> payload:message_sealed
    author[0]   -> fact:user_or_authority
    frontier[0] -> fact:frontier
    policy[0]   -> fact:retention_policy

signature
  signs content_message_root id
```

For simple content, `content[0]` can hold all typed user/application data. In
the privacy-favoring target, shared payload facts are sealed and the clear root
surface is limited to root family/version, event time when present, and refs.

## Clear Surface Target

The target shared-content cleartext surface is:

```text
root header
  family, version, created_at_ms, ref roles/indexes/target ids

signature facts
  enough public signature material to prove signed_root(root_id, ...)

auth/key/control facts
  enough public material to establish authority and key coverage

sealed payload envelope
  crypto format, nonce/header, ciphertext
```

Everything else that is user/application content should live in encrypted
payload bytes. This includes message text, reaction emoji, filenames, mime
labels, captions, file metadata, and other app fields.

"Only refs in the clear" is the right content-design pressure, but not a
literal rule for the whole protocol. Some clear bytes remain necessary:

- root family/version fields, so the runtime can route and match roots;
- ref roles and indexes, so projectors can form exact dependency needs;
- signature material, so roots can be authorized before payload opening;
- public auth and key-distribution material, so peers can prove authority and
  obtain or decrypt keys;
- sealed-payload crypto headers, such as format and nonce, unless those are
  derivable from the root edge.

If a projector needs a value before opening encrypted payloads, prefer one of
these encodings:

1. make it a ref to a fact;
2. derive it from root header fields, refs, or witness context;
3. if it truly must be clear and is not a ref, treat that as an explicit privacy
   tradeoff and document it.

## Why Split

The current content facts mix several concerns in one wire layout:

- public semantic coordinates;
- exact relationships to other facts;
- encrypted user content;
- signature bytes;
- encryption format details.

Splitting roots, payloads, and signatures gives these pieces separate upgrade
surfaces:

- root readers upgrade public ref manifests;
- signature readers/projectors upgrade signature algorithms and target shapes;
- payload readers/openers upgrade clear/sealed byte formats;
- domain projectors consume current semantic roots and opened payload context.

The important simplification is that historical compatibility stays in readers,
openers, and signature/key compatibility layers. Old domain projectors should
not be needed during replay.

## Root Refs

A ref edge is identified by:

```text
(root_id, role, index) -> target_fact_id
```

`role` describes what the edge means, not just the target fact type.

Examples:

```text
workspace[0]      -> workspace root or control fact
content[0]        -> content payload
secret[0]         -> local secret payload
metadata[0]       -> metadata payload, usually sealed if user-visible
parent_message[0] -> parent message root
reply_to[0]       -> replied-to message root
attachment[0]     -> file root
attachment[1]     -> file root
frontier[0]       -> key frontier fact
target[0]         -> deletion target root
```

`parent_message` and `reply_to` may both point to content-message roots, but
they are different relationships. `attachment[0]` and `attachment[1]` use the
same role and different indexes to represent a list.

The wire root has a fixed number of ref slots for its version.
Unused slots are a canonical empty ref, for example zero role/index/id. This
keeps root length stable and leaves headroom without giving each family its own
variable-length manifest encoding.

Projectors validate the ref set for their family:

- required roles are present;
- no duplicate `(role, index)` pairs exist;
- repeated roles use valid indexes;
- unexpected roles are rejected unless that family explicitly allows extension
  roles;
- targets have the expected current semantic type after their own projection.

The generic root reader validates only canonical root shape: tag, length,
family/version, `created_at_ms`, empty-slot padding, sorted or otherwise
canonical refs, and duplicate `(role, index)` slots. It does not decide whether
a `content_message` root has the right roles or whether `created_at_ms` must be
zero or nonzero. The content-message projector decides that.

`created_at_ms` is creator-asserted event time, not freshness or ordering
proof. Deterministic records set it to `0`. Families that model real events can
require nonzero time; deterministic/control families can require zero time.

## Ref Proofs And Context

Refs are exact dependencies. Witnesses are not refs.

Exact dependencies:

```text
payload id
metadata payload id, if this family splits metadata from content
parent root id
target root id
attachment root id
frontier fact id, if this root chooses to pin an exact frontier fact
```

Witness context:

```text
signed_root(root_id, signer, purpose)
content signer authority
admin authority
key coverage
deletion or retention floor
time wake
```

The proof shape for an exact ref is:

1. The root reader produces the canonical ref list.
2. A signature projector offers `signed_root(root_id, signer, purpose)` after
   verifying a signature fact over the root id.
3. The root projector validates authority from current witness context.
4. The root projector derives exact needs from its refs.
5. The target projector offers current context for its target fact id after its
   own validation.
6. The root projector checks that the matched target id equals the referenced
   id and that the target semantic role is the expected one.

This keeps the context distinction clean:

- root refs prove "this signed statement names exactly this fact id";
- target context proves "that fact id has valid current meaning";
- witness context proves "some acceptable authority/key/deletion proof exists."

For example, a reaction root might ref `target_message[0]`. The reaction
projector must need current `content_message(target_message_id)` context, not
just raw fact existence. The target message projector decides whether the
message is valid, opened, deleted, expired, or retained.

## Payload-Like Facts

Payload-like facts are referenced byte facts. A payload by itself should not
create user-visible state.

Payload formats:

```text
payload_clear_v1 {
  tag
  format
  schema
  bytes
}  // transitional, local-only, or test-only in the privacy target

payload_sealed_v1 {
  tag
  format
  algorithm
  nonce_or_header
  ciphertext
}
```

The important families are:

```text
sealed_content_payload
  shared; generic crypto envelope for private application content

opened_payload
  local-only; derived clear bytes or handles produced through an authorized root
  edge

local_secret_payload
  local-only; family, version, raw secret bytes

sealed_key_material
  shared or local depending on family; encrypted keys or wraps, not application
  content

typed_protocol_control
  sync, connection, and other protocol facts with clear fixed fields
```

Only the first kind is the ordinary shared content payload. The others are
listed so they are not accidentally forced through content opening rules.

The `schema` can be carried by the payload, by the root ref role, or both. If
both exist, the opener/projector must require them to agree. Carrying it in the
root ref keeps sealed payloads closer to pure ciphertext. Carrying it in the
payload helps standalone diagnostics and malformed-data rejection. This design
can choose either per size class.

Opened payload context should be keyed by the root edge, not only by payload id:

```text
opened_payload(root_id, role, index, payload_id, schema)
```

That prevents "payload fact exists" from becoming meaningful outside an
authorized signed root edge. The same payload id can be referenced by multiple
roots, but each root edge authorizes and opens it independently.

Local secret payloads use the same ref mechanism but not the shared content
opener:

```text
local_secret_payload {
  tag
  family
  version
  bytes
}
```

A local root refs a secret with an ordinary role-tagged edge such as
`secret[0]`. The local projector validates that the ref points to the expected
secret family and that the secret reader adapts `family/version/bytes` to the
current local secret semantics. The secret id may commit to exact secret bytes;
rotation creates a new secret fact and usually a new local root.

## Encrypted Payloads As Ciphertext

Prefer sealed payload facts that contain only crypto envelope bytes:

```text
payload_sealed {
  algorithm_or_format
  nonce_or_header
  ciphertext
}
```

Do not put domain key coordinates in the sealed payload when the root context
can provide them. The opener should receive key context from the authorized root
edge:

```text
payload_open_request {
  root_id
  role
  index
  payload_id
  schema
  key_coordinate
}
```

The root projector creates that request only after proving:

- the root has the expected payload ref;
- the root has a valid `signed_root` proof;
- the signer or author has authority to create the root;
- the root's clear refs and witness context imply the key coordinate.

Then the payload opener:

1. reads the payload envelope;
2. consumes the open request for `(root_id, role, index, payload_id)`;
3. if clear, emits opened payload;
4. if sealed, needs current key coverage for the request's key coordinate;
5. decrypts with empty or constant AEAD associated data;
6. emits local opened payload context.

This lets sealed payloads avoid carrying `workspace_id`, `frontier_id`,
`minute`, author, signer, group, channel, or other semantic coordinates. Those
belong to the signed root, exact refs, or witness context.

If a payload format needs an AEAD nonce, the nonce can be a crypto header in the
sealed payload. "Ciphertext-only" here means "no domain metadata," not
"literally no nonce or algorithm tag."

## Payload Metadata Choices

If root has no family-owned body, non-ref metadata must become a ref, be
derivable from root fields and refs, or live in payload bytes. For shared
content, living in payload bytes usually means being sealed.

Use these rules:

- If metadata is an exact fact relationship, put it in `refs[]`.
- If metadata is a scalar needed before opening encrypted content, first try to
  model it as a ref or derive it from root context.
- If metadata must remain clear and is not a ref, document the privacy leak and
  keep the clear surface narrow.
- If metadata is user/application content, put it in a sealed payload.
- If metadata can be derived from root refs, created time, signature context, or
  witness context, derive it instead of storing it again.

Examples:

```text
message
  root refs:
    author[0]   -> user or author authority fact
    workspace[0] -> workspace fact
    frontier[0] -> frontier/key-coordinate fact
    policy[0]   -> retention policy fact
    content[0]  -> sealed message payload
  sealed content payload:
    message text, optional subject/thread labels, content metadata

reaction
  root refs:
    target_message[0] -> message root
    workspace[0]      -> workspace fact
    content[0]        -> sealed emoji payload

file
  root refs:
    parent_message[0] -> message root
    workspace[0]      -> workspace fact
    content[0]        -> sealed file metadata payload
    blob[0]           -> file blob root or payload
```

Some facts may only need a single `payload[0]` ref. The split is a tool, not a
requirement that every fact has metadata and content payloads.

Facts that are not user/application payload should not be forced into sealed
payloads just for uniformity. Workspace identity, user invites, endpoint
authority, recipient keys, key wraps, signatures, retention-control facts,
deletion targets, sync facts, and connection carrier facts are protocol control
or transport evidence. They may still use root/ref envelopes where useful, but
their clear fields are often the point of the fact.

Current-style fact families fall roughly into three buckets:

```text
sealed content payloads
  message text
  reaction emoji/object
  file metadata
  file bytes/slices or blob chunks
  application-level content fields that users would expect to be private

clear root refs plus witness/control facts
  parent/target/attachment refs
  author/user/admin/endpoint authority
  retention policy refs or deletion target refs
  key-coordinate refs such as frontier/group/epoch facts
  signature facts over roots

clear protocol/control facts
  workspace identity and invites
  endpoint and recipient public keys
  key requests, key wraps, removal frontiers
  deletion and retention-control facts
  sync/connection carrier and receipt facts
```

The first bucket should converge on sealed payloads. The second bucket should
mostly be refs and witness context. The third bucket is intentionally public
protocol state; encrypting it would either make validation impossible or hide
the very information peers need to establish authority and decryption.

## Generic Package Fit

The maximum useful generic package is:

```text
root
  family, version, created_at_ms, refs[MAX_REFS]

sealed_content_payload
  format, nonce/header, ciphertext

local_secret_payload
  family, version, bytes

signature
  target root id, signer proof
```

`created_at_ms = 0` marks deterministic or timeless records. Nonzero
`created_at_ms` is for authored events where creator-asserted time is part of
the statement: messages, reactions, files, deletions, retention changes,
invites, key requests, and endpoint/user/admin grants.

The root package intentionally has no scope field, no generic scalar map, and
no family-owned byte body. If a value is an exact relationship, put it in
`refs[]`. If a value is shared application content, put it in
`sealed_content_payload`. If a value is local private material, put it in
`local_secret_payload`. If a value is public protocol control material, the
family is a control fact and should not pretend that value is private content.

This is the important pushback: a refs-only root fits all facts only if we turn
public keys, signatures, hashes, ranges, counters, enum flags, addresses, and
protocol ciphertexts into separate value facts. That would make the graph
larger and less readable without improving privacy. The root package should be
maximal for content and relationship edges, not universal at the cost of making
control state awkward.

### Fit Audit

Content families:

```text
message
  root with refs:
    workspace[0], author[0], key_domain[0], policy[0] when pinned, content[0]
  sealed content payload:
    text and private content metadata

reaction
  root with refs:
    workspace[0], author[0], target_message[0], key_domain[0], content[0]
  sealed content payload:
    reaction object

file descriptor
  root with refs:
    workspace[0], author[0], parent_message[0], key_domain[0], content[0],
    blob[0]
  sealed content payload:
    filename, mime, caption, private file metadata

file slice / blob chunk
  root or specialized blob fact with refs:
    file[0] or blob[0]
  created_at_ms:
    usually 0 if deterministic from parent/chunk coordinates
  sealed content payload or specialized encrypted blob storage:
    chunk bytes
  public control:
    chunk index and proof may remain specialized if the blob transport needs it
```

Content control:

```text
message_deletion
  root with refs:
    workspace[0], author[0], target[0]
  no content payload

file_deletion
  root with refs:
    workspace[0], author[0], target[0]
  no content payload

retention_policy
  root control fact with refs:
    workspace[0], author[0], target[0] or domain[0], supersedes[0] when present
  no content payload
  public control:
    ttl, retire floor, and policy domain mode are mechanics, not private content
```

Auth and identity:

```text
workspace
  control root or typed control fact
  refs: none or provider/bootstrap refs
  public control: root public key
  optional sealed content payload: private workspace display label

user
  control root with refs:
    workspace[0], invite/authority[0]
  public control: user public key and signer proof
  optional sealed content payload: private username/profile label

user_invite, device_invite, endpoint_shared, invite_server, admin
  control root with refs:
    workspace[0], authority[0], user[0], endpoint[0] as applicable
  public control:
    public keys, endpoint roles, signer keys
  optional sealed content payload:
    private device name or display label only if product wants that private

signature
  signature fact over root id
  no content payload

recipient_key, key_request, removal_frontier
  control root with refs:
    workspace[0], endpoint[0], frontier/key_domain[0], recipient[0]
  public control:
    recipient public key, request route, frontier owner, signer material
  no content payload

key_wrap
  root or specialized sealed control fact with refs:
    workspace[0], signer_endpoint[0], key_domain[0], recipient_key[0],
    wrapped_secret[0] or source_secret[0] as applicable
  created_at_ms:
    usually 0 when deterministic from exact inputs
  encrypted control material:
    wrapped secret ciphertext
  no content payload
```

Local-only auth and connection material:

```text
local_endpoint, local_signer_secret, local_recipient_key
local_key_secret, local_history_node_secret, invite_secret
invite_accepted, local_secret_retirement, connection_ephemeral_secret
```

These are local capability/secret facts. They can use root refs for readability
where useful, but they are not shared content. Their secret bytes should be
plain local secret payload-like facts:

```text
local_root refs:
  workspace[0], endpoint[0], secret[0], supersedes[0] as needed

local_secret_payload:
  family, version, bytes
```

The `secret[0]` edge is structurally the same as every other ref. The target
fact type marks it local-only and secret-bearing. Storage policy, keychain use,
backup exclusion, and encryption-at-rest are local store concerns, not fields in
the secret payload format.

Sync and connection:

```text
sync range_request, shared_fact, compare, have_id, need_id
  transport/control roots or typed control facts
  refs: connection[0], fact[0], workspace[0] where exact ids matter
  public control: ranges, counts, fingerprints, booleans
  no content payload

connection request, connection, frame_small, frame_file_slice, frame_bundle
  sealed control/carrier facts
  public control: routing/opening header
  encrypted control/carrier bytes:
    handshake material or inner fact bundle
  no content payload

connection close, frame_observation, fact_receipt
  local/control roots or typed control facts
  refs: connection[0], request[0], frame[0], received_fact[0]
  public control: local time, origin, receive path, hashes
  no content payload
```

The result is a stricter rule than "every fact has a payload":

```text
content roots may ref sealed content payloads
control roots do not have content payloads
sealed control carriers are not content payloads
local secrets are not shared payloads
```

This keeps encrypted payloads focused on private application content. It also
keeps protocol control facts inspectable enough for projectors to prove refs,
authority, key coverage, sync state, and transport state before any content is
opened.

## Protocol Control And Transport Boundary

Do not turn the root package into a schema language for sync and connection.
The main value is in durable content and local secret material. Ephemeral
transport and sync process facts can stay typed, fixed-layout, and explicit.

Core should remain the dumb socket/runtime boundary. Facts decide what is
valid, shareable, opened, and projected. Connection request/response/frame facts
may carry sealed bytes, but that sealing is still a protocol fact concern, not
a generic core carrier abstraction.

Protocol facts have legitimate clear control parameters: timestamp ranges,
counts, fingerprints, booleans, addresses, public keys, nonces/headers,
signatures, and fixed transport size classes. Those values are not private
application content.

Keep these families typed unless a future cleanup has a local code-quality
reason to change them:

```text
sync range_request, compare, have_id, need_id, shared_fact
  fixed protocol control layouts
  no content payload
  no historical adapter requirement

connection request, connection, frame_small, frame_file_slice, frame_bundle
  fixed protocol transport layouts
  no generic content payload
  no historical adapter requirement

connection close, frame_observation, fact_receipt
  local observation/control layouts
  no content payload
  no historical adapter requirement
```

This means `frame_small`, `frame_file_slice`, and `frame_bundle` remain separate
fixed-length typed facts for now. If they are ever simplified, prefer an
implementation-local helper such as "small fixed frame" and "large fixed frame"
over a new durable generic payload kind. A large frame can carry a file slice or
a bundle if that helps batching, but that is a connection implementation detail.

Local secret extraction remains useful for connection/auth secret material:

```text
local_secret root
  created_at_ms: creation time or 0 if deterministic
  refs: workspace[0], endpoint[0], secret[0], supersedes[0] as needed

local_secret_payload
  family, version, bytes
```

Key wraps are durable encrypted control material, not content payloads:

```text
key_wrap or sealed_key_material
  refs: workspace[0], key_domain[0], recipient_key[0], source_secret[0] as
  needed
  ciphertext: wrapped key bytes
```

Opening sealed key material produces current key coverage or local secret
payloads. It does not produce application content.

The resulting payload-like kind list is:

```text
sealed_content_payload   private shared application content
opened_payload           local derived application content
local_secret_payload     local raw secret bytes
sealed_key_material      encrypted durable key/control material
typed_protocol_control   sync/connection/control facts that stay typed
```

Large content blobs do not need a new semantic kind. They can be sealed content
payloads with a size class, chunk ref scheme, or local opened handle. Signatures,
public keys, sync control values, connection frames, and receipts also do not
need payload kinds; they are public or ephemeral protocol facts whose bytes are
the protocol material.

## Reader And Projector Boundaries

Keep readers pure where possible:

```text
root reader
  bytes -> current RootEnvelope

payload reader
  bytes -> current PayloadEnvelope

local secret reader
  bytes -> current LocalSecretEnvelope

signature reader
  bytes -> current SignatureEnvelope

key reader
  bytes -> current KeyEnvelope
```

Context waiting belongs in current projectors and openers:

```text
signature projector
  SignatureEnvelope + verifier material -> signed_root context

root projector
  RootEnvelope + signed_root + witness context -> open requests, exact needs, rows

payload opener
  PayloadEnvelope + open request + key coverage -> opened_payload context

local secret projector
  LocalSecretEnvelope + local root refs -> local secret context

key projector
  KeyEnvelope -> current key_coverage context
```

Avoid old domain projectors. Historical compatibility should look like:

```text
old root bytes -> current RootEnvelope -> current root projector
old payload bytes -> current PayloadEnvelope -> current payload opener
old local secret bytes -> current LocalSecretEnvelope -> current local context
old key bytes -> current KeyEnvelope -> current key_coverage offer
old signature bytes -> current SignatureEnvelope -> current signed_root offer
```

The exception is a narrow compatibility layer below domain projection. If an old
sealed payload cannot map to current key coverage, the payload opener may need a
legacy key role and old key projectors may offer that legacy role. Keep that
inside payload/key compatibility, not in domain projectors.

Connection and sync transport facts are intentionally outside this compatibility
contract. They are ephemeral protocol process facts; stale versions can be
dropped, recreated, or allowed to fail decode without affecting retained content
semantics.

## Transition Plan

Use this as the plan for aligning `main` with the root/ref/payload model while
leaving ephemeral sync and connection facts alone.

### Phase 1 - Root Envelope Library

Add a protocol-level root envelope module, not core semantics:

- one fixed root layout for the current version, with `created_at_ms` and
  enough `MAX_REFS` headroom for known families;
- canonical empty refs for unused slots;
- canonical ref encoding and sorting rules;
- duplicate `(role, index)` rejection;
- helpers to find refs by role/index and validate cardinality;
- tests for wrong length, wrong padding, duplicate refs, unexpected count, and
  max-ref boundaries.

Core may provide byte helpers, but root roles remain protocol semantics.

### Phase 2 - Generic Content Payload Facts

Add generic content payload facts:

- payload readers normalize sealed envelopes;
- clear payload support, if added, is transitional, local-only, or test-only;
- payload facts do not offer user-visible domain context by themselves;
- clear payload opening is request-gated just like sealed payload opening;
- opened payload is local-only and keyed by `(root_id, role, index, payload_id,
  schema)`.

If implementation wants to prove the root/open-request flow before crypto lands,
start with local/test clear payloads. Do not treat shared clear content payloads
as the target format.

### Phase 3 - Generic Local Secret Payloads

Add local secret payload-like facts:

- `local_secret_payload` is local-only `family, version, bytes`;
- local roots ref secrets through ordinary `secret[N]` refs;
- storage policy is outside the fact bytes;
- secret readers adapt old local secret byte formats to current local secret
  context;
- rotation creates new secret facts and new local roots when needed.

### Phase 4 - Signature Facts Over Root Ids

Make signature facts produce normalized `signed_root` context:

- signature target is root id;
- purpose/domain is explicit;
- signer identity is exposed as current semantic data;
- old and new signature formats can offer the same normalized context.

Do not require roots to ref their signature facts. A root can have zero, one, or
many acceptable signature witnesses.

### Phase 5 - Current Payload Opening

Add sealed payload opening:

- root projector emits `payload_open_request` after signed-root and authority
  checks;
- key coordinate comes from root refs and witness context, not from sealed
  payload domain fields;
- sealed payload opener asks for current `key_coverage`;
- AEAD associated data is empty or a constant domain string;
- opened payload bytes are local and re-derivable.

### Phase 6 - First Content Family Migration

Migrate one narrow family, probably reactions or message text:

- root authoring emits root, payload, and signature facts;
- root projector validates exact refs and signed-root context;
- payload opener emits opened payload;
- current domain projector materializes the same rows as before;
- sync shares root, payload, and signature only after the owning projectors
  decide they are shareable.

### Phase 7 - Message, File, Slice, Deletion, Retention

Migrate the remaining content families:

- message roots use content payload refs and exact metadata refs as needed;
- file roots use exact parent refs and payload/blob refs;
- deletion roots target exact root refs;
- retention can remain a typed fact or move to root/payload when useful;
- file slices should stay optimized for large byte movement, but their parent
  and proof edges should use root refs where practical.

### Phase 8 - Preserve Ephemeral Protocol Facts

Keep current sync and connection process facts typed unless a later cleanup has
a narrow implementation reason:

- leave `range_request`, `compare`, `have_id`, `need_id`, and `shared_fact` in
  their current typed layouts;
- leave `request`, `connection`, `frame_small`, `frame_file_slice`,
  `frame_bundle`, `close`, `frame_observation`, and `fact_receipt` in their
  current typed layouts;
- do not add a generic transport carrier fact as part of this transition;
- do not add historical adapter chains for old ephemeral transport/sync facts;
- keep the core socket/runtime boundary dumb: protocol facts and handlers own
  validity, sealing, opening, receipts, and sendability.

If connection private material later moves to `local_secret_payload`, treat that
as part of the local secret migration, not as transport generalization.

### Phase 9 - Compatibility And Version Harness

Add historical readers/openers intentionally:

- root v1 -> current root semantics;
- payload clear/sealed v1 -> current payload envelope;
- local secret v1 -> current local secret envelope;
- opened payload schema v1 -> current typed payload;
- key v1 -> current key coverage;
- signature v1 -> current signed-root context.

Current projectors should consume current semantic/context vocabulary only.

### Phase 10 - Worktree Handoff Rule

Every implementation worktree that follows this plan must finish by committing
the completed work on that same branch before handoff or review.

## Aggressive Upgrade Tests

These are acceptance targets for the model. They should become concrete tests
as the root/payload machinery lands.

### Root And Ref Tests

- A root with duplicate `(role, index)` refs is rejected by the root reader.
- A root with the same target fact id under two different roles is accepted by
  the root reader but interpreted distinctly by the typed projector.
- A `reply_to[0]` message ref cannot satisfy a required `parent_message[0]`
  need.
- A typed projector rejects missing required refs, unexpected refs, and invalid
  repeated-role indexes.
- Roots with unused ref capacity require canonical empty slots.
- A root with nonzero data in an unused ref slot is rejected.
- A deterministic family rejects nonzero `created_at_ms`; an event family
  rejects `created_at_ms = 0` when time is required.
- Workspace, key domain, author, payload, and local secret links are all normal
  refs; none is read from a root `scope` or special payload slot.
- Refs arriving out of order on the wire either canonicalize identically or are
  rejected, depending on the chosen root encoding rule.
- A root can be admitted before its payload, signature, parent, and key facts;
  replay later wakes it without order dependence.

### Signature Tests

- Ed25519 signature facts and a future PQ or hybrid signature fact both offer
  the same `signed_root(root_id, signer, purpose)` context.
- A signature over the payload id does not satisfy a signature need for the
  root id.
- A signature with the wrong purpose/domain does not satisfy the root projector.
- Two valid signatures over one root can coexist, and the typed projector can
  require either one signer, a specific signer, or a threshold policy.
- An old signature format that signed root bytes normalizes honestly to
  `signed_root` only when those bytes hash to the named root id.

### Payload Opening Tests

- A clear payload fact alone does not create user-visible rows or domain
  context, if clear payloads exist for transition or tests.
- A sealed payload fact alone does not create user-visible rows or domain
  context.
- A root edge to a payload creates an open request only after signed-root and
  authority checks pass.
- `opened_payload` is keyed by `(root_id, role, index, payload_id, schema)`, so
  one payload reused by two roots opens as two separately authorized edges.
- A payload opened under `content[0]` cannot satisfy a need for `metadata[0]`.
- A payload schema mismatch between root edge and payload envelope is rejected.
- Transitional clear payloads and sealed payloads with the same plaintext
  produce the same current typed payload after opening.
- Opened payload bytes are local-only and can be wiped and re-derived by replay.
- A shared content family that marks metadata private has no clear metadata
  payload; only root refs and sealed payload envelope bytes are visible.
- A projector that needs author, target, parent, frontier, or policy before
  opening content obtains those values from refs or witness context, not from
  clear payload metadata.

### Local Secret Tests

- A local root can ref `secret[0]` exactly like any other ref.
- A `secret[0]` ref to a shared content payload is rejected by the local
  projector.
- A local secret payload has only `family, version, bytes`; storage policy is
  not encoded in the fact bytes.
- Rotating local secret material creates a new local secret id and a new local
  root or supersession edge; old refs continue to name the old exact secret.
- An old local secret payload adapts to current local secret context without
  changing root/ref parsing.

### Encrypted Payload Tests

- A sealed payload carries no workspace/frontier/group/channel domain metadata;
  the opener obtains the key coordinate from the authorized root edge.
- A copied ciphertext under a new authorized root is treated as a new statement
  by that root, and opens only if the root's key coordinate has matching key
  coverage.
- A copied ciphertext under a root with a different key coordinate fails to open
  unless the same key coverage legitimately applies to that coordinate.
- Changing root refs that determine the key coordinate changes the open request
  and cannot silently reuse old key coverage.
- Empty or constant AEAD associated data is sufficient because domain binding is
  checked through signed root refs and key-coordinate validation.
- A malformed nonce/header/ciphertext is rejected by the payload opener without
  waking domain projectors as if content were missing.
- A future sealed format with a different algorithm opens to the same
  `opened_payload` context shape.
- A large sealed payload can emit an opened blob handle/hash instead of putting
  all bytes into context, while small payloads can use inline local bytes.

### Key And Encryption Upgrade Tests

- An old key fact reader/projector offers current `key_coverage`.
- A new key fact reader/projector offers the same current `key_coverage`.
- An old sealed payload opens using key material that arrived in a new key fact
  format.
- A new sealed payload opens using key material that arrived in an old key fact
  format after that key fact adapts to current coverage.
- If an old sealed payload coordinate cannot normalize to current coverage, the
  compatibility opener uses a legacy key role contained to payload/key layers;
  no domain projector sees the legacy role.
- Key-wrap format changes do not require content root projectors to change.
- Hybrid/PQ KEM-wrapped payload keys can open new payloads without changing
  root ref proof or domain projection.
- Old non-PQ ciphertext remains decryptable with old material, but tests assert
  that PQ migration does not claim retroactive PQ protection without explicit
  re-encryption or rewrap facts.

### Protocol Boundary Tests

- Existing sync facts continue to decode and project through their typed
  layouts after the root/payload model lands.
- Existing connection request, connection, frame, close, observation, and
  receipt facts continue to decode and project through their typed layouts.
- No generic transport-carrier fact is required for the content root/payload
  migration.
- No historical adapter chain is required for old sync or connection process
  facts; stale ephemeral facts can fail decode, be dropped, or be recreated by
  current sync/connection behavior.
- Core socket/runtime tests still treat core as a dumb transport boundary:
  protocol handlers own validity, sealing, opening, receipts, and sendability.
- Local connection/auth secrets can migrate to local secret payload refs without
  changing frame, request, response, range, or compare layouts.

### Content Schema Upgrade Tests

- Message text payload v1, v2, and v3 all adapt to the current message text
  semantic value.
- Reaction payload changes from raw emoji string to structured reaction object
  without changing root ref proof.
- File metadata changes from `filename,mime` to `filename,mime,caption,hash`;
  all versions remain sealed and display with defaulted new fields after open.
- A message root moves from separate public metadata and content payloads to one
  sealed `content[0]` payload plus refs for pre-open context; both versions
  project to the same current rows.
- A content payload that contains encrypted inner refs opens first, then the
  current domain projector emits exact needs for those refs using current roles.
  This is allowed but should stay rare.

### Deletion And Retention Tests

- Old deletion facts targeting `(frontier, minute, fact_id)` normalize to
  current deletion context for the target root id.
- New deletion roots target exact root refs and do not need encrypted payloads
  to be opened before removing visible rows.
- Retention policies can purge roots whose content payload is absent or still
  sealed.
- A deletion root that refs `target[0]` cannot delete a different root with the
  same payload id.
- Retention-floor context remains witness-shaped, while exact deletion targets
  remain ref-shaped.

### Authority And Witness Tests

- Root refs never substitute for signer/admin/key witnesses.
- Witness context can be satisfied by any valid current proof, not only by a
  fact id pinned in the root.
- A root can be validly signed but never visible because signer authority,
  author membership, key coverage, or parent context never appears.
- A payload open request is not emitted for a root whose signature is valid but
  whose signer lacks authority.
- A parent root that is deleted or expired cannot satisfy a child root's
  required current parent context.

### Replay And Sync Tests

- Root, payload, signature, key, and parent facts sync in every permutation and
  converge to the same rows after replay.
- Wiping opened payload local state and replaying retained shared facts
  re-creates the same opened payloads and rows.
- Payload facts do not become sync-visible merely because they exist locally;
  shareability follows the authorized root/payload policy.
- A store containing only payload facts remains semantically empty.
- A store containing root plus signature but missing payload parks with exact
  payload needs and later wakes when the payload arrives.
- A store containing payload plus root but missing signature does not open clear
  or sealed payload bytes for domain projection.

### Performance And Readability Tests

- Ref-array helpers reduce hand-coded parent/payload/target matching in content
  families without moving domain semantics into core.
- Size-class roots avoid forcing small messages to pay for large file DAG ref
  capacity.
- Large payload opening stores bytes out-of-context and exposes stable local
  handles; small payload opening can stay inline.
- Root readers remain pure and fast enough for replay; crypto and key waits
  stay in payload/signature/key projectors.
- Versioned readers are table-driven enough that adding `payload_sealed_v2`
  does not require edits to message, reaction, and file projectors.
