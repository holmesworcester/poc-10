# Auth

This document records the poc-10 auth authority and key-material invariants.
Auth combines workspace identity, endpoint authority, naturally signed facts,
recipient public keys, removal frontiers, deterministic key wraps, and local
secret material because those facts form one proof boundary: who can act in a
workspace and what this store is allowed to open or share for that authority.

Content retention and deletion live in `protocol::content`; they interact with
auth keys by emitting purge context that auth projectors can range-match.
Production code expresses these relationships with facts, context
needs/offers, `WakeLoop`, projectors, and handlers.

## Fact Families

- `workspace`: root shared namespace for users, endpoints, content, and sync.
- `user`, `admin`, `user_invite`, `device_invite`, `invite`,
  `invite_accepted`, and `invite_server`: shared authority edges for joining,
  granting, and accepting workspace authority.
- `endpoint` and `endpoint_shared`: local and shared endpoint identity
  material.
- `removal_frontier`: shared fact naming a content-key frontier and its owner.
- `recipient_key`: shared endpoint public key for receiving wraps.
- `local_recipient_key`: local private material paired with one recipient key.
- `key_wrap`: deterministic shared fact wrapping either a frontier root or one
  retained history-node secret to one recipient key. Its integrity comes from
  deterministic coordinate validation and AEAD associated data, not a natural
  signature.
- `key_request`: shared fact asking an authorized responder for missing key
  material for one frontier.
- `local_key_secret`: local opened frontier/root secret.
- `local_history_node_secret`: local retained node in the time/trie key tree.

Content facts name their frontier, minute, and target fact coordinate in their
encrypted fields. Deletion, expiry, and retention-floor facts make content
unavailable and wake key-purge behavior by publishing content-owned purge
context; they are not auth fact families.

## Content Key Tree

Each frontier has one root secret. Content derives per-message or per-file leaf
keys by walking a deterministic tree:

```text
frontier root -> time node -> in-minute trie node -> content leaf
```

The target coordinate is recoverable from canonical fact fields, so peers can
describe what key coverage they need without decrypting the content first.
Retained history-node secrets let a peer keep decrypting surviving content after
the root and a deleted descend path have been purged.

Target projection represents this with context:

- encrypted content emits a need for secret coverage over its frontier, minute,
  and target coordinate.
- local key material emits offers for the coverage it can derive.
- a coverage matcher wakes encrypted content when a root, retained node, or leaf
  covers the requested coordinate.

## Key Wraps

Wraps are deterministic and idempotent for a wrap edge:

```text
workspace
frontier
recipient_key
source key material
source coordinate
```

The wrap idempotence key must not include request entropy. A duplicate request
for the same edge should converge on the same pending wrap/fact, preventing key
amplification.

Generated wraps use the source fact time. Root wraps use frontier/root source
time; retained-node wraps use the retained node source time. Request time may be
recorded separately as provenance if needed, but it must not affect wrap
identity.

## Proactive Sharing

Learning a current recipient key should proactively create deterministic wraps
for current eligible sources, usually before the recipient asks. This makes the
initial share and the key-request response the same operation: materialize the
deterministic wrap edge if authorized and absent.

Superseded recipient keys must not receive old frontiers. Their standing needs
should be replaced by supersession cleanup, not by more wrap requests.

## Key Requests

Key requests are facts, not sync-layer privileges. The request projector must
validate:

- requester matches the recipient key being served.
- responder owns the requested frontier or retained source.
- requested recipient/frontier/source all belong to the same workspace.
- the source is still shareable: root if available, retained nodes if the root
  has been purged.

For a partitioned valid member joining after deletion, the responder cannot
share a purged root. It should wrap all retained path nodes needed to cover
surviving content in the requested frontier.

## Forward Secrecy Requires Recipient Key Rotation On Root Loss

When deletion, expiry, or floor advancement purges a frontier root or makes it
unavailable for future sharing, recipient keys must rotate. This prevents peers
from continuing to wrap new material to a key that may have been exposed before
the root was retired.

Local private material for a superseded recipient key is purged by exact
supersession proof. Shared superseded public keys remain as context so peers can
reason about why old wraps stopped.

Forward secrecy here is post-compromise secrecy for retired content: after the
retirement transaction commits, remaining local disk state must not be enough to
derive the retired leaf. It does not erase plaintext or keys an attacker saw
before retirement.

## Disappearing Messages And Purge

Disappearing content has semantic expiry/floor facts. Those facts wake content
projection and purge handlers through context offers.

Purge is event-centric:

- semantic deletion/expiry/floor facts authorize removal.
- projectors emit deterministic purge intents once proof is present.
- purge handlers perform bounded physical deletion of canonical bytes or local
  secret material.
- purge does not authorize remote erasure; it removes only local retained
  material after durable semantic facts preserve what peers need to know.

Deleting one event that used a recipient wrap is a natural trigger for pruning
obsolete recipient key material and stale wrap relevance. There should be no
time-only garbage collector responsible for core key correctness.

## Open Content

Opening encrypted content is projector work when all inputs are provided as
context and the operation is deterministic: validate the signed content-message
context, find covering local key material, derive or validate the leaf, decrypt
the encrypted fields, and emit opened rows via row mutations.

Message metadata is intentionally separate from opened content. After signer
and author context validate, a content-message projector may emit
`content_message_meta` so an author deletion can be validated and purged before
any key material arrives. It emits the normal `content_message` offer and
opened rows only after decrypting the encrypted fields, so files and reactions
still depend on opened message context.

If opening ever requires broad scans, IO, clock reads, or external mutation,
split that step into a bounded intent/handler. Do not create a generic
"open-message worker" as a dumping ground.

## Dep-Aware Sync

For encrypted facts in a synced range, dep-aware sync must provide the relevant
out-of-range key facts needed to project them:

- recipient keys and supersession facts needed to validate wraps.
- key wraps needed by the receiver.
- retained history-node wraps when roots are unavailable.
- key requests/responses as ordinary facts when a peer does not yet know what it
  needs.

The untrusted server may compare ranges, but key authority and key healing are
event-layer facts.
