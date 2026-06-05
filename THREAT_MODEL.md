# Threat Model

This is the invariant-centric threat model for the poc-10 Context prototype.
It follows the invariant-centric threat modeling form: start from no assumed
security, name the usage scenario and adversaries, and list only the security
properties that this design expects users and proof authors to rely on. Any
expected property that is not listed here is either out of scope, a missing
invariant, or a known weakness to document before users rely on it.

This document is also the review bridge to the Verus work in
`docs/todo-add-verus-proofs.md`. The proofs should either establish the
mechanized form of these invariants or force this threat model to move the
property into Known Weaknesses.

Sources and starting points:

- Invariant-Centric Threat Modeling: <https://github.com/defuse/ictm>
- Quiet Threat Model: <https://github.com/TryQuiet/quiet/wiki/Threat-Model>
- Context Verus plan: `docs/todo-add-verus-proofs.md`
- Current architecture docs: `README.md`, `src/core/README.md`, and
  `src/protocol/*/README.md`

## Target Audience

This document is for Context developers, reviewers, and proof authors. It uses
developer-facing protocol terms because the prototype is a fact runtime, not a
finished end-user application.

## Usage Scenario

A team uses Context as the backend for an encrypted workspace chat. Users join
workspaces through authentic out-of-band invitations or already-established
workspace authority. Each real member runs authentic Context code, protects the
device outside the app with normal OS controls, and does not intentionally
archive content that the app has declared deleted.

Facts may move over direct peer connections, sync range exchange, invite-server
flows, or other relay/storage infrastructure. Those carriers are not trusted.
They can store, replay, reorder, omit, or mutate bytes, but they cannot create
valid member signatures or local-only facts without the relevant private
material.

Deletion is local until a device has processed the semantic deletion, expiry,
or retention-floor fact and committed the target-owned purge or retirement
effects. A remote offline device is not assumed to have deleted anything until
it receives and processes the relevant facts. Deletion does not erase plaintext
or keys already observed by a malicious user, compromised device, backup tool,
or screen capture.

## Definitions

- **Fact**: immutable protocol bytes identified by the BLAKE3 hash of the
  bytes. Scope and timestamp are local admission metadata.
- **Local fact**: a fact admitted with local scope. Local facts and private
  tags are private store material and must not be synced or sent in connection
  frames.
- **Shareable fact**: a non-local fact whose owning projector has emitted a
  validated `share_fact_with_sync` contribution for a workspace.
- **Admitted output**: a materialized row, context offer, sync-share
  contribution, deferred intent, or purge that has crossed the projection or
  handler commit boundary.
- **Opened content**: decrypted content rows derived from encrypted content
  facts after signer, author, deletion/retention, and local key-material
  context have all validated.
- **DELETED**: content whose target-owned deletion, expiry, or retention-floor
  path has committed locally, including row removal/retraction and any
  authorized self-purge for the target fact.
- **RETIRED**: key material that has been made unavailable for future sharing
  after deletion, expiry, retention-floor advancement, or exact supersession
  proof.
- **SURVIVING CONTENT**: content not covered by the deletion, expiry, or
  retention-floor that caused a root or recipient key to retire.
- **REMOVED**: a user, endpoint, recipient key, or key frontier that current
  projected authority no longer permits for future membership, sending, or key
  sharing in that workspace.

## Adversaries

The names below mostly follow the Quiet threat model, with `SERVER` added for
this prototype's untrusted carrier and sync infrastructure.

- **OWNER** is the workspace creator or root authority holder.
- **MEMBER** is a user and endpoint admitted by valid workspace authority, with
  no extra capabilities.
- **NON-MEMBER** is a user or endpoint that has never been admitted, or was
  REMOVED, with no extra capabilities.
- **DRAGNET** can passively observe and archive network traffic and server-side
  carrier data.
- **NETWORK ACTIVE ATTACKER** can observe, block, delay, replay, reorder, drop,
  or alter network traffic, but has no member private keys.
- **SERVER** has compromised a relay, invite server, range-summary service,
  sync helper, or storage carrier. SERVER can do everything a NETWORK ACTIVE
  ATTACKER can do, can archive all carrier-side bytes and summaries, can answer
  arbitrary compare/have/need/range messages, and can serve stale or forged
  bytes. SERVER has no member signing keys, local endpoint secrets, local
  recipient private keys, local content secrets, or workspace root key unless
  another adversary gives them those keys.
- **MALWARE** has compromised a VICTIM device. It can read the device's current
  app state, plaintext visible to the app, and current local private material,
  and can act as VICTIM going forward.
- **POST-DELETE DEVICE** is MALWARE whose first access to the VICTIM device is
  after the relevant local DELETED/RETIRED transaction has committed. This is
  the device-compromise adversary used by the post-deletion forward-secrecy
  invariants below.
- **UPDATE PROVIDER** can distribute malicious application updates or malicious
  dependencies.

Adversary classes:

- **ACTIVE CARRIER**: NETWORK ACTIVE ATTACKER or SERVER.
- **LOCAL COMPROMISE**: MALWARE or POST-DELETE DEVICE.
- **DELETION COLLUSION**: SERVER plus POST-DELETE DEVICE.

## Security Invariants

### Membership And Authority

**TM-M1: Non-members cannot mint membership.** In the usage scenario,
NON-MEMBER, DRAGNET, NETWORK ACTIVE ATTACKER, and SERVER cannot cause a correct
store to materialize workspace, user, admin, invite, endpoint, content-signer,
recipient-key, or connection membership authority unless the admitted fact has
a valid authority chain from the workspace root or an already valid admin path.

**TM-M2: Sync and connection carriers do not grant authority.** SERVER can
deliver bytes, receipts, range summaries, `have_id`, `need_id`, and opened
frame payloads, but those carrier facts cannot by themselves create membership,
admin status, content-signer status, key-recipient status, or connection
authority. The owning auth or connection projector must still validate the
fact type, scope, signer, transcript, and matched context.

**TM-M3: Authority is workspace scoped.** A valid authority fact, context
offer, key wrap, share contribution, or connection route for one workspace
cannot authorize membership, content admission, key sharing, or sync visibility
in another workspace.

**TM-M4: Members cannot escalate without authority.** MEMBER cannot become
OWNER, admin, invite issuer, device issuer, endpoint signer, or removal
authority unless the projected auth graph contains the required already-valid
authority path.

**TM-M5: Removal and retirement stop future sharing.** After a removal,
recipient-key supersession, frontier retirement, or retention-floor proof has
committed, correct stores do not create new shareability rows or key-wrap edges
that treat the removed or retired authority as current.

### Confidentiality

**TM-C1: Carriers cannot read encrypted content plaintext.** DRAGNET, NETWORK
ACTIVE ATTACKER, and SERVER cannot learn plaintext message text, reaction
values, sealed file metadata, or file bytes from network frames, stored facts,
range summaries, or sync dependency closure unless they also obtain local key
material that covers the content coordinate.

**TM-C2: Local private material is not syncable.** Local endpoint secrets,
invite secrets, signer secrets, recipient private keys, local root secrets, and
local history-node secrets are never emitted as sync-share contributions and
are rejected by connection sendability checks.

**TM-C3: Dependency closure stays inside authorization boundaries.** SERVER can
ask for arbitrary ranges or fact ids, but sync response and live-tail paths only
select facts that are shareable on that connection, non-local, not purged, and
visible in the authorized workspace. Recursive dependency expansion cannot
cross into private facts, unauthorized workspaces, or missing/purged facts.

**TM-C4: Key requests are protocol facts, not server privileges.** SERVER
cannot cause a correct member to wrap root or retained key material to an
unauthorized recipient. Key-wrap creation must validate recipient key, source
secret, signer, frontier, source coordinate, workspace, and post-retirement
shareability.

**TM-C5: Opening content requires both authority and key coverage.** A correct
store does not write opened-message, reaction, file, or file-slice read rows
unless the content signer/author context validates, the target is not deleted
or retired for that row, and local secret coverage proves the relevant
frontier/minute/target coordinate.

### Impersonation And Integrity

**TM-I1: Content authorship is signer-bound.** NON-MEMBER, NETWORK ACTIVE
ATTACKER, and SERVER cannot cause a correct store to materialize a message,
reaction, file, file slice, deletion, or retention-policy row as if authored by
a MEMBER unless the fact verifies under an authorized signer for that member
and workspace.

**TM-I2: Admin authority is not content-signing authority.** OWNER or an admin
can exercise the membership and policy authority granted by the auth graph, but
that authority alone does not let them create accepted content as another
member. Content admission still requires the other member's authorized endpoint
signer path.

**TM-I3: Carrier replay cannot create a different accepted statement.** ACTIVE
CARRIER can replay an old valid fact, but content identity, fixed signing
transcripts, context validation, and idempotent projection prevent that replay
from changing the sender, content body, deletion target, key coordinate, or
workspace of the accepted statement.

**TM-I4: Receipts and frames are evidence, not authority.** A receipt,
observation, request, connection, or established frame can prove only the
transport relationship its owning projector validates. Child auth, content, and
sync facts opened from a frame must still pass their own admission rules.

### Deletion And Post-Deletion Forward Secrecy

**TM-D1: Deletion is target-owned.** A deletion, expiry, or retention-floor
fact can publish purge context only after the owning projector validates the
author or admin authority and the exact target coordinate. The target projector
consumes that context and can delete only target-owned rows and purge only its
own fact id.

**TM-D2: Deleted content is no longer locally materialized or shareable.** Once
a correct device has committed DELETED for a target message, file, reaction, or
slice, user-visible rows for that target and dependent rows are removed or
marked deleted, sync shareability is retracted where required, and connection
send paths cannot re-send the purged local bytes as live content.

**TM-D3: Key retirement removes derivation paths for deleted content.** After
deletion, expiry, or retention-floor advancement makes a frontier root
unavailable, correct stores purge or retire the root and superseded recipient
private material according to exact proof. Remaining retained history-node
secrets may cover SURVIVING CONTENT, but must not cover the deleted leaf or
reconstruct the retired root.

**TM-D4: Server replay cannot resurrect a local deletion.** After DELETED
commits locally, SERVER can replay old facts, range summaries, `have_id`,
`need_id`, key requests, or carrier frames, but correct projection either keeps
the target deleted, waits for required context, or rejects the mismatched
context. Replayed carrier data cannot make the old target live again without a
new independently valid content fact that is outside the deleted target.

**TM-D5: Server plus post-delete device compromise cannot decrypt deleted
content from remaining state.** In the DELETION COLLUSION scenario, SERVER has
archived all carrier-side facts, frames, summaries, and key wraps, and
POST-DELETE DEVICE reads all remaining app-owned local state after the local
DELETED/RETIRED commit. If neither adversary observed the plaintext, the
deleted leaf key, the retired root, or the victim device before that commit,
they cannot decrypt the deleted content from remaining state.

**TM-D6: Post-deletion key healing cannot resurrect removed roots.** A valid
key request after root retirement may cause a correct responder to wrap
retained path nodes needed for SURVIVING CONTENT. It cannot cause the responder
to wrap the retired root, a deleted leaf, or fresh key material to a superseded
recipient key. Duplicate requests for the same deterministic edge converge
instead of amplifying key material.

## Proof Mapping

The Verus proof plan should connect these threat invariants to executable
boundaries. The mapping below names the first proof surfaces that matter for
review.

| Invariants | Proof surface |
| --- | --- |
| TM-M1, TM-M3, TM-M4 | Auth authority DAG predicates: `valid_workspace_offer`, `valid_user_offer`, `valid_admin_offer`, `valid_device_invite_offer`, `valid_endpoint_shared_offer`, `valid_content_signer_offer`. |
| TM-M2, TM-I4 | Connection handshake and receipt predicates: request/connection/frame projectors prove receipts and opened carrier facts do not grant semantic authority. |
| TM-M5, TM-C4, TM-D3, TM-D6 | Auth key-material predicates and handlers: `valid_recipient_key_offer`, `valid_wrap_source_offer`, `valid_secret_coverage_offer`, `valid_key_wrap_fact`, `create_key_wrap`, and `unwrap_key_wrap`. |
| TM-C1, TM-C5, TM-I1, TM-I2 | Content admission predicates for message, reaction, file, file-slice, deletion, and retention-policy projectors. |
| TM-C2, TM-C3, TM-D2, TM-D4 | Sync shareability and connection sendability: `share_fact_with_sync`, dependency closure, connection-visible send filters, and local/private tag rejection. |
| TM-D1, TM-D2, TM-D4 | Content deletion/retention proof: deletion facts publish `content_purged` only for proved targets, and target projectors self-purge only their own facts. |
| TM-D5 | Cross-scope composition of content deletion, auth root retirement, retained-node coverage, sync retraction, and local/private send rejection. |

The core induction target remains:

```text
Every materialized row, emitted authority offer, emitted sync-share contribution,
emitted deferred intent, and emitted purge has a derivation from valid facts and
valid matched context.
```

## Known Weaknesses

- A malicious MEMBER can save plaintext, take screenshots, copy files, archive
  app data, or run a modified client that refuses to delete. Context deletion
  does not provide remote erasure from malicious members.
- MALWARE that compromises a device before or during deletion can read
  plaintext and keys available at that time, block deletion, and act as the
  victim until removal or key rotation takes effect.
- This model targets app-owned logical state after committed purge/retirement.
  It does not currently prove raw block-device secure deletion, SSD wear-level
  erasure, OS swap removal, crash dump removal, filesystem journal erasure, or
  cloud backup deletion.
- ACTIVE CARRIER and SERVER can deny service, delay deletion propagation,
  partition peers, replay stale traffic, and make sync incomplete. Availability
  is not a listed invariant.
- Traffic metadata is not protected by this prototype threat model. Carriers
  may learn IP addresses, timing, fact sizes, workspace activity, and other
  metadata unless a separate transport layer hides it.
- UPDATE PROVIDER can ship malicious code and should be treated as LOCAL
  COMPROMISE for affected devices.
- A REMOVED member may retain facts, plaintext, or keys received before
  removal. The intended invariant is that correct peers stop future sharing and
  future key wrapping after removal or retirement commits.
- Transcript ordering and timestamp consistency beyond fixed fact bytes,
  signatures, and deterministic projection are not separately promised here.
- Cryptographic primitive bugs, weak randomness, OS compromise, side channels,
  and social compromise of out-of-band invitation channels are outside this
  prototype threat model.

## Review Questions

- Should REMOVED be modeled as full user removal now, or only as endpoint,
  recipient-key, and frontier retirement until user removal semantics are
  complete?
- What exact product state should mean "deleted across the workspace" once
  multi-device acknowledgments exist? This document currently defines DELETED
  per local device.
- Should SERVER include compromise of an invite-server endpoint's local device
  key, or should that remain modeled as LOCAL COMPROMISE of that endpoint?
