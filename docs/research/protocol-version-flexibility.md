# Protocol Version Flexibility Design

This note records the poc-10 protocol evolution policy. The runtime uses
immutable canonical fact bytes, deterministic fact ids, fixed wire layouts,
scope-owned codecs, pure projectors, and connection frames with a public `TRNS`
tag plus version byte. Version flexibility should preserve those properties
instead of making core a compatibility layer.

The product case is one provider-signed client family, not broad
interoperability between independent implementations. Users can delay upgrades,
platform releases can land at different times, and a bad release can strand a
platform. The visibility invariant is:

> Any shared production action emitted under the current production protocol ceiling must be visible to every supported production client.

This policy is intentionally conservative. It uses a global production
protocol ceiling, not per-workspace or per-peer readiness, because proving that
every relevant device in every workspace is upgraded is a consensus problem
that this policy does not introduce.

## Core Policy

The policy has four separations:

- **Protocol ceiling.** Production clients may create, admit, project, and
  display shared durable protocol no newer than the global expiry-derived
  protocol ceiling. A binary may contain future protocol code, but production
  must not register that reader, projector, or command path until every
  still-usable non-capable release has expired or been security-deprecated.
- **Release safety.** A release may be allowed or blocked independently from
  the facts it wrote. Releases embed `warn_after` and `expires_at`, plus their
  shared durable protocol capabilities; emergency deprecation uses a signed,
  monotonic, persisted `must_update` canary.
- **Fact-version safety.** A fact version is deprecated only if that fact
  format or validation rule is unsafe. Security-deprecating a client release
  does not automatically invalidate historical facts written by that release.
- **Replay truth.** Retained facts, not rows or queued intents, are the
  durable source of truth. Updates wipe materialized state and replay retained
  facts through historical adapters plus the ceiling-active registry.

Operational rules:

1. **One protocol ceiling.** At a trusted time, a release is still usable if it
   is not past `expires_at` and has not been security-deprecated by canary. The
   production ceiling is the greatest shared durable protocol version supported
   by every still-usable release. New shared durable fact versions become
   producible and admissible in production only when the ceiling allows them.
2. **Expiry-driven ceiling advance.** A capability becomes ceiling-active when
   the last still-usable release that cannot create, admit, project, or display
   it expires or is security-deprecated. In a monotonic release train, the
   blocking release is the oldest still-usable non-capable release, and its
   `expires_at` is the ceiling transition. If a grace window is needed, set that
   release's `expires_at` later; do not add a separate readiness signal or
   infer readiness from observed active clients.
3. **Trusted time.** Clients persist the greatest trusted time learned from
   embedded release metadata, signed registry facts, or signed canaries. If the
   local clock rolls backward too far, shared production use blocks until time
   is plausible again.
4. **Alpha isolation.** Alpha, dogfood, and test builds may register the
   implementation head. Production workspaces reject or quarantine above-ceiling
   facts instead of reading them.
5. **Old readers stay.** Old fact adapters and projectors stay in the codebase
   for retained history because a user may later join a workspace containing
   old retained facts.
6. **Old meaning stays old.** Old adapters may tighten validation or emit
   ceiling-era read-model rows and durable needs, but they must preserve the old
   semantic contract and must not grant an old fact new authority.
7. **Signed facts are not assumed rewritable.** Available authors or devices may
   issue replacement or superseding facts for safety or compaction, but
   correctness must remain safe when old signers never return.
8. **Replay is deterministic and local.** Replay may rebuild rows, sync indexes,
   negentropy trees, due-time indexes, and durable work queues. Replay must not
   observe fresh time, send network frames, perform attachment IO, fire timers,
   or sign new shared facts. Idempotent handlers perform those effects after
   replay from declared durable needs. After an upgrade wipe, full replay and
   purge completion must finish before any network receive, network send, sync
   advertisement, or connection retry resumes.
9. **Permanent state is facts.** Auth, retention, purge, deletion,
   disappearance, and durable work requirements must be facts or derivable from
   retained facts. Purge facts must be preserved until every protected byte,
   row, and local secret they cover is gone. During replay, preserved purge facts
   define absence: matching stale material is not usable, and local purge work
   must complete before the runtime reconnects.
10. **Transport compatibility is separate.** Old connection and sync formats may
    be parsed and answered indefinitely for reliability. A vN request receives a
    vN-shaped response. Transport compatibility does not raise the production
    protocol ceiling or make an expired client part of the visibility
    guarantee.

## Security Changes

Security changes should name the smallest unsafe surface:

- **Unsafe release:** block the binary with embedded expiry or a `must_update`
  canary. Historical facts from that release stay valid unless their fact
  version is also unsafe.
- **Unsafe fact version:** tighten that version's adapter, quarantine affected
  facts, or add a durable policy fact that invalidates a bounded subset. Ask
  live signers to reissue when useful, but do not require universal re-signing
  for correctness.
- **Unsafe derived state:** wipe and replay. If the source facts are safe, no
  durable migration is needed.

Plaintext usernames are the useful example. In poc-10,
`auth::user::UserFact` contains plaintext `username`. That fact is signed by
the user-invite key that admitted the user; later devices usually have only
their endpoint signing key, proven by `auth::endpoint_shared`, not the original
invite key. A normal device therefore cannot reissue the same `auth::user`
shape unless it still has the original signing key.

The practical fix is a new ceiling-gated profile fact, not a same-shaped user
rewrite:

```text
auth::user_profile_v2 {
  workspace_id,
  subject_user_id,          // old auth_user fact id; still the membership anchor
  supersedes_profile_id,
  encrypted_display_name,
  signer_endpoint_shared_id,
  signer_public_key,
  signature,
}
```

`user_profile_v2` is signed by an admitted endpoint. Its projector needs the
old `auth_user` fact and the signer `auth_endpoint_shared` fact. It admits only
when both are in the same workspace,
`endpoint_shared.user_authority_fact_id == subject_user_id`, and the signer
public key matches the endpoint_shared row. The new fact may replace profile
display data only. It cannot change membership, admin authority, the original
user public key, or the subject user id.

The old `user_v1` adapter then preserves authority identity without
materializing unsafe plaintext into display rows. A policy fact can hide or
quarantine old plaintext names, and live user devices can publish encrypted
profile facts opportunistically. If the raw plaintext fact bytes themselves
must be purged, the protocol first needs an authority-preserving replacement or
tombstone; otherwise old content that names `author_user_id == user_v1.id`
loses its context proof.

## Intents And Replay

Facts are the compatibility boundary; intents are current-runtime work. On
upgrade, queued intents are not the durable source of correctness. Retained
facts replay through their versioned adapters and produce ceiling-active
durable needs or current intent payloads. Handlers must be idempotent because
replay may enqueue work that was already completed before the upgrade.

Current poc-10 intent replay behavior:

| Intent kind | Source facts | Replay behavior |
| --- | --- | --- |
| `send_bootstrap_connection_request` | local `connection_request` plus local ephemeral secret | Local socket attempt. Drop queued local sends on upgrade; replay the request and retry time wake until a `connection_response` exists. |
| `create_connection_response` | received `connection_request`, local invite secret, local fact receipt | Rebuild responder work only when the request is still valid locally. If an old local response fact exists, request projection sees it; otherwise a new retryable response may be created. |
| `send_sync_compare_response` | `sync_compare` | Recompute child compares and exact fact sends from the current shareable index. Stale compare facts are harmless sync prompts. |
| `send_needed_fact_id` | `sync_have_id` | If the advertised fact is already present, no-op; otherwise create a `sync_need_id` and send it. |
| `send_requested_fact` | `sync_need_id` | Send the requested fact only if it exists and is shareable on that connection; otherwise no-op. |
| `share_fact_with_sync` | any admitted shareable fact, or a retraction | Rebuild shareable-fact rows, dependency context rows, and negentropy summaries. Reject local-only bytes. Live-tail sends are derived side effects. |
| `seed_connection_sync` | `connection_response` | Rebuild the root compare for a connection from the current shareable index. Repeated seeds are safe. |
| `create_key_wrap` | `recipient_key` or `key_request`, wrap source, local signer secret | Recreate the deterministic `key_wrap` only if local source and signing material still exist. Replay must not fabricate missing key material. |
| `unwrap_key_wrap` | `key_wrap`, recipient key, local recipient secret, frontier | Reopen the wrap only when replay finds no preserved purge or retirement fact covering the local recipient capability. A retained wrap is not enough; purge facts make matching local recipient material unusable, and replay must not resurrect the opened secret. |
| `send_facts_on_connection` | sync compare/need/seed/live-tail work | Package current fact bytes into connection frames. This is derived transport work, not content truth. |
| `send_network_frame` | packaged connection frame | Final local socket write. Drop queued local sends on upgrade; replay can rederive them from sync or connection retry facts. |
| `receive_network_frame` | daemon inbound bytes | Local boundary before canonical facts exist. Once handled, replay starts from the staged request, response, frame, and receipt facts. If dropped before admission, peer retry or sync recovers. |

Pending local user actions need the same classification. If losing the work
would lose user-visible shared state, persist a durable local fact before
upgrade. If it is only process state, it may be dropped and retried by UI.

## Connection And Sync

Connection and sync have two independent compatibility surfaces:

- The **transport format** is about opening requests, responses, receipts,
  frames, range compares, have/need facts, and fact bytes.
- The **shared durable protocol** is about what facts production clients are
  allowed to create under the ceiling.

For a still-usable older release, the ceiling already guarantees that shared
durable facts are within the older release's admission and projection surface.
The mixed-version problem is therefore transport selection, not content
fallback.

Connection behavior:

1. **Newer initiates to older.** The newer client sends the bootstrap request
   version named by the invite/link/endpoint metadata. If no trustworthy
   metadata exists, it uses the oldest still-safe bootstrap version. The older
   responder answers in that same version. No pre-bootstrap negotiation is
   required, so an active network attacker does not get a separate downgrade
   choice.
2. **Older initiates to newer.** The newer client parses the old request,
   validates the same invite-secret, local-endpoint, and receipt proofs, and
   creates an old-shaped response. The request version selects the response
   version.
3. **Established session.** The session starts with the request/response
   carrier version. A newer carrier can be negotiated later only inside the
   authenticated session. Until then, connection frames, receipts, and local
   send/receive intents use the established carrier.
4. **Expired older release.** Safe old request/response formats may still be
   answered so users can recover, update, or finish old sync. That does not make
   the expired release part of the production visibility guarantee, and it does
   not lower the durable protocol ceiling.

Sync behavior:

1. **Envelope version.** The connection's carrier version selects the
   compare/have/need/range/frame shape. A newer client answers an old compare
   with old-shaped compare children, old-shaped have/need facts, and old-shaped
   frame bundles.
2. **Fact bytes stay canonical.** Sync carries opaque fact bytes plus ids and
   dependency closure. It does not reinterpret fact contents. Receiving still
   routes by the fact's own type tag and current ceiling-active adapters.
3. **Dependency closure.** A newer sender should include projector-declared
   context facts with the requested fact when the old envelope can carry them.
   If the old sync version can only ask by exact id, it falls back to have/need
   rounds; correctness is preserved, latency is worse.
4. **Carrier limits are real.** If an old frame or sync version cannot carry a
   new fact's byte size or required dependency shape, that fact family cannot
   become ceiling-active until every release limited by that carrier has
   expired, or until the new fact family has an old-carrier-compatible chunking
   path.
5. **Current-ceiling transfer.** A v1 sync session may carry current-ceiling
   facts when the authenticated peer's release can parse and admit those fact
   families. The `v1` label describes only the sync envelope, not the semantic
   version of the facts inside.

## Upgrade Examples

These examples map poc-10 scopes and poc-7/topo event families to upgrade
paths.

| Feature or fact family | Current surface | Upgrade path |
| --- | --- | --- |
| Workspaces, users, admins, invites, endpoints | poc-10 `auth::{workspace,user,admin,user_invite,device_invite,invite_accepted,endpoint,endpoint_shared}`; topo `workspace`, `user`, `admin`, `user_invite`, `device_invite`, `invite_accepted`, `peer_shared`, `endpoint_shared` | Authority changes are ceiling-gated because unsupported clients could admit different actors. Old authority adapters stay forever. A security fix may reject malformed old authority facts, but must not grant old facts new authority. |
| Encrypted usernames and profile data | topo `user` has plaintext `username`; poc-10 user/profile naming is auth-owned | Introduce encrypted profile/user facts at a new ceiling. Old plaintext user facts remain authority anchors by default but may be hidden, quarantined, or superseded by policy if plaintext display is unsafe. Reissue encrypted names opportunistically; do not require every old signer. |
| Messages | poc-10 `content::message`; topo `message` | New message body encoding, metadata, mentions, edits, or thread coordinates become readable/projectable and writable in production only at a ceiling raise. Before then they are alpha/test-only or dormant. Old message projectors stay and may output current rows. Unsafe encryption or signature bugs are fact-version safety issues, handled by stricter validation, quarantine, or reissue. |
| Channels, groups, spaces | No first-class poc-10 content family; retention policy already carries `scope_kind` for workspace/channel/thread-shaped scopes | Add the new scope/auth fact family behind the ceiling. Before the ceiling, production clients cannot create channel-only content. After the ceiling, message, file, reaction, deletion, retention, and sync visibility project through the new scope facts. |
| Reactions | poc-10 `content::reaction`; topo `reaction` | New reaction payloads, custom emoji, or reaction deletion semantics are ceiling-gated if they affect shared display. Existing reaction facts keep old meaning and project to current reaction rows. |
| Files and file slices | poc-10 `content::{file,file_slice,file_deletion}`; topo `file`, `file_slice` | New file descriptors, chunking, BAO proof formats, metadata encryption, or storage backends are new fact versions gated by the ceiling. Old descriptors and slices stay readable. If a proof format is unsafe, quarantine or tighten that fact version instead of converting every slice. |
| Link unfurls | No poc-10 shared durable family | Local-only unfurl previews can ship anytime. Shared unfurl facts are user-visible content and must wait for the ceiling; the fact should include fetched snapshot, origin, timestamp, and authority so replay does not refetch the web. |
| Online status and presence | No poc-10 durable content family | Ephemeral presence can use highest-common transport/session formats because it is not retained workspace state. Durable "last seen" or status history facts are shared content and follow the ceiling. |
| Message deletion, file deletion, disappearing messages, retention | poc-10 `content::{message_deletion,file_deletion,retention_policy,purge}`; topo `message_deletion`, `removal`-style frontiers | Purge and retention policy are permanent facts. New deletion rules or disappearing-message policies are ceiling-gated. Purge facts must be retained long enough to prevent replay resurrection; target projectors own their own row and fact purge. |
| Forward secrecy history keys | poc-10 `auth::{local_history_node_secret,local_secret_retirement,removal_frontier}`; topo `key_history`, `removal`, `key_rotation` | Key-tree coordinate changes are ceiling-gated for shared facts. Old retained key-node facts stay readable. Replay derives current key-retention and wrap needs, but handlers perform wrapping and IO after replay. |
| TreeKEM or key-wrap redesign | poc-10 `auth::{recipient_key,key_request,key_wrap,create_key_wrap,unwrap_key_wrap}`; topo `key_request`, `key_shared`, `key_rotation`, `key_secret` | Treat as a new auth/key-material protocol under the ceiling. Keep old key-wrap and request adapters forever. Old projectors should emit ceiling-active deterministic coverage needs; registered handlers create new wraps only when local secret material proves they can. |
| Connection bootstrap, receipts, frames | poc-10 `connection::{request,response,bootstrap_request,bootstrap_response,fact_receipt,frame_*}` | Keep old safe request/response formats for reliability and answer in the request version. New handshake or frame formats can be negotiated by endpoints, but they do not affect the shared durable ceiling. |
| Sync and negentropy | poc-10 `sync::{compare,have_id,need_id,range_request,shared_fact}`; topo negentropy and dependency sync state | New sync algorithms or range-summary encodings may be negotiated per session. Sync rows, trees, and due work are replay-derived local state. Sync must move fact bytes and dependency closure without reinterpreting fact semantics. |

## Implementation Shape

Core should stay protocol-neutral:

- route facts by tag and version to scope-owned adapters;
- route command construction and fact admission through protocol-ceiling checks;
- wipe and replay materialized state on upgrade;
- store signed release/canary/time observations as durable local facts;
- keep old connection/sync codecs separate from old fact projectors.

Scope modules own the compatibility decisions. Adding or changing a fact family
requires a manifest entry naming the releases that support it, the blocking
non-capable releases and their expiries, old adapters, security-deprecation
policy, replay output, and tests that prove above-ceiling facts are rejected or
quarantined in production and accepted only once the ceiling enables them.
