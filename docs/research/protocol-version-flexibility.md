# Protocol Version Flexibility Design

This note records the poc-10 protocol evolution policy. The runtime uses
immutable canonical fact bytes, deterministic fact ids, fixed wire layouts,
scope-owned codecs, pure projectors, and connection frames with a public `TRNS`
tag plus version byte. Version flexibility should preserve those properties
instead of making core a compatibility layer.

The product case is one provider-signed client family, not broad
interoperability between independent implementations. Users can delay upgrades,
platform releases can land at different times, and a bad release can strand a
platform. The invariant is still strict:

> Any shared production action emitted under the current production protocol ceiling must be visible to every supported production client.

The policy below is intentionally conservative. It uses a global production
protocol ceiling, not per-workspace or per-peer readiness, because proving that
every relevant device in every workspace is upgraded is a consensus problem
outside the current design.

## Core Policy

The policy has four separations:

- **Protocol ceiling.** Production clients may create, admit, project, and
  display shared durable protocol no newer than the global provider-scheduled
  protocol ceiling. A binary may contain future protocol code, but production
  must not register that reader, projector, or command path until the ceiling
  advances.
- **Release safety.** A release may be allowed or blocked independently from
  the facts it wrote. Releases embed `warn_after` and `expires_at`; emergency
  deprecation uses a signed, monotonic, persisted `must_update` canary.
- **Fact-version safety.** A fact version is deprecated only if that fact
  format or validation rule is unsafe. Security-deprecating a client release
  does not automatically invalidate historical facts written by that release.
- **Replay truth.** Retained facts, not rows or old queued intents, are the
  durable source of truth. Updates wipe materialized state and replay retained
  facts through historical adapters plus the ceiling-active registry.

Operational rules:

1. **One protocol ceiling.** The production ceiling is global product state,
   not per peer, group, workspace, or active-client observation. New shared
   durable fact versions become producible and admissible in production only
   when the ceiling allows them.
2. **Scheduled ceiling advance.** Ceiling changes are provider-scheduled at a
   wall-clock `ceiling_raises_at` time. Choose this after old-client warning and
   expiry windows plus clock-skew grace. Until that time, every production
   client writes the old ceiling even if its implementation head is newer.
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
   current read-model rows and durable needs, but they must preserve the old
   semantic contract and must not grant an old fact new authority.
7. **Signed facts are not assumed rewritable.** Available authors or devices may
   issue replacement or superseding facts for safety or compaction, but
   correctness must remain safe when old signers never return.
8. **Replay is deterministic and local.** Replay may rebuild rows, sync indexes,
   negentropy trees, due-time indexes, and durable work queues. Replay must not
   observe fresh time, send network frames, perform attachment IO, fire timers,
   or sign new shared facts. Idempotent handlers perform those effects after
   replay from declared durable needs.
9. **Permanent state is facts.** Auth, retention, purge, deletion,
   disappearance, and durable work requirements must be facts or derivable from
   retained facts. Purge facts must exist before purged data disappears, so
   replay cannot resurrect deleted or expired state.
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

Plaintext usernames are the useful example. If `user_v1` exposes a name in
plaintext and the product decides that is a privacy bug, the next ceiling can
introduce `user_v2` with encrypted profile text. Existing `user_v1` facts do
not magically become safe. The safe outcomes are a policy fact that hides or
quarantines old plaintext names, optional user/device reissue of encrypted
replacement facts, and an old adapter that preserves authority identity without
continuing to display unsafe plaintext.

## Intents And Replay

Facts are the compatibility boundary; intents are current-runtime work. On
upgrade, old queued intents are not the durable source of correctness. Retained
facts replay through their versioned adapters and produce current durable needs
or current intent payloads.

For example, an old key-coverage fact or old key-wrap request can replay into:

```text
ensure_key_wrap_coverage_vCurrent(workspace, frontier, recipient, source)
```

The current handler fulfills that need idempotently if the required local
secret still exists. If the material was purged or never available, replay
leaves an unsatisfied durable need rather than fabricating coverage.

Pending local user actions need an explicit classification. If losing the work
would lose user-visible shared state, persist a durable local fact before
upgrade. If it is only process state, it may be dropped and retried by UI.

## Connection And Sync

Connection and sync have two independent compatibility surfaces:

- The **transport format** is about opening requests, responses, receipts,
  frames, range compares, have/need facts, and fact bytes.
- The **shared durable protocol** is about what facts production clients are
  allowed to create under the ceiling.

When an old connection or sync request fact is safe to answer, the response
uses the same request version. New clients can keep old request/response
formats for reliability while still enforcing release safety and the production
ceiling. A v1 sync session may transfer facts produced at the current ceiling if
the authenticated peer can understand them; the v1 envelope does not imply v1
content semantics.

## Upgrade Examples

These examples map current poc-10 scopes and the older poc-7/topo event
families to upgrade paths.

| Feature or fact family | Current surface | Upgrade path |
| --- | --- | --- |
| Workspaces, users, admins, invites, endpoints | poc-10 `auth::{workspace,user,admin,user_invite,device_invite,invite_accepted,endpoint,endpoint_shared}`; topo `workspace`, `user`, `admin`, `user_invite`, `device_invite`, `invite_accepted`, `peer_shared`, `endpoint_shared` | Authority changes are ceiling-gated because unsupported clients could admit different actors. Old authority adapters stay forever. A security fix may reject malformed old authority facts, but must not grant old facts new authority. |
| Encrypted usernames and profile data | topo `user` has plaintext `username`; poc-10 user/profile naming is auth-owned | Introduce encrypted profile/user facts at a new ceiling. Old plaintext user facts remain authority anchors by default but may be hidden, quarantined, or superseded by policy if plaintext display is unsafe. Reissue encrypted names opportunistically; do not require every old signer. |
| Messages | poc-10 `content::message`; topo `message` | New message body encoding, metadata, mentions, edits, or thread coordinates become readable/projectable and writable in production only at a ceiling raise. Before then they are alpha/test-only or dormant. Old message projectors stay and may output current rows. Unsafe encryption or signature bugs are fact-version safety issues, handled by stricter validation, quarantine, or reissue. |
| Channels, groups, spaces | Not a first-class current poc-10 content family; retention policy already carries `scope_kind` for workspace/channel/thread-shaped scopes | Add the new scope/auth fact family behind the ceiling. Before the ceiling, production clients cannot create channel-only content. After the ceiling, message, file, reaction, deletion, retention, and sync visibility project through the new scope facts. |
| Reactions | poc-10 `content::reaction`; topo `reaction` | New reaction payloads, custom emoji, or reaction deletion semantics are ceiling-gated if they affect shared display. Existing reaction facts keep old meaning and project to current reaction rows. |
| Files and file slices | poc-10 `content::{file,file_slice,file_deletion}`; topo `file`, `file_slice` | New file descriptors, chunking, BAO proof formats, metadata encryption, or storage backends are new fact versions gated by the ceiling. Old descriptors and slices stay readable. If a proof format is unsafe, quarantine or tighten that fact version instead of converting every slice. |
| Link unfurls | Not a core current family | Local-only unfurl previews can ship anytime. Shared unfurl facts are user-visible content and must wait for the ceiling; the fact should include fetched snapshot, origin, timestamp, and authority so replay does not refetch the web. |
| Online status and presence | Not durable content today | Ephemeral presence can use highest-common transport/session formats because it is not retained workspace state. Durable "last seen" or status history facts are shared content and follow the ceiling. |
| Message deletion, file deletion, disappearing messages, retention | poc-10 `content::{message_deletion,file_deletion,retention_policy,purge}`; topo `message_deletion`, `removal`-style frontiers | Purge and retention policy are permanent facts. New deletion rules or disappearing-message policies are ceiling-gated. Purge facts must be retained long enough to prevent replay resurrection; target projectors own their own row and fact purge. |
| Forward secrecy history keys | poc-10 `auth::{local_history_node_secret,local_secret_retirement,removal_frontier}`; topo `key_history`, `removal`, `key_rotation` | Key-tree coordinate changes are ceiling-gated for shared facts. Old retained key-node facts stay readable. Replay derives current key-retention and wrap needs, but handlers perform wrapping and IO after replay. |
| TreeKEM or key-wrap redesign | poc-10 `auth::{recipient_key,key_request,key_wrap,create_key_wrap,unwrap_key_wrap}`; topo `key_request`, `key_shared`, `key_rotation`, `key_secret` | Treat as a new auth/key-material protocol under the ceiling. Keep old key-wrap and request adapters forever. Old projectors should emit current deterministic coverage needs; current handlers create new wraps only when local secret material proves they can. |
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
requires a manifest entry naming its first production ceiling, old adapters,
security-deprecation policy, replay output, and tests that prove above-ceiling
facts are rejected or quarantined in production and accepted only once the
ceiling enables them.
