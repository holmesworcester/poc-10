# Poc-10 Cutover Checklist

This is the working checklist for finishing the poc-10 rewrite. The destination
architecture is `new_architecture.md`; encryption/key-rotation rules are in
`encryption.md`. Reviewers should use this as the acceptance list and fail the
work on any fake or missing behavior.

## Review Loop

- [ ] A reviewer has checked this checklist against the current tree.
- [ ] Every review finding is either fixed or represented by a failing/ignored
  guardrail test with the exact blocker named.
- [ ] No item is marked done because a comment says it is deferred. Comments are
  useful only when paired with a concrete test or a listed blocker below.
- [ ] If a projector, handler, command, or CLI path is fake, row-only when
  context is required, or looser than poc-8, add the missing behavior or a
  failing test before continuing.
- [ ] The loop repeats until review says target poc-10 is real,
  poc-8-equivalent where claimed, and free of old-mechanism holdovers.

Reviewer instructions:

1. Read this checklist first.
2. Inspect production code, not only tests.
3. Compare target behavior with the corresponding poc-8 projector, command,
   worker, or CLI test.
4. Fail on hidden dumping grounds, unbounded handlers, fake response paths,
   placeholder crypto/transit/sync behavior, missing need/offer relationships,
   or missing authorization checks.
5. Report findings as file paths plus required fixes. Prefer concrete failing
   tests over prose.

## Source Shape

- [x] Product binary is `match`, not `topo`, `demo`, or `smoke`.
- [x] The old source island has been removed from the target tree.
- [x] The old root command/fact/handler manifests are gone; manifests live
  under `src/protocol/`.
- [x] No `src/workers`, worker catalog, round-robin scheduler, ready queue,
  blocked queue, recently-valid queue, or pending-reprojection queue remains in
  the active target tree.
- [ ] Runtime code is consolidated: core owns the generic runtime/app facade;
  protocol supplies the registry; fact modules and handlers do not know the
  product entrypoint.
- [ ] Fact modules use consistent files:
  `fact.rs`, `layout.rs`, `create.rs`, `commands.rs`, `queries.rs`,
  `matchers.rs`, `project.rs`, `rows.rs`, and module-specific small files only
  when they make the projector clearer.
- [ ] Multi-fact bundles are split into fact-family modules. The current
  `src/protocol/facts/encryption/` bundle is not acceptable as final shape:
  recipient keys, local recipient keys, removal frontiers, local key secrets,
  key requests, key wraps, and retained/history-node key material each need
  their own fact module shape with local `fact.rs`, `layout.rs`, `project.rs`,
  and only the relevant `create.rs`/`commands.rs`/`rows.rs`.
- [x] Sync follows the same rule. `src/protocol/facts/sync/` must not be a
  dumping folder for range/key/support facts. The active tree keeps
  `sync_compare`, `sync_have_id`, `sync_need_id`, and `sync_shared_fact` as
  separate modules. Dep-aware subrange sync is deferred; if range requests,
  encrypted-root advertisements, or key-wrap availability return, add them back
  as separate fact-family modules with their own `fact.rs`, `layout.rs`, and
  `project.rs`.
- [ ] No hidden `project/` subtrees remain unless explicitly justified; split
  projector families should use clear flat names.
- [ ] No dumping-ground files exist. `mod.rs`, broad `schema.rs`, broad
  `codec.rs`, and broad `cli.rs` are not allowed as logic sinks.
- [ ] Schema is declared only in the three DSL files:
  `src/core/schema.p8sql`, `src/protocol/facts/schema.p8sql`,
  `src/protocol/intents/schema.p8sql`.

## Projector Contract

- [ ] Every target projector reads like: decode, validate local invariants,
  declare needs, inspect supplied context, validate context authority, emit
  offers/intents.
- [ ] A projector that needs another fact emits a `ContextNeed` and returns
  without materializing state until matching context is supplied.
- [ ] Projectors inspect context through typed/indexed `ProjectionContext`
  lookups (`payload_for`, `payload_for_checked`, or `matched_payloads_for`),
  not ad hoc `matched_context()` scans.
- [ ] A projector that can be re-run by later updates keeps standing needs for
  those updates.
- [ ] Projectors never query SQLite directly and never call handlers, workers,
  network code, or other stateful services.
- [ ] Projectors may use `core::crypto` for deterministic verification,
  signing/envelope checks, and encryption/decryption that is genuinely part of
  projection.
- [ ] Projectors return needs, offers, time wakes, row mutations, and intents.
  Row mutations commit with projection; deferred work is an intent handled
  elsewhere.
- [ ] Root/local facts with no context requirements are explicitly identified;
  every other row-only projector is suspect until proven against poc-8.

## Identity Projectors

- [ ] Workspace projection matches poc-8 root workspace behavior.
- [ ] User-invite projection validates workspace/admin authority through
  need/offer context and signed authority where poc-8 required it.
- [ ] User projection waits for matching user-invite key context and checks
  workspace and public-key binding.
- [ ] Admin projection waits for workspace/admin/user context and enforces
  bootstrap and delegated admin rules from poc-8.
- [ ] Device-invite projection waits for user and optional user-invite context,
  checks workspace/user/key binding, and emits the invite-key offer used by
  endpoint_shared.
- [ ] Invite-server projection waits for workspace/admin context, checks
  authority, and emits the invite-server key offer used by endpoint_shared.
- [ ] Endpoint-shared projection is not row-only: it waits for either
  device-invite-key or invite-server-key context, verifies signer/public-key,
  workspace, user authority, and role, then writes endpoint rows and membership
  rows.
- [ ] Invite-accepted projection waits for invite-secret context and produces
  the real local state/intents needed for bootstrap.
- [ ] Signed envelope validation is integrated for every identity fact that was
  signed in poc-8; raw inner payload projection must not silently admit shared
  authority facts.

## Content Projectors

- [ ] Content message projection validates signer endpoint/user/workspace
  authority, deterministic leaf binding, disappearance setting, and deletion
  updates from poc-8.
- [ ] Message deletion projection waits for target message and author context;
  it only materializes if the deletion author is authorized by poc-8 rules.
- [ ] File projection waits for parent message, deletion updates, and validates
  file metadata/blob invariants from poc-8.
- [ ] File-slice projection waits for parent file context and validates slice
  range/proof/hash rules from poc-8.
- [ ] File deletion projection waits for target file and author/admin context
  and emits purge/cascade intents according to poc-8 behavior.
- [ ] Reaction projection waits for target message context, deletion updates,
  signer/author context, and does not use placeholder deletion layouts.
- [ ] Content-event projection is either removed if redundant or made fully real
  with its poc-8 signature and membership checks.

## Encryption And Key Healing

- [ ] Encryption is split out of the current bundled `src/protocol/facts/encryption/`
  shape. Shared crypto/key-healing helpers may remain in a clearly named helper
  module, but no bundled `EncryptionProjector`, bundled `fact.rs`, bundled
  `layout.rs`, bundled `create.rs`, or bundled `commands.rs` may define several
  fact families at once.
- [ ] Encryption projector layout is consistent and easy to review.
- [ ] Recipient-key projection emits the recipient offer, supersession need, and
  proactive wrap intents only for non-superseded keys.
- [ ] Recipient-key rotation does not rewrap old frontiers for superseded keys.
- [ ] Local recipient-key projection waits for recipient context and emits purge
  intents when superseded.
- [ ] Removal-frontier projection checks admin/root authority and emits frontier
  and sync offers.
- [ ] Local key-secret and history-node projection wait for frontier/source
  context, validate retained path structure, and emit secret coverage offers.
- [ ] Key-request projection waits for recipient/frontier/source/signer context
  and materializes deterministic/idempotent wraps.
- [ ] Signed key-wrap receive path is complete: signed envelope validation,
  signer authority, recipient/frontier context, key-wrap row, sync key offer,
  local unwrap intent when local recipient material exists.
- [ ] Key unwrap writes only local secret facts/offers authorized by the signed
  key wrap.
- [ ] Concurrent join during removal heals through deterministic key requests.
- [ ] Post-deletion retained path key requests can wrap path keys without
  resurrecting a purged frontier root.
- [ ] Key amplification is bounded: no request entropy in wrap identity, no
  repeated wraps for acknowledged/superseded/stable context.
- [ ] Purging of recipient material is event-triggered by deletion/retirement
  facts, not by time-based background GC.

## Transit And Connections

- [ ] Connection request/response projectors wait for invite, ephemeral secret,
  and receive-metadata context as required by poc-8.
- [ ] Transit-received metadata is modeled as a local fact/about-context offer
  so state can track where transit events came from.
- [x] Transit unwrap admits signed key-wrap and sync compare/have/need facts:
  inbound network frame -> receive_transit intent -> authenticated open -> fact
  admission plus transit_received provenance fact.
- [ ] Transit wrap is real: send-on-connection intent -> fixed-size transit
  frame -> network_send intent -> durable send acknowledgement.
- [ ] Connection handlers are bounded and idempotent; they do not define fact
  wire formats, crypto-shaped fake facts, or protocol projection state.
- [ ] Network handlers treat transit frames as opaque bytes.

## Sync And Dep-Aware Range Closure

- [x] Sync compare projection writes the row and emits a response intent when
  `response_requested=true`.
- [ ] Sync response handler computes compare/have facts from current fact
  context and sends them over transit; the remaining cutover is to replace the
  in-memory fact scan with bounded durable range/index state.
- [ ] Sync have/need projectors emit real follow-up intents/offers as needed,
  not only rows if poc-8 responded transitively.
- [ ] Dep-aware sync range closure includes all out-of-range dependency facts
  needed to project in-range facts.
- [ ] Dep-aware sync also includes relevant key-wrap offers for encrypted
  in-range facts so encrypted messages display without day-scale delay.
- [ ] Sync state is durable fact/handler state, not a mutable global `SyncIndex`
  escape hatch.
- [ ] Purge and sync coordinate so purged canonical bytes are not reintroduced,
  while retained path keys needed for surviving ciphertext can still heal.

## Purge, Retention, And Forward Secrecy

- [ ] Content purge is represented as explicit purge/cascade/retirement intents,
  all idempotent and event-triggered.
- [ ] Purge handlers perform physical canonical-byte deletion and local row
  cleanup after the intent is valid.
- [ ] Secret retirement happens after purge commits and does not remove retained
  path keys still needed by surviving ciphertext.
- [ ] Disappearing-message expiry/floor behavior is represented as facts/intents,
  not implicit worker scans.
- [ ] Forward secrecy tests prove deleted frontiers cannot be re-shared while
  retained path keys can still satisfy valid requests.

## Commands And CLI

- [ ] Commands live with their event modules.
- [ ] `create.rs` constructs deterministic facts from explicit params.
- [ ] `commands.rs` owns user-facing workflow composition and may use
  `CommandContext`; automatic/reactive behavior must use intents and handlers.
- [x] `queries.rs` owns only read-only projected-state lookups for its own
  module rows. It must not become context, capability lookup, private-key
  access, projection policy, cross-module workflow, or display composition.
- [x] Local private capabilities are not exposed from `queries.rs`; they live
  behind explicit command/handler capability boundaries or context offers.
- [x] Cross-module read models such as `view`, local workspace membership, and
  display joins live in an explicit read-model/query module, not hidden inside
  a leaf event module's `queries.rs`.
- [ ] `cli.rs` only parses user input and formats output.
- [x] Product `match_app.rs` is routing and lifecycle only. It must not contain
  command business logic, protocol-specific row scans, key derivation, purge
  logic, or command chaining that belongs in fact-module commands/read models
  or handlers.
- [ ] Commands return ids/output only after submitted facts/intents are drained
  enough for read-your-writes behavior.
- [ ] Black-box CLI tests use the real `match` binary and real daemon/runtime
  path. They do not seed rows or assert removed queue state.
- [x] First make poc-8 CLI suites true black-box behavior tests, prove them
  green there, then port those contracts to poc-10 unchanged except for harness
  and binary-name changes.
- [ ] Every non-ignored poc-8 black-box behavior test is ported unchanged except
  for harness and binary-name changes.

## Apples-To-Apples Performance

- [ ] Use `scripts/perf_compare.py` as the concrete runner. It writes measured
  JSON/Markdown results under ignored `target/perf-compare/` and records skipped
  rows when a worktree lacks the inspected equivalent.
- [ ] Smoke command:
  `python3 scripts/perf_compare.py --keep-going`
- [ ] 100k command:
  `python3 scripts/perf_compare.py --keep-going --messages 100000 --sync-messages 100000 --display-messages 10000 --cascade-events 50000`
- [ ] Perf harness can run the same workload against `/home/holmes/poc-7`,
  `/home/holmes/poc-8`, and this poc-10 tree without changing workload
  semantics per repo.
- [ ] 100,000-message projection benchmark records wall time, rows/facts
  produced, database size, and peak memory if available.
- [ ] Sync perf benchmark records time to converge two peers with 100,000
  messages and reports bytes/frames/facts transferred where available.
- [ ] Encrypted-message display-latency benchmark includes messages whose deps
  and key offers are outside the main sync range, so dep-aware sync/key healing
  is tested instead of only local projection.
- [ ] Topo cascade benchmark covers the old cascade workload and reports
  projection/wake counts plus wall time for poc-7, poc-8, and poc-10.
- [ ] Harness has a small smoke mode for CI and a documented full command for
  100,000-message runs. It must never print invented comparison numbers;
  missing metrics are reported as unavailable.
- [ ] Treat the poc-7 sync result as the daemon baseline and poc-8/poc-10 sync
  results as the shared black-box CLI scenario until a single common sync
  harness exists in all three worktrees.
- [ ] Compare poc-8 and poc-10 projection output directly; poc-7 has no
  equivalent 100,000-message projection test in the inspected tree.
- [ ] Perf results are checked into a dated report only after a real local run,
  with machine/runtime details.

## Guardrails And Tests

- [ ] `cargo fmt --check`
- [ ] `cargo test --no-run`
- [ ] `cargo test`
- [ ] `cargo test --test poc10_architecture_boundary_test`
- [ ] `cargo test --test poc10_intent_cleanliness_test`
- [ ] `cargo test --test poc10_protocol_registry_test`
- [ ] `cargo test --test poc10_cutover_todo_test -- --ignored`
- [x] `cargo test --test daemon_lifecycle_cli_test -- --nocapture`
- [x] `cargo test --test poc10_topo_cli_test -- --nocapture`
- [ ] No ignored poc-10 guardrail remains unless it names a real blocker in this
  checklist.
- [ ] Projector tests that are not black-box behavior tests live with the module
  they test, or there is a tracked migration item explaining why they remain in
  `tests/`.

## Current Known Blockers

- [x] Invite/accept/link, invite-server/accept-invite-server, local identity,
  `users`, `peers`, and normal black-box multi-daemon membership flows are
  ported to the target runtime and covered by `invite_accept_cli_test`.
- [x] Target `generate`, `content-count`, `send`, and `messages` have active
  black-box coverage through the `match` binary.
- [x] Encryption CLI flows for recipient rotation, key wrap/access, chop, and
  invite-server key-recipient denial are active and green.
- [ ] `view`, `react`, file send/save/listing, disappearing-message
  expiry/retention/key-derive, leaf-coordinate, cascade perf, and negentropy
  purge/sync-status CLI surfaces remain explicit ignored cutover blockers.
  Current `view_cli_test` status: 4/5 pass; remaining failure is missing
  `react`/file CLI parity, not view selection/rendering for messages.
- [ ] Sync compare response now emits response facts and a transit send intent
  from current facts, but real bounded durable range-index response state is not
  complete yet.
- [ ] `network_send` now resolves connection-request listen routes and attempts
  bounded TCP delivery through core network queues. Remaining gaps: durable send
  acknowledgement/cursors, bidirectional route hints, and nonfatal daemon retry
  policy for offline peers.
- [ ] Transit send still needs schema-generated fixed-layout intent/frame
  codecs for the two supported size classes; current handler tests prove
  bounded TCP send, not the final wire-layout source of truth.
- [ ] General shared signed-fact admission is not complete. Signed key-wrap
  receive is real, but other shared signed fact families still enter through
  module-specific paths and need the same target admission treatment.
- [ ] Removal-frontier projection still has an ignored guardrail because the
  current fact shape lacks signed/admin authority fields.
- [ ] Dep-aware sync has no apples-to-apples perf proof yet for fast display of
  in-range encrypted messages whose deps/key offers are out of range.
- [ ] Purge is not fully decomposed into bounded cascade, physical byte purge,
  retained-secret retirement, and sync-index repair handlers.
- [ ] `match_app.rs` still owns product command routing directly. Active
  guardrail now proves it does not own protocol command business logic; end
  state is a generic core app facade driven by protocol command registries.
- [ ] Content projector parity review found remaining real checks to add:
  content_event/message/file/reaction/deletion projectors must consistently
  need signer endpoint context, validate signer workspace/key/user authority,
  and validate leaf/setting context before row materialization.
- [ ] Guardrails still include ignored cutover TODO tests. A normal non-ignored
  suite passing is not the same as the final review passing.
