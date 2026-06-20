# Test Organization Review

A tree-wide pass that (1) put every unit-test module at the bottom of its scope,
(2) gave each test module a `Tests` section heading in the file's own comment
style, and (3) reordered the `#[test]` functions **most-central-first** — the
tests that exercise the most core logic or prove the most central invariants
read first; broad happy-path/integration tests above narrow single-guard tests.

**Scope & guarantees**
- 85 source files touched (2 reviewed directly, 83 across 10 subagents).
- **No test or production code changed.** For every file the diff was verified to
  remove zero non-blank lines and add only `//` comment lines — i.e. a pure
  permutation of existing `#[test]` blocks plus headings. Verified per-file by
  each worker and re-verified in bulk over all 85 files.
- `cargo fmt` clean; **519 lib tests pass**; committed green
  (`cdabe179`, `009bc2b4`).
- Test *code*, assertions, names, and `#[cfg(test)]` helper items were left
  untouched. Helper fns interleaved with production siblings stayed put (they are
  not tests). Out of scope: the `tests/` integration directory.

---

## Trends (distilled from all per-file findings)

These are the cross-cutting patterns. They matter more than any single file and
drive the proposal at the end.

**1. The codebase was already disciplined about test placement.** Of 85 files,
only **4** had tests intermingled with production code at the file level —
`connection/create_connection.rs`, `sync/shared_fact/index.rs`,
`connection/ephemeral_secret/project.rs`, `connection/frame_small/project.rs` —
each a whole `mod tests`/projector-test module sitting *above* production code.
All four were relocated to the file bottom. Everywhere else tests already sat at
the bottom of their scope; the value added was the ranking and headings.

**2. One dominant file shape: the fact-family triple.** Most `protocol`
files are `decode::tests` + `authenticate::tests` (+ sometimes a top-level
projector/`tests` module). This gave a uniform ranking rule:
- `decode::tests` → led by the **fixed-width roundtrip** (proves the whole
  codec), then sentinel/optional-field branches, then tag/length guards.
- `authenticate::tests` → **canonical admit**, then **`rejects_id_not_matching_bytes`**
  (the id == hash(bytes) binding that authenticate uniquely adds over decode),
  then the inherited `wrong_tag` / `truncated` layout guards.

**3. The single biggest duplication: `authenticate::tests` is structurally
identical across ~25 fact families** — the same canonical/id/wrong_tag/truncated
quartet over a per-fact `canonical_fact()` fixture. Compact per file, but
family-wide it is the prime candidate for a shared macro or table-driven helper.
A secondary cluster of near-duplicate `wrong_tag`+`truncated` layout rejections
repeats in nearly every decode module.

**4. The headline correctness finding: projector *semantic* logic is the most
common coverage gap.** Many fact-family files thoroughly test decode +
authenticate (+ row builders) but have **no in-file test of `project_semantic`** —
the context-wait → materialize → retract/purge behavior that is the actual
protocol. This is exactly where `ReaderVerdict` came back `partial`: the top
tests prove the bytes are well-formed but not how the fact *behaves*. Affected
(projector untested or barely touched in-file): `sync/shared_fact`,
`sync/range_request`, `connection/fact_receipt`, `connection/frame_observation`,
`connection/close`, `connection/frame_small`, `auth/invite_secret`,
`auth/key_wrap`, `auth/endpoint_shared`, `auth/local_history_node_secret`,
`auth/key_wrap_creation`, `auth/key_wrap_recovery`, `content/file`,
`content/reaction`, `content/file_slice` (project layer). Several are covered
indirectly by `tests/` black-box suites, but not at the unit level.

**5. Where projectors *are* tested, the ranking is clean and convincing.** Files
like `content/message`, `content/message_deletion`, `connection/connection`,
`connection/request`, `auth/workspace`, `auth/signature`, `auth/invite_accepted`,
`sync/seed_connection`, `sync/maintain_sync`, `sync/compare/author`, and the core
`project_fact`/`handle_intent`/`runtime` lead with a full materialize/handle
happy path, then context-wait/park gates, then rejection/edge guards — a reader
going top-down learns how the file works before the edge cases. These got
`ReaderVerdict: yes`.

**6. Handler / recurring-builder files share a sub-pattern:** lead with the full
handler output path (what gets emitted + committed), then the transactional
marker, then skip-gate guards. Applied consistently in `handle_intent`,
`runtime`, `maintain_sync`, `maintain_connections`, `seed_connection`.

**7. Recurring "two tests that differ by one input" pairs** — table-driven
candidates flagged repeatedly: the wait-with-partial-context pairs
(`message_deletion`, `file_deletion`), insertion-order pairs (`handle_intent`
durable/local), recurring-intent single/dedup/multi (`runtime`), identity-scope
flag pair (`invite_accepted`), exact/range endpoint pairs (`context.rs`),
constructor mode pairs (`request/api`).

**8. A handful of central invariants unique to one file have no test at all** —
high-value, low-cost additions: `auth/recipient_key` self-supersession rejection
(`previous_recipient_key_id == fact_id`); `registry` route/admission
completeness (every routed tag has an admission arm); `wire` Reader/Writer
plumbing + `FixedText`; `db` storage-version marker reads + insert-conflict path;
`network` SQLite queue idempotence; `handle_intent` intent-id collision retry.

**9. Heading style was matched per file**, not standardized: plain `// Tests.`
for plain-comment files; `// ===…` / `// ----` banners for banner-style files
(`project_fact`, `local_history_node_secret`, `key_wrap` top-level). Nested
modules use plain `//` headings even in banner files, matching local context.

---

## Proposal for subsequent work

Prioritized by correctness ROI, then by cleanup value.

**P1 — Close the projector-semantic coverage gap (highest ROI).** For each fact
family whose `project_semantic` is untested in-file (trend #4), add a minimal
pair: one "context-wait → materialize" happy-path test and one
"deletion/expiry/close → retract/purge" test. This is the difference between
"the bytes parse" and "the fact behaves correctly," and it makes the per-file
`ReaderVerdict` go from partial to yes. Suggested order: key material
(`invite_secret`, `key_wrap`, `endpoint_shared`, `local_history_node_secret`) →
connection (`fact_receipt`, `frame_small`, `close`, `frame_observation`) → sync
(`shared_fact`, `range_request`) → content (`file`, `reaction`, `file_slice`).

**P2 — De-duplicate the `authenticate`/decode rejection quartet (trend #3).**
Introduce one `assert_authenticate_rejections!(canonical_fact)` macro (or a
table-driven helper) generating the canonical/id/wrong_tag/truncated cases from a
fixture, and adopt it across the ~25 fact families. Removes the largest source of
test boilerplate without losing coverage. Decide deliberately: macro (max
compaction) vs. status quo (max locality) — recommend the macro.

**P3 — Add the unguarded unique invariants (trend #8).** Cheap, targeted tests:
`recipient_key` self-supersession; `registry` completeness; `wire`
`Reader::finish`/`take` overflow/`FixedText`; `db` storage-version marker +
insert-conflict; `network` queue idempotence; `handle_intent` id-collision
retry. Each is a single test pinning a real invariant with no current guard.

**P4 — Fold the flagged near-duplicate pairs into table-driven tests (trend
#7).** Mechanical compaction; do it opportunistically alongside P1/P2 in the same
files.

**P5 — Extend the pass to `tests/` and adopt the "thesis-test pointer"
convention.** Run the same bottom-placement+ranking on integration files, and add
a one-line `//` note on only the top "thesis" test of each module (the reader's
entry point) rather than per-test docstrings — keeps signal high without comment
rot.

**P6 — Minor tidy:** relocate the stray module-overview comment that sits between
`project_fact`'s two bottom test modules; consider whether the family-shared
`canonical_fact()` fixtures should move to a shared test-support module if P2 is
adopted.

---

## Per-file findings

Format per file: **modules** · layout-before · ranked order (condensed) ·
ReaderVerdict · key gap. "auth quartet" = canonical → id_not_matching →
wrong_tag → truncated. "roundtrip-led" = fixed-width roundtrip first, then
guards.

### core

**`core/project_fact.rs`** (reviewed directly) — `contract_tests` (34),
`tests` (9), `effects::tests` (3); already-at-bottom. `contract_tests` reordered
to lead with the queue/context wake loop (`drain_revisits_dependent_after_offer_commits`,
`resolves_new_need_matches_existing_offer`, `attaches_all_satisfied_context…`),
then incoming retention, then failure isolation, then storage/owner/timing
guards. `tests` led by content-addressed idempotency + purge/delete cleanup.
**Verdict: yes.** Gaps: no direct time-wake fire→requeue test; 5 owner-rejection
tests + 2 range/exact pairs are table-driven candidates.

**`core/handle_intent.rs`** — `tests` (17); already-at-bottom. Led by
`durable_success_deletes_only_claimed_row`, then the two handler-SQL rollback
contracts, effect retention+queueing, context load; terminal-drop and
insertion-order guards last. **Verdict: yes.** Gaps: stale-version-handler path
only covered by the trailing guard; no intent-id collision-retry test; the two
insertion-order tests are table-driven candidates.

**`core/runtime.rs`** — `tests` (15); already-at-bottom. Led by whole-turn
host-mode contract, recurring-then-drain-then-pump ordering, batch limits; data
guards last. **Verdict: yes.** Gaps: no turn-level inbound-network-intake test;
time-wake admission via `run_turn` untested end-to-end; recurring single/dedup/
multi are table-driven candidates.

**`core/db.rs`** — `tests` (3); already-at-bottom. Led by
`row_mutations_insert_delete_and_roll_back_as_one_transaction`, then column-
mismatch no-partial-commit, then temp-store pragma. **Verdict: yes.** Gaps:
insert-conflict error path, storage-version marker reads, replay-lifecycle
validation untested.

**`core/wire.rs`** — `tests` (10, split by a stationary helper into 5+5);
already-at-bottom. Each run led by its broadest proof (big-endian round-trip;
FixedSlot round-trip). **Verdict: partial** (helper split prevents a single
global order). Gaps: Reader/Writer sequential plumbing, `Reader::finish` trailing
byte, `take` overflow, string codecs, `FixedText` entirely untested.

**`core/crypto.rs`** — `tests` (9); already-at-bottom. Led by
DH+HKDF+AEAD round-trip with negatives, symmetric AEAD tamper, ed25519
sign/verify, then bao, then primitive hash/HKDF determinism. **Verdict: yes.**
Gaps: none significant.

**`core/context.rs`** — `tests` (9); already-at-bottom. Led by the additions-
delta pair (only new relationships wake; identical sets → no additions), then key
syntax, normalization, guards. **Verdict: yes.** Gaps: exact/key-part endpoint
pair is a merge candidate.

**`core/cli.rs`** — `tests` (6); already-at-bottom. Led by registry dispatch +
usage, duplicate-name guard, then hex codec. **Verdict: yes.** Gaps: no
successful-dispatch test (only error paths); `parse_positive_usize` untested; hex
guards table-driven candidate.

**`core/intents.rs`** — `tests` (5); already-at-bottom. Led by effects/intent/
row-mutation separation, handler key, vocabulary, Value→sqlite. **Verdict:
partial.** Gaps: `HandlerContext::require_non_local_fact_bytes` (local-fact
rejection) untested.

**`core/network.rs`** — `tests` (4); already-at-bottom. Led by accept/drain/
limit, length-prefixed framing, heartbeat, budget timeout. **Verdict: partial.**
Gaps: SQLite outgoing/incoming queue idempotence + `pump_outgoing` connect-fail
deferral untested.

**`core/daemon.rs`** — `tests` (4); already-at-bottom. Led by start-flag parse,
lock-path derivation, tick cadence, default fallback. **Verdict: partial.** Gaps:
lock lifecycle, `stop_daemon` stale-lock, `validate_reset_path` untested.

**`core/perf_profile.rs`** — `tests` (3); already-at-bottom. Led by full profile-
line format, then inactive no-op passthroughs. **Verdict: partial.** Gaps:
active profile accumulating durations untested.

**`core/facts.rs`** — `tests` (2); already-at-bottom. Content-addressed identity,
then scope vocabulary. **Verdict: partial.** Gaps: storage-column decode /
`verify_fact_id` mismatch untested.

**`core/command.rs`** — `tests` (2); already-at-bottom. Led by AuthoredFacts
bundle, then injected-clock helper. **Verdict: yes.** Gaps: none material.

**`core/effects.rs`** — `tests` (1); already-at-bottom. `is_empty` only.
**Verdict: partial.** Gaps: builder methods (incoming metadata, local vs durable
intent split, storage_requirement) unproven.

### protocol / content

**`content/message/project.rs`** (reviewed directly) — `decode::tests` (3),
`authenticate::tests` (4), `projector_tests` (9); already-at-bottom.
`projector_tests` led by full materialize-after-context, then wait/park gates,
then deletion + non-author rejection, then expiry retraction; decode roundtrip-
led; authenticate quartet. **Verdict: yes.** Gaps: no end-to-end decrypt→opened-
row content test (decryption only covered at `recover_text` unit level).

**`content/retention_policy/project.rs`** — `decode` (4), `authenticate` (4),
`projector` (5); already-at-bottom. decode roundtrip+sentinel-led; auth quartet;
projector led by wait-for-authority→materialize, then supersession/monotonic-
floor, then guards. **Verdict: yes.** Gaps: none material (deletion/expiry lives
in message projector).

**`content/message_deletion/project.rs`** — `decode` (2), `authenticate` (4),
`row_tests` (1), `projector` (6); already-at-bottom. Projector led by authorized-
author-delete materialize, then non-target author claim (authority validated by
target, not deleter), then the two context-wait parks, then scope/malformed
guards. **Verdict: yes.** Gaps: the two wait tests are one table-driven case.

**`content/file_slice/project.rs`** — `decode` (3), `authenticate` (4),
`tests` (4); already-at-bottom. `tests` led by bao-proof→verified-ciphertext,
wrong-root, slot sizing, row builder. **Verdict: partial.** Gaps: `project_semantic`
parent-match, index-range, and deletion-retract branches untested.

**`content/file_deletion/project.rs`** — `decode` (2), `authenticate` (4),
`tests` (3); intermingled within `tests` (narrow row test sat above the two
projector tests — reordered below them). Projector led by materialize-signed-
claim, then 3-need park, then row builder. **Verdict: yes.** Gaps: no projector
rejection test (target-side validation in `file/project.rs`).

**`content/file/project.rs`** — `decode` (3), `authenticate` (4), `tests` (1);
already-at-bottom. **Verdict: partial.** Gaps: `project_semantic` materialize +
parent/deletion-retract untested; only a narrow descriptor-field guard present.

**`content/reaction/project.rs`** — `decode` (2), `authenticate` (4),
`tests` (1); already-at-bottom. **Verdict: partial.** Gaps: projector target-
message + deletion-retract untested; only the row builder.

**`content/retention_policy/queries.rs`** — `tests` (1); already-at-bottom.
Supersession-beats-created-at. **Verdict: yes.** Gaps: `status_report` horizon/
floor math + message counting untested.

**`content/message/api.rs`** — `tests` (1); already-at-bottom. End-to-end batch
authoring reuse. **Verdict: partial.** Gaps: `send_message`, count/size
validation, `decode_message_fact` untested.

**`content/file_slice/fact.rs`** — `tests` (2); already-at-bottom. bao slot
budget covers all alignments, then derived from max tree. **Verdict: yes.** Gaps:
none material.

### protocol / auth

**`auth/workspace/project.rs`** — `decode` (3), `authenticate` (4),
`projector_tests` (3); already-at-bottom. Projector led by emit-share-after-
acceptance, then wait gate, then mismatch rejection; auth quartet. **Verdict:
yes.** Gaps: signature-unmet-then-met path and global-scope rejection untested.

**`auth/signature/project.rs`** — `decode` (3), `authenticate` (5), `tests` (2);
already-at-bottom. authenticate led by canonical, then tampered-signature,
tampered-target-id (the central signed-target binding), then id/tag; `tests` led
by proof-offer projection, then key-symmetry. **Verdict: yes.** Gaps: projector
scope-mismatch rejection untested.

**`auth/invite_secret/project.rs`** — `decode` (5), `authenticate` (4); already-
at-bottom. decode led by unscoped + scoped roundtrips, then hash/secret-mismatch
and incomplete-scope `validate()` rejections, then tag. **Verdict: yes.** Gaps:
the projector (local-scope guard + two offers + row) has no test in-file.

**`auth/endpoint_shared/project.rs`** — `decode` (5), `authenticate` (4);
already-at-bottom. decode roundtrip + type/role/padding guards; auth quartet.
**Verdict: partial.** Gaps: `has_valid_authority` (device-invite vs invite-server
path) and authenticate's non-empty-field checks untested.

**`auth/local_history_node_secret/project.rs`** — `decode` (1),
`authenticate` (4), `coverage_tests` (3); already-at-bottom (dash-banner style
matched). coverage led by time-range+leaf-prefix match, then prefix and inverted-
range guards. **Verdict: partial.** Gaps: the projector (retirement/self-purge,
frontier/source/tombstone validation, child addressing) — the bulk of the file —
untested.

**`auth/invite_accepted/project.rs`** — `decode` (2), `authenticate` (4),
`tests` (2); already-at-bottom. `tests` led by identity-scoped materialize (offers
accepted-workspace, *not* workspace authority), then non-identity gate. **Verdict:
yes.** Gaps: identity-scope pair is table-driven candidate; local-scope rejection
untested.

**`auth/user/project.rs`** — `decode` (3), `authenticate` (4); already-at-bottom.
decode roundtrip + non-canonical-padding + long-username; auth quartet.
**Verdict: yes.** Gaps: empty selector-field rejections untested.

**`auth/key_wrap/project.rs`** — `decode` (1), `authenticate` (4),
`wrap_source_tests` (2, dash-banner); already-at-bottom. wrap_source covers
requested-frontier and proactive-min-time matching. **Verdict: yes.** Gaps: the
key_wrap projector (signer/recipient/frontier wait, local-recovery emission)
untested in-file.

**`auth/endpoint/project.rs`** — `decode` (3), `authenticate` (4); already-at-
bottom. decode roundtrip + key/signing-key rederivation guards; auth quartet.
**Verdict: yes.** Gaps: projector must-be-local + offer/row materialization
untested.

**`auth/device_invite`, `auth/admin`, `auth/user_invite`, `auth/invite_server`
(/project.rs)** — each `decode` (2–3) + `authenticate` (4); already-at-bottom;
decode roundtrip-led (admin/device add sentinel/option branches), auth quartet.
**Verdict: yes.** Gaps (shared): non-zero field rejections + the two authority
projector paths untested in-file.

**`auth/{removal_frontier, recipient_key, local_signer_secret,
local_secret_retirement, local_recipient_key, local_key_secret,
key_request}/project.rs`** — each `decode` (1) + `authenticate` (4); already-at-
bottom; auth quartet, decode single. **Verdict: yes** except **`recipient_key`
partial**. Gaps: `recipient_key` — **self-supersession rejection
(`previous_recipient_key_id == fact_id`) has NO test** (a central invariant unique
to that file); others none beyond the family-shared projector gap.

**`auth/key_wrap_creation/project.rs`, `auth/key_wrap_recovery/project.rs`** —
`decode` (1) each; already-at-bottom. **Verdict: partial.** Gaps: the
context-wait/materialize projector + source-kind variants untested in-file.

**`auth/key_wrap/author.rs`** — `tests` (2); already-at-bottom. admit happy path,
then wrong-type rejection. **Verdict: partial.** Gaps: `create`/`unwrap` wrap
crypto untested here.

**`auth/endpoint/api.rs`** — `tests` (2); already-at-bottom. `local_or_create`
create branch then reuse branch. **Verdict: yes.** Gaps: `local_signing_capability`
untested here.

**`auth/key_wrap/queries.rs`** — `tests` (1); already-at-bottom. Row round-trips
by coordinate. **Verdict: partial.** Gaps: lookup/key_access/status/supersession
query logic untested here.

**`auth/invite_accepted/api.rs`** — `tests` (1); already-at-bottom. `accept()`
emits one acceptance fact. **Verdict: yes.** Gaps: `validate_id` rejection
branches untested.

**`auth/user_invite/api.rs`** — `tests` (1); already-at-bottom.
`create_with_secret` derives key+id and emits fact+signature. **Verdict: yes.**
Gaps: unsigned `create()` error path untested.

### protocol / connection

**`connection/connection/project.rs`** — `decode` (2), `authenticate` (6),
`projector` (5); already-at-bottom. authenticate interleaves park-on-opener tests
between canonical and guards; projector led by initiator materialize (durable
then incoming observation), responder send+seed-sync, then park/replay.
**Verdict: yes.** Gaps: `NeedsContext` branch and close-context delete+purge
untested.

**`connection/request/project.rs`** — `decode` (2), `authenticate` (4),
`projector` (6); already-at-bottom. Projector led by receiver receipt+create-
connection intent, sender pending-retry row, then observation/park gates.
**Verdict: yes.** Gaps: membership-mode receiver + membership sender branches
untested (all tests use bootstrap mode).

**`connection/fact_receipt/project.rs`** — `decode` (7), `authenticate` (4);
already-at-bottom. decode reordered: full roundtrip, optional-id-absent roundtrip,
origin-addr normalize, then reject guards; auth quartet. **Verdict: yes.** Gaps:
`project_semantic` (local-scope + offer + row) has no test.

**`connection/ephemeral_secret/project.rs`** — `decode` (2), `authenticate` (4),
`project_tests` (1); **intermingled — projector tests moved to bottom.** Only
test: live-secret offers fact-id + public-key context. **Verdict: partial.**
Gaps: close-gate branch (delete row + purge_self) + non-local rejection untested.

**`connection/frame_small/project.rs`** — `decode` (1), `authenticate` (4),
`material_tests` (1); **intermingled — material tests moved to bottom.** Only
material test: parks on exact endpoint+ephemeral-key needs. **Verdict: partial.**
Gaps (large): `project_observed_frame` happy path, `require_connection_endpoints`,
`decode_packed_inner_bundle`, per-type admit dispatch all untested.

**`connection/frame_observation/project.rs`** — `decode` (2), `authenticate` (4);
already-at-bottom. decode roundtrip + origin-addr normalize; auth quartet.
**Verdict: partial.** Gaps: `project_semantic` (local-scope + observation offer)
untested.

**`connection/close/project.rs`** — `decode` (2), `authenticate` (4); already-at-
bottom; roundtrip-led + auth quartet. **Verdict: partial.** Gaps: empty-
connection-id guard + `project_semantic` (park→connection_closed offer; non-local
rejection) untested.

**`connection/frame_file_slice/project.rs`, `connection/frame_bundle/project.rs`**
— `decode` (1) + `authenticate` (4) each; already-at-bottom; auth quartet.
**Verdict: yes.** Gaps: bundle-specific fixed-slot inner decode untested here;
layout-reject pair is table-driven candidate.

**`connection/maintain_connections.rs`** — `tests` (5); already-at-bottom. Led by
bootstrap-attempt replay, queue-pending-request-to-network, transactional marker,
then builder retry/listener skip gates. **Verdict: yes.** Gaps:
`attempt_is_active_or_answered` dedupe untested.

**`connection/create_connection.rs`** — `tests` (3); **intermingled — module
relocated to file bottom.** roundtrip, request-scoped-key invariant, tamper guard.
**Verdict: yes.** Gaps: decode wrong-length / wrong-kind rejection untested.

**`connection/send_facts_on_connection.rs`** — `tests` (2); already-at-bottom.
fact-batching keeps slices in dedicated frames, then trigger-fact intent identity.
**Verdict: partial.** Gaps: seal/route/enqueue path + small-vs-bundle frame
selection untested.

**`connection/request/api.rs`** — `tests` (2); already-at-bottom. bootstrap
superset path then membership path. **Verdict: yes.** Gaps: `validate_id` +
`connect` wrapper untested; pair is table-driven candidate.

**`connection/request/queries.rs`** — `tests` (1); already-at-bottom. no-endpoint
guard. **Verdict: partial.** Gaps: `choose_connection_mode` happy path +
self-target guard only covered by black-box test.

**`connection/fact_receipt/fact.rs`** — `tests` (3); already-at-bottom. canonical
addr normalize, friendly-form parse, reject non-socket. **Verdict: yes.** Gaps:
`ConnectionFactReceipt`/`ReceiptPathInput` structs untested.

### protocol / sync

**`sync/compare/project.rs`** — `decode` (5), `authenticate` (4); already-at-
bottom. decode roundtrip + inverted-range + response-flag + tag/length; auth
quartet. **Verdict: yes.** Gaps: none for the slice (admission-scope is projector-
side by design).

**`sync/shared_fact/index.rs`** — `tests` (8); **intermingled — module relocated
to file bottom.** Led by upsert-records-leaf+lazy-summary, idempotent+monotonic
context (convergence), range-query auth + optional deps, transitive-closure, then
retract-clears-closure, bootstrap-invite authorization, narrow expansion/
concurrency guards. **Verdict: yes.** Gaps: range-auth vs bootstrap-invite tests
share scaffolding (common-builder candidate).

**`sync/need_id/project.rs`, `sync/have_id/project.rs`** — `decode` (2) +
`authenticate` (4) + top-level (1) each; already-at-bottom. decode roundtrip +
tag/length; auth quartet; replay-no-op test. **Verdict: yes.** Gaps: none.

**`sync/seed_connection.rs`** — `tests` (6); already-at-bottom. Led by advertise→
root-compare+send-intent, handler-depends-on-connection-row, live-tail context
expansion, then range-setting/skip/round-trip. **Verdict: yes.** Gaps: none
material.

**`sync/maintain_sync.rs`** — `tests` (6); already-at-bottom. Led by queue path,
retry-window gate, transactional marker, then skip gates, then codec. **Verdict:
yes.** Gaps: none.

**`sync/shared_fact/project.rs`, `sync/range_request/project.rs`** — `decode` (1)
+ `authenticate` (4) each; already-at-bottom; auth quartet. **Verdict: partial.**
Gaps: `project_semantic` scope-match rejection + offer emission untested in-file;
`range_request` inverted-range decode untested.

**`sync/compare/author.rs`** — `tests` (4); already-at-bottom. Led by split-large-
mismatch, batch-small-mismatch, empty-local-answers, then start-compare-root.
**Verdict: yes.** Gaps: summaries-match early-return + lazy summarizer untested.

**`sync/local_setting.rs`** — `tests` (3); already-at-bottom. Led by read-model
(projection→latest-row+active_range), then fact roundtrip, then author path.
**Verdict: yes.** Gaps: CLI range parsing + non-Local-scope rejection untested.

**`sync/share_fact_with_sync.rs`** — `tests` (1); already-at-bottom. Origin-
suppression of live tail. **Verdict: partial.** Gaps: intent codec/handler_key,
Retract path, local-only-bytes rejection untested.

**`sync/send_needed_fact_id.rs`** — `tests` (1); already-at-bottom. Emits need-id
+ send when fact missing. **Verdict: partial.** Gaps: already-have short-circuit,
replay no-op, codec untested.

### protocol / versioning + registry

**`versioning/check_version.rs`** — `tests` (2); already-at-bottom. Led by
missing-marker→queue+emit (end-to-end), then stale-version handler emits priority
update. **Verdict: yes.** Gaps: storage-ready/replay early-return paths untested.

**`registry.rs`** — `tests` (2); already-at-bottom (unchanged order). fact-tag
global uniqueness (core dispatch invariant), then storage-gating policy.
**Verdict: yes.** Gaps: no route/admission **completeness** test (every routed
tag has an admission arm and vice versa).

**`versioning/local_update/{project,encode,author,api}.rs`** — `tests` (1) each;
already-at-bottom. project: live records version + requests rebuild, replay
no-ops; encode: fixed-width roundtrip; author/api: emit one Local fact at
CURRENT_PROTOCOL_VERSION. **Verdict: yes.** Gaps: non-Local-scope/bad-id
rejection (project), wrong-tag/length decode (encode), receipt-field assertions
(api).
