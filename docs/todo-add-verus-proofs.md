# TODO: Add Verus Proofs

This document records the work needed to use Verus to prove projection,
context, sync, and key-material invariants in the current fact-based
architecture. Core may match candidates, queue work, and commit replacement
state. Protocol fact families still own meaning and authority.

## Goal

The target invariant is:

```text
Every materialized row, emitted authority offer, emitted sync-share contribution,
emitted deferred intent, and emitted purge has a derivation from valid facts and
valid matched context.
```

For projectors this means proving more than shape preservation. A projector
cannot emit an offer, row mutation, deferred intent, sync-share contribution, or
self-purge unless the fact-family predicate for that output is satisfied.

For context matching this means proving less than authority. A matcher only
finds candidate context by role, scope, owner, range, and offer owner. The
consuming projector still proves fact type, workspace, signer, endpoint, key
coordinate, receipt path, deletion coordinate, and protocol meaning before
producing output.

## Proof Target Selection

Use the architecture rules in `docs/RULES.md` when choosing proof work. A proof
target is meaningful only if it names:

1. The protected output: row, context offer, intent, sync share, or purge.
2. The executable boundary that emits the output.
3. The exact input facts and matched context required for the output.
4. The negative case: missing context parks, mismatched context rejects, and
   untrusted carrier data cannot grant authority.
5. The ownership boundary: core plumbing, protocol projector, or intent handler.

Prioritize targets that protect authority, secrecy, shareability, deletion, and
transport admission. Do not spend early proof effort on layout round trips, enum
syntax, or generated row boilerplate unless a layout field participates in a
signature transcript, key coordinate, BAO proof, or context selector.

## File Layout

Verus proof code should live close to the code whose invariant it proves, with a
small shared proof surface in core. Proof layout follows the target staged
fact-family roles: decode, authenticate, adapt, project, and effects. The
current source tree has flat manifests, scope modules, fact-family directories,
and verb-named handler files; proof layout should follow that shape and keep
`mod.rs` out of the tree.

```text
src/core/proof.rs
src/core/context_proof.rs
src/core/pipeline_proof.rs

src/protocol/<scope>/<fact_family>/proof.rs
src/protocol/<scope>/<fact_family>/proof/
  authenticate.rs
  adapt.rs
  project.rs
  authority.rs
  effects.rs

src/protocol/<scope>/<verb_object>_proof.rs
```

A single proof file per fact family is preferred at first:

```text
src/protocol/connection/request/proof.rs
src/protocol/connection/response/proof.rs
src/protocol/auth/admin/proof.rs
src/protocol/auth/key_wrap_creation/proof.rs
src/protocol/auth/key_wrap_recovery/proof.rs
src/protocol/content/file_slice/proof.rs
```

Verb-named intent handlers such as `sync/share_fact_with_sync.rs` should use a
sibling proof file such as `src/protocol/sync/share_fact_with_sync_proof.rs`
rather than creating handler subdirectories.

Proofs should not live directly in `project.rs`, `commands.rs`, `author.rs`,
`encode.rs`, `decode.rs`, `authenticate.rs`, `adapt.rs`, `create.rs`,
`layout.rs`, `rows.rs`, or handler files by default. Those files are the
production implementation surface. They should remain readable as protocol code:
decode, validate, emit needs, offers, row mutations, facts, purges, or intents.
`create.rs`, `layout.rs`, and `rows.rs` are transitional implementation or
inventory names, not target proof homes for new work.

The exception is a small specification hook that must sit on the executable item
being verified. A pure helper may carry a Verus precondition, postcondition, or
ghost-free spec reference if that is the least invasive way to verify it. Larger
lemmas, induction arguments, proof-only wrappers, model types, and role
certificates belong in proof files.

Split a fact family's proof into `proof/` subfiles only after the file becomes
hard to review. The split should follow invariants, not generic names. For
example, `projector.rs`, `handshake.rs`, `authority.rs`, and `key_material.rs`
are useful; `helpers.rs` is not.

Normal Rust builds should not compile proof files. Module manifests should gate
proof modules behind a dedicated cfg or feature:

```rust
#[cfg(feature = "verus-proof")]
pub mod proof;
```

The exact gate can be chosen when the Verus runner is introduced, but production
code must not depend on proof modules.

## Shared Core Proof Surface

`src/core/proof.rs` owns protocol-neutral specification types and lemmas:

```text
SpecFact
SpecFactScope
SpecContextNeed
SpecContextOffer
SpecMatchedContext
SpecProjectionOutput
SpecPipelineGraph
```

Core predicates:

```text
context_set_normalized(set)
range_match_sound(need, offer)
exact_match_sound(need, offer)
projection_context_sound(ctx, graph)
standing_context_sound(graph)
row_mutations_bounded(output)
purges_are_self_only(output, current_fact_id)
atomic_runtime_effects_sound(output, graph)
```

Core lemmas:

```text
range matcher returns only same role and scope with overlapping selector ranges
exact matcher is the equal-endpoint case of range matching
matched offer values are hydrated from the matched offer id
matched value helpers preserve the need chosen by the projector
context replacement preserves owner boundaries
unchanged needs and offers do not create new wake work
new matching offers wake only matching need owners
row mutation and purge commit is atomic with context replacement
core rejects cross-fact purges from projector output
```

These core proofs intentionally do not know protocol roles such as
`auth_admin`, `content_message`, or `request`.

## Fact Family Proof Contract

Each fact family owns its semantic predicates. A proof file should define the
certificates for the context offers, rows, intents, sync-share contributions,
and purges that the fact family emits.

Example shape:

```text
valid_request_fact(fact)
valid_request_offer(offer, payload, graph)
valid_request_row(row, fact, graph)
valid_connection_intent(intent, fact, matched_context, graph)

lemma_request_projector_waits_without_materializing(...)
lemma_request_projector_offer_is_valid(...)
lemma_request_projector_row_is_valid(...)
lemma_request_projector_intent_is_valid(...)
```

Projector proof obligations:

```text
1. Decode failure emits no output.
2. Missing required context emits stable needs and no materialized rows,
   authority offers, sync shares, deferred intents, or purges.
3. Invalid matched context rejects or emits no materialized output.
4. Every emitted offer satisfies that role's semantic offer predicate.
5. Every emitted row mutation satisfies that table's row predicate.
6. Every emitted deferred intent satisfies that intent's input and authority
   predicate.
7. Every emitted sync-share contribution is for an already admitted non-local
   owner fact and records only validated non-local dependencies.
8. Every emitted purge is for the current fact id only and follows a
   target-owned deletion, close, retirement, expiry, or retention proof.
```

Matcher proof obligations:

```text
1. A returned match has the requested role.
2. A returned match has the requested scope.
3. A returned match satisfies the requested selector relation.
4. A returned match preserves need owner, offer owner, offer id, and offer value.
5. The matcher does not claim protocol authority.
```

Intent handler proof obligations:

```text
1. The intent payload names the exact fact inputs the handler may load.
2. Missing input or unavailable IO returns retry without committing partial
   protocol effects.
3. Every returned fact is constructed by its owning fact-family helper.
4. Every returned purge is exact and authorized by the input facts.
5. The handler does not mutate projector-owned rows directly.
```

## Stringing Proofs Across Context

Proof composition should use offer predicates as certificates.

For a producer projector:

```text
projector emits Offer(role = R, owner = F)
  -> valid_R_offer(offer, F, graph)
```

For a matcher:

```text
need and offer match
  -> matched context contains the stored offer value
  -> no semantic authority conclusion yet
```

For a consumer projector:

```text
projection_context_sound(ctx, graph)
ctx contains matched offer for role R
valid_R_offer(offer, payload, graph)
consumer validates module-specific cross-checks
  -> consumer output predicate holds
```

For runtime work:

```text
standing_context_sound(before)
projector theorem for current fact
context replacement for current owner
matcher soundness for newly added context
atomic commit of rows, facts, purges, and queued intents
  -> standing_context_sound(after)
  -> materialized rows, sync shares, and intents remain sound
```

This gives an induction over projection steps instead of a one-off proof about a
single projector.

## Meaningful Security Proof Targets

The first proof set should cover invariants that would be security bugs if
mis-projected.

### Auth Authority DAG

Auth relationships should be modeled as a least authorized closure, not as broad
store queries.

Authority predicates:

```text
valid_workspace_offer(workspace_offer, workspace_fact)
valid_user_invite_offer(user_invite_offer, user_invite_fact, graph)
valid_user_offer(user_offer, user_fact, graph)
valid_admin_offer(admin_offer, admin_fact, graph)
valid_device_invite_offer(device_invite_offer, device_invite_fact, graph)
valid_endpoint_shared_offer(endpoint_offer, endpoint_fact, graph)
valid_invite_server_offer(invite_server_offer, invite_server_fact, graph)
valid_content_signer_offer(content_signer_offer, endpoint_fact, graph)
```

Admin closure:

```text
workspace root
  -> workspace-signed first user_invite
  -> first user
  -> bootstrap admin for that first user
  -> delegated admin
  -> user / invite / endpoint / content-signer authority
```

The proof should show that an `auth_admin` offer can appear only from one of two
cases:

```text
bootstrap:
  workspace exists
  valid_user_invite_offer(bootstrap_invite)
  bootstrap_invite.workspace_id == workspace_id
  bootstrap_invite.authority_fact_id == workspace_id
  bootstrap_invite.signer_id == workspace_id
  bootstrap_invite.signer_public_key == workspace.public_key
  valid_user_offer(user)
  user.signer_id == bootstrap_invite.id
  user.workspace_id == workspace_id
  user.public_key == admin.public_key
  admin.authority_fact_id == workspace_id
  admin.user_fact_id == user.id
  admin.signer_id == workspace_id
  admin.signer_public_key == workspace.public_key
  admin.signature verifies under workspace.public_key

delegated:
  valid_admin_offer(authority_admin)
  authority_admin.workspace_id == admin.workspace_id
  valid_user_offer(user)
  user.workspace_id == admin.workspace_id
  user.public_key == admin.public_key
  admin.signature verifies under authority signer path
```

Cycles of admin facts do not bootstrap authority because the induction requires
an already valid authority offer before a delegated admin offer can be emitted.

The auth proof set should also cover `user_invite`, `user`, `device_invite`,
`endpoint_shared`, and `invite_server` branch predicates. Each branch must prove
scope, workspace id, signer id, signer public key, and signature transcript
before publishing `auth_*`, `content_signer`, or sync-share output.

### Auth Key Material And Forward Secrecy

Key-material proofs should cover shared key facts, local secret facts, and the
local work facts that connect them:

```text
valid_recipient_key_offer(recipient_key_offer, recipient_key_fact, graph)
valid_wrap_source_offer(wrap_source_offer, source_fact, graph)
valid_secret_coverage_offer(secret_offer, local_secret_fact, graph)
valid_key_wrap_fact(key_wrap_fact, recipient_key, source_secret, signer, graph)
valid_unwrapped_secret_fact(local_secret_fact, key_wrap, recipient_key, graph)
```

Proof obligations:

```text
1. Deterministic key-wrap identity excludes request entropy.
2. `key_wrap_creation` validates recipient key, signer secret, source fact,
   frontier, source coordinate, and workspace before emitting a `key_wrap`.
3. `key_wrap_recovery` validates recipient private material, recipient public
   fact, frontier, wrap coordinate, AEAD associated data, and output secret id.
4. `secret_coverage` offers cover only the frontier/minute/target range proved
   by the local key secret or retained history-node secret.
5. Superseded recipient keys stop receiving new frontier wraps.
6. Local private material and local secret facts are never sync-shareable or
   connection-sendable.
7. Local private material is purged only after exact supersession or retirement
   proof.
8. Post-retirement key healing may wrap retained path nodes for surviving
   content, but cannot resurrect a removed root.
```

### Connection Handshake

The first vertical proof slice should remain the connection handshake. It has a
small surface, crosses several context roles, and exercises the exact composition
model.

Predicates:

```text
valid_connection_invite_secret_offer(offer, invite_secret)
valid_ephemeral_secret_offer(offer, ephemeral_secret)
valid_connection_fact_receipt_offer(offer, receipt_fact)
valid_request_offer(offer, request_fact, graph)
valid_connection_row(row, response_fact, graph)
valid_connection_offer(offer, response_fact, graph)
```

Proof chain:

```text
connection_ephemeral_secret projector
  -> local secret offer implies public key matches private key

connection_fact_receipt projector
  -> receipt offer implies only local observation for received_fact_id
  -> receipt alone grants no request, response, or child-fact authority

request projector
  -> invite context is present
  -> invite signature transcript verifies
  -> local branch has matching local ephemeral secret
  -> received branch has matching local endpoint and request receipt
  -> emitted request offer is valid

connection projector
  -> request offer is valid
  -> invite context matches request bootstrap hash
  -> endpoint direction reverses request
  -> public handshake hash matches transcript
  -> local branch has responder ephemeral secret
  -> received branch has response receipt and initiator secret
  -> emitted connection row and offers are valid
```

The resolved invite-secret role shape should be part of the proof setup:
`invite_secret` projection emits both `auth_invite_secret` and
`connection_invite_secret`, while request/response projection consumes
`connection_invite_secret`.

### Content Admission, Deletion, And Retention

Content proofs should start with the outputs that protect user-visible state:
message metadata rows, opened-message rows, file rows, reaction rows, deletion
offers, retention-floor offers, sync-share contributions, and self-purges.

Core predicates to reuse:

```text
valid_content_signer_offer(...)
valid_auth_user_offer(...)
valid_auth_admin_offer(...)
valid_secret_coverage_offer(...)
```

Fact-family targets:

```text
message:
  signer and author context prove metadata admission
  opened rows require matching secret coverage and successful decrypt
  deletion, expiry, or retention context deletes only message-owned rows

message_deletion and file_deletion:
  signer, author, and target context prove the deletion coordinate
  `content_purged` is emitted only for the proved target coordinate

reaction:
  parent opened-message context and author context prove admission
  target deletion context removes only the reaction row and purges this fact

file:
  parent message context, author context, signature, and deletion watches prove
  descriptor rows and `content_file` offers

retention_policy:
  admin or workspace-bootstrap authority proves `content_retention_floor`
  predecessor context prevents regressing the floor
```

Deletion is target-owned. The deletion fact proves authority once and publishes
context. The target projector consumes that context, validates the payload when
there is one, deletes only rows it owns, retracts shareability when required,
and calls `purge_self` for its own fact id.

### Encrypted File Slice

`content/file_slice` is a high-value proof target because it connects signature
authority, parent content context, fixed slice coordinates, BAO proof
verification, and sync sharing.

The proof should show that a file-slice row or sync-share contribution requires:

```text
1. Workspace-scoped slice fact.
2. Signature under the expected endpoint signer.
3. Parent file context for the same workspace, file id, root hash, slice size,
   and total slice count.
4. Parent message context proving the file remains attached to a valid message.
5. Slice index in range.
6. BAO slice proof verifies against the parent file descriptor root hash.
7. Verified ciphertext length matches the canonical slice bounds.
8. File or parent-message deletion context removes only slice-owned rows and
   purges only this slice fact.
```

Connection `frame_file_slice` remains a carrier proof: it may prove frame
opening and receipt creation, but it does not prove content admission.

### Sync Shareability And Dependency Closure

Sync facts describe convergence, not domain validity. Proof targets should make
that separation explicit.

Predicates:

```text
valid_sync_share_contribution(owner_fact, dependencies, graph)
valid_connection_visible_share(row, connection, graph)
valid_requested_fact_send(request, requested_fact, connection, graph)
```

Proof obligations:

```text
1. `share_fact_with_sync` is emitted only after the owner projector's authority
   proof succeeds.
2. The handler accepts only an existing non-local owner fact whose scope is
   global or the named workspace scope.
3. Recorded dependency facts are non-local when they still exist.
4. Negentropy summaries cover ids and timestamps, not payload copies.
5. `compare`, `have_id`, and `need_id` can request transfer but cannot prove
   payload validity.
6. `send_requested_fact` checks connection-specific visibility and sendability
   before asking connection to carry bytes.
7. Out-of-range dependency expansion includes key wraps and retained key nodes
   needed to project encrypted in-range facts, without trusting the server for
   key authority.
```

## Runner And Build Plan

Introduce proof execution in stages:

```text
scripts/run_verus.sh
verus.toml or equivalent local runner config
```

The runner should verify only proof-enabled modules first:

```text
core context and matcher lemmas
core projection-output purge and replacement lemmas
connection_ephemeral_secret proof
connection_fact_receipt proof
request proof
connection proof
auth_workspace proof
auth_admin proof
sync_share_fact_with_sync proof
content_file_slice proof
```

Keep Rust tests and Verus proofs complementary:

```text
Rust tests prove concrete behavior and regressions.
Verus proofs prove universal invariants over all inputs accepted by the spec.
```

Every proof task should still include realistic executable tests when it changes
runtime behavior. Pure proof-only changes should run the Verus runner and any
nearby Rust tests affected by the proof refactor.

## Worktree Task Template

Use this template when assigning proof work to a worktree:

```text
1. Work only in the named worktree.
2. Define or update the module-local semantic predicates for the target role,
   row, intent, sync-share contribution, or purge.
3. Add or update the Verus lemmas for the changed projector, matcher, or handler
   behavior.
4. Add or update realistic Rust tests if runtime behavior changes.
5. Run the relevant Verus target and nearby Rust tests.
6. Document any proof assumptions, especially opaque crypto assumptions.
7. Commit the completed work on that same worktree branch before handoff or
   review.
```

## Initial Milestones

1. Add the Verus runner and a tiny core proof target for exact/range selector
   matching plus offer-id/value hydration.
2. Prove projection context replacement, stable parking, atomic row/intent
   commit, and self-purge enforcement.
3. Prove local connection ephemeral-secret offer validity.
4. Prove connection fact-receipt offer validity without treating receipts as
   authority.
5. Prove connection request offer validity.
6. Prove connection row and offer validity.
7. Add auth workspace/admin/user/user-invite predicates and prove admin closure.
8. Prove `share_fact_with_sync` accepts only admitted non-local owner facts and
   validated non-local dependencies.
9. Prove deletion/retention target-owned purge for one content fact family.
10. Prove `content/file_slice` BAO-backed row and shareability validity.
11. Prove key-wrap determinism, secret coverage bounds, recipient-key
    supersession, and local-secret non-shareability.
