# Verus Connection Proof Bracket

This note records the first proof bracket for the connection-based
confidentiality invariant in `THREAT_MODEL.md`. The proof target is narrow on
purpose: prove the largest property that follows from the current connection
and sync visibility shape without pretending that every adjacent subsystem has
already been modeled in Verus.

The current Verus file is `src/protocol/connection/proof.rs`, verified by
`scripts/run_verus.sh`.

## Claim

For a workspace message selected by the sync visibility path for a connection,
the remote endpoint on that connection must have one of these authorization
witnesses for the workspace:

- an `auth_endpoint_shared_rows` membership row for the remote endpoint in the
  workspace; or
- a scoped bootstrap invite secret for that connection and workspace.

Therefore, if the remote endpoint is never invited for that workspace, meaning
it has neither endpoint membership nor a scoped bootstrap invite on that
connection, sync visibility cannot select that workspace message for the
connection.

## Proof Boundary

The proof abstracts over real bytes, signatures, X25519, AEAD, and SQL. It
models the proof-relevant shape:

- `ConnectionRow` names a local/remote endpoint pair and a connection id.
- `remote_endpoint` mirrors `remote_endpoint_for_connection`.
- endpoint membership mirrors rows emitted by `endpoint_shared` projection.
- scoped bootstrap invite authorization mirrors `connection_workspaces`, which
  opens the connection request and maps its invite secret to a workspace.
- sync message visibility mirrors `shareable_facts_for_connection` for
  workspace-scoped facts.

The executable obligations left for later proof slices are:

- `endpoint_shared` rows are emitted only from valid invite-server or
  device-invite authority.
- connection rows are emitted only after request and connection projectors
  validate endpoint direction, request authority, handshake transcript, and
  local receive evidence.
- sync producers call the connection-visible shareability path before creating
  explicit `send_facts_on_connection` work for workspace payloads.
- connection frame sendability rejects local/private facts and does not parse
  semantic authority.

## Counterexamples Contained By The Bracket

- **Bootstrap without membership.** A newly invited endpoint may have no
  endpoint membership row yet but can still be allowed to receive workspace
  bootstrap data through a scoped invite secret. The proof includes
  `scoped_bootstrap_invite_is_intentional_memberless_visibility` so the theorem
  cannot be misread as "not a member means no visibility."
- **Wrong local endpoint orientation.** If the local endpoint is neither side
  of the connection row, the connection authorizes no workspace. This mirrors
  the production sync code returning no remote endpoint for that row.
- **Server-forged range or need-id traffic.** A server can ask for ids, but the
  modeled sync path still requires connection-visible shareability before
  workspace payloads are selected.
- **Carrier frames are not content authority.** A connection may carry bytes,
  but opened child facts must still be admitted by their owning projectors.
  This proof only covers whether sync is allowed to select workspace message
  bytes for the connection in the first place.
- **Unchecked explicit send intents.** The final `send_facts_on_connection`
  handler packages explicit fact ids after sendability checks; it does not
  independently re-check sync visibility for those explicit ids. The first
  theorem is therefore about sync-selected sends, not arbitrary locally queued
  explicit sends. A later proof or implementation change should either prove
  every explicit producer is visibility-checked or move the check into the
  final handler.

## Current Verus Theorems

- `never_invited_remote_cannot_receive_workspace_message_from_sync`: the main
  theorem for sync-selected workspace messages.
- `endpoint_membership_is_sufficient_for_sync_visibility`: membership is one
  legitimate visibility witness.
- `scoped_bootstrap_invite_is_intentional_memberless_visibility`: bootstrap
  invite visibility is intentional and prevents overclaiming.
- `connection_not_involving_local_endpoint_authorizes_no_workspace`: malformed
  local orientation cannot authorize a workspace.
