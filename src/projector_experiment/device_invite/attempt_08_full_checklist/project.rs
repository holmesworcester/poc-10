//! Device-invite projector as a scannable checklist of named operations.
//!
//! # The angle
//!
//! Reviewer feedback on attempt_03 was: "I like the way declarative put
//! together arrays of statements so you could see a SUMMARY of what was being
//! checked, and then check that the summary functions are doing what you
//! expect quite easily down below." attempt_03 reached for that with an enum
//! + interpreter — strong summary, but the interpreter cost an indirection
//! and the parking story was buried under loose `Vec<ContextNeed>` plumbing.
//!
//! This attempt pushes the same idea by making `project()` itself the
//! summary: a vertical list of named helper calls, each helper sitting a
//! short scroll below. The summary is real code, not data; the names ARE the
//! checklist. Read `project()` once and you have seen every step:
//!
//! ```text
//!     parse_envelope_and_invite        STAGE 1 - shape
//!     InviteAuthority::classify        STAGE 2 - which path?
//!     declare_needs_for_signer         STAGE 3 - populate NeedSet
//!     collect_payloads_or_park         STAGE 4 - single bail-out
//!     verify_workspace_payload         STAGE 5a
//!     verify_authority_chain           STAGE 5b/c/d (dispatches)
//!     emit_row_and_offers              STAGE 6
//! ```
//!
//! # Needs-collection: one set, declared once, parked once
//!
//! The reviewer's other note was "It seems less clear than it could how we
//! collect and express needs at the end. (or how we stop and return the main
//! need)." Here the picture is single-pointed:
//!
//!   1. `declare_needs_for_signer` builds a `PathNeeds` (per-path, typed).
//!   2. `PathNeeds::park` is the ONE place we stuff them into a `NeedSet` and
//!      return them.
//!   3. `collect_payloads_or_park` is the ONE place that returns the parked
//!      output if any payload is missing.
//!   4. After STAGE 4 the function deals only in payloads — needs are done.
//!
//! No scattered `.need(a).need(b)` chains; no needs threaded through every
//! validator. The set is created, populated, consulted, and either yields
//! payloads or short-circuits.
//!
//! # Two granularities considered
//!
//! - **Per-check verbs** (~17 helpers): one helper per spec line. Maximally
//!   scannable as a list, but `project()` becomes a wall of 17 `?`s — the
//!   summary stops being a summary and turns into a flat enumeration.
//! - **Per-stage verbs** (this file, 7 stages): one helper per logical stage.
//!   Each helper is itself a short list of `require(...)?` lines, so the
//!   scan-then-drill loop happens at two levels: read `project()` for the
//!   stages; drill into a stage for its rules.
//!
//! Per-stage won. It keeps `project()` short enough to memorise while letting
//! every spec rule live in a named, locally-readable function.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::fact::DeviceInviteFact;
use crate::event_modules::identity_device_invite::layout;
use crate::event_modules::identity_device_invite::rows::device_invite_row;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers as m;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;
use crate::event_modules::signed_fact::fact::SignedFactEnvelope;
use crate::projector_experiment::checks::{is_zero32, open_signed, require, NeedSet};

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

// =============================================================================
// project(): the checklist. Read top-to-bottom for the full policy summary.
// Each helper is named for what it enforces and lives a short scroll below.
// =============================================================================

impl Projector for DeviceInviteProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        let (envelope, invite) = parse_envelope_and_invite(fact)?;
        let authority = InviteAuthority::classify(&invite, &envelope);
        let needs = declare_needs_for_signer(fact.id, &invite, &authority);
        let Some(payloads) = collect_payloads_or_park(&needs, &authority, ctx) else {
            return Ok(needs.park());
        };
        verify_workspace_payload(payloads.workspace, invite.workspace_id)?;
        verify_authority_chain(&envelope, &invite, &payloads.authority)?;
        Ok(emit_row_and_offers(fact.id, &invite, needs.park()))
    }
}

// =============================================================================
// STAGE 1: parse the envelope, decode the invite, reject empty required fields.
// Nothing in here looks at cross-fact relationships — pure shape.
// =============================================================================

fn parse_envelope_and_invite(
    fact: &Fact,
) -> Result<(SignedFactEnvelope, DeviceInviteFact), String> {
    require(fact.scope == FactScope::Global, "device_invite fact must have global scope")?;
    let envelope = open_envelope(&fact.bytes)?;
    let invite = layout::decode_fact(&envelope.payload)?;
    require(!is_zero32(&invite.workspace_id), "device_invite fact has empty workspace_id")?;
    require(!is_zero32(&invite.user_authority_event_id),
        "device_invite fact has empty user_authority_event_id")?;
    require(!is_zero32(&invite.public_key), "device_invite fact has empty public_key")?;
    Ok((envelope, invite))
}

/// The outer envelope's "fact must be signed" and "wrong inner type" errors are
/// distinct strings, so we can't use the shared `open_signed` helper (it folds
/// both into one). Three lines, inlined.
fn open_envelope(bytes: &[u8]) -> Result<SignedFactEnvelope, String> {
    let envelope = signed_fact::layout::decode_signed_fact(bytes)
        .map_err(|_| "device_invite fact must be signed".to_string())?;
    require(envelope.inner_type == layout::TYPE_DEVICE_INVITE,
        "signed fact does not contain a device_invite")?;
    Ok(envelope)
}

// =============================================================================
// STAGE 2: classify the signer. This is the single spot where the two paths
// diverge. Everything downstream consults this typed value, never re-inspects
// `invite.user_invite_event_id`.
// =============================================================================

#[derive(Debug, Clone, Copy)]
enum InviteAuthority {
    UserSigned { user_authority: FactId, user_invite: FactId },
    EndpointSigned { endpoint_signer: FactId },
}

impl InviteAuthority {
    fn classify(invite: &DeviceInviteFact, envelope: &SignedFactEnvelope) -> Self {
        match invite.user_invite_event_id {
            Some(user_invite) => Self::UserSigned {
                user_authority: invite.user_authority_event_id,
                user_invite,
            },
            None => Self::EndpointSigned { endpoint_signer: envelope.signer_id },
        }
    }
}

// =============================================================================
// STAGE 3: declare the needs the matcher must satisfy before we can resume.
//
// The needs are stuffed into a `NeedSet`. From this point on the projector
// either parks (one call site, in `project()`) or proceeds with payloads
// already in hand — there is no further need plumbing.
// =============================================================================

struct PathNeeds {
    workspace: ContextNeed,
    /// Filled per path: two needs for user-signed, one for endpoint-signed.
    path: Vec<ContextNeed>,
}

impl PathNeeds {
    fn park(self) -> ProjectionOutput {
        let mut set = NeedSet::new();
        set.add(self.workspace);
        for need in self.path {
            set.add(need);
        }
        set.park()
    }
}

fn declare_needs_for_signer(
    owner: FactId,
    invite: &DeviceInviteFact,
    authority: &InviteAuthority,
) -> PathNeeds {
    let workspace = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let path = match *authority {
        InviteAuthority::UserSigned { user_authority, user_invite } => vec![
            m::exact_need(owner, m::user_role(), user_authority),
            m::exact_need(owner, m::user_invite_role(), user_invite),
        ],
        InviteAuthority::EndpointSigned { endpoint_signer } => {
            vec![m::exact_need(owner, m::endpoint_shared_role(), endpoint_signer)]
        }
    };
    PathNeeds { workspace, path }
}

// =============================================================================
// STAGE 4: try to resolve every declared need against the context. If anything
// is missing, the caller parks. Otherwise the caller proceeds with all the
// payloads it could possibly need.
// =============================================================================

struct ResolvedPayloads<'a> {
    workspace: &'a Fact,
    authority: AuthorityPayloads<'a>,
}

enum AuthorityPayloads<'a> {
    UserSigned { user: &'a Fact, user_invite: &'a Fact },
    EndpointSigned { endpoint: &'a Fact },
}

fn collect_payloads_or_park<'a>(
    needs: &PathNeeds,
    authority: &InviteAuthority,
    ctx: &'a ProjectionContext,
) -> Option<ResolvedPayloads<'a>> {
    let workspace = ctx.payload_for(&needs.workspace)?;
    let authority = match authority {
        InviteAuthority::UserSigned { .. } => AuthorityPayloads::UserSigned {
            user: ctx.payload_for(&needs.path[0])?,
            user_invite: ctx.payload_for(&needs.path[1])?,
        },
        InviteAuthority::EndpointSigned { .. } => AuthorityPayloads::EndpointSigned {
            endpoint: ctx.payload_for(&needs.path[0])?,
        },
    };
    Some(ResolvedPayloads { workspace, authority })
}

// =============================================================================
// STAGE 5a: the workspace check is identical on both paths — same id check,
// same shape check, same two error strings.
// =============================================================================

fn verify_workspace_payload(workspace: &Fact, expected_id: FactId) -> Result<(), String> {
    require(workspace.id == expected_id,
        "device_invite workspace context payload id mismatch")?;
    workspace_layout::decode_fact(&workspace.bytes)
        .map(drop)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())
}

// =============================================================================
// STAGE 5b: dispatch to the path-specific authority chain. One line of
// dispatch keeps `project()` linear; the chains themselves live just below.
// =============================================================================

fn verify_authority_chain(
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    authority: &AuthorityPayloads<'_>,
) -> Result<(), String> {
    match *authority {
        AuthorityPayloads::UserSigned { user, user_invite } => {
            verify_user_signed_chain(envelope, invite, user, user_invite)
        }
        AuthorityPayloads::EndpointSigned { endpoint } => {
            verify_endpoint_signed_chain(envelope, invite, endpoint)
        }
    }
}

// =============================================================================
// STAGE 5c: the user-signed authority chain. Six rules, each one require() line.
//
//   1. Envelope signer id equals the named user.
//   2. User payload id equals the named user.
//   3. User envelope key equals the device_invite envelope key.
//   4. User belongs to the invite's workspace.
//   5. User envelope was signed by the named user_invite.
//   6. User_invite payload id matches, lives in the workspace, carries the
//      user's signing key.
// =============================================================================

fn verify_user_signed_chain(
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    user_payload: &Fact,
    user_invite_payload: &Fact,
) -> Result<(), String> {
    let user_envelope = verify_user_payload(envelope, invite, user_payload)?;
    let user_invite_id = invite.user_invite_event_id
        .expect("user-signed path implies Some(user_invite_event_id)");
    require(user_envelope.signer_id == user_invite_id,
        "device_invite user_invite dependency does not match signed user")?;
    verify_user_invite_payload(user_invite_payload, user_invite_id, invite.workspace_id,
        user_envelope.signer_public_key)
}

/// Rules 1-4 of the user-signed chain. Returns the user envelope so the
/// caller can reach `signer_id` for rule 5 (chain to user_invite).
fn verify_user_payload(
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    user_payload: &Fact,
) -> Result<SignedFactEnvelope, String> {
    require(envelope.signer_id == invite.user_authority_event_id,
        "user-signed device_invite authority must match signer user")?;
    require(user_payload.id == invite.user_authority_event_id,
        "device_invite user context payload id mismatch")?;
    let (user_envelope, user) = open_user(&user_payload.bytes)?;
    require(envelope.signer_public_key == user.public_key,
        "device_invite signer public key does not match user")?;
    require(user.workspace_id == invite.workspace_id,
        "device_invite user authority belongs to a different workspace")?;
    Ok(user_envelope)
}

fn open_user(
    bytes: &[u8],
) -> Result<(SignedFactEnvelope, crate::event_modules::identity_user::fact::UserFact), String> {
    open_signed(bytes, user_layout::TYPE_USER, user_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite user signer payload is invalid")
}

fn verify_user_invite_payload(
    user_invite_payload: &Fact,
    expected_id: FactId,
    expected_workspace: FactId,
    expected_key: [u8; 32],
) -> Result<(), String> {
    require(user_invite_payload.id == expected_id,
        "device_invite user_invite context payload id mismatch")?;
    let (_, user_invite) = open_user_invite(&user_invite_payload.bytes)?;
    require(user_invite.workspace_id == expected_workspace,
        "device_invite user_invite belongs to a different workspace")?;
    require(user_invite.public_key == expected_key,
        "device_invite user_invite key does not match user")
}

fn open_user_invite(
    bytes: &[u8],
) -> Result<
    (SignedFactEnvelope, crate::event_modules::identity_user_invite::fact::UserInviteFact),
    String,
> {
    open_signed(bytes, user_invite_layout::TYPE_USER_INVITE, user_invite_layout::decode_fact,
        "device_invite user_invite dependency is not a user_invite",
        "device_invite user_invite context is not a user_invite fact")
}

// =============================================================================
// STAGE 5d: the endpoint-signed authority chain. Five rules.
//
//   1. Endpoint payload id equals the envelope signer id.
//   2. Endpoint payload decodes as endpoint_shared.
//   3. Endpoint's signing key equals the invite envelope's signer key.
//   4. Endpoint and invite agree on workspace.
//   5. Endpoint and invite agree on user_authority.
// =============================================================================

fn verify_endpoint_signed_chain(
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    endpoint_payload: &Fact,
) -> Result<(), String> {
    require(endpoint_payload.id == envelope.signer_id,
        "device_invite endpoint_shared context payload id mismatch")?;
    let (_, endpoint) = open_endpoint_shared(&endpoint_payload.bytes)?;
    require(envelope.signer_public_key == endpoint.signing_public_key,
        "device_invite signer public key does not match endpoint_shared signing key")?;
    require(endpoint.workspace_id == invite.workspace_id,
        "endpoint_shared-signed device_invite workspace does not match signer")?;
    require(endpoint.user_authority_event_id == invite.user_authority_event_id,
        "endpoint_shared-signed device_invite user authority does not match signer")
}

fn open_endpoint_shared(
    bytes: &[u8],
) -> Result<
    (SignedFactEnvelope, crate::event_modules::identity_endpoint_shared::fact::EndpointSharedFact),
    String,
> {
    open_signed(bytes, endpoint_shared_layout::TYPE_ENDPOINT_SHARED,
        endpoint_shared_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite endpoint_shared signer payload is invalid")
}

// =============================================================================
// STAGE 6: emit the row + the two offers on top of the parked-needs output.
// =============================================================================

fn emit_row_and_offers(
    owner: FactId,
    invite: &DeviceInviteFact,
    parked: ProjectionOutput,
) -> ProjectionOutput {
    let row = device_invite_row(owner, invite).expect("invite already validated");
    let key = m::device_invite_key(invite.user_authority_event_id, invite.public_key);
    parked
        .intent(AtomicIntent::PutRow(row).into_intent())
        .offer(m::exact_offer(owner, m::device_invite_role()))
        .offer(m::scoped_key_offer(owner, m::device_invite_key_role(), invite.workspace_id, key))
}

// =============================================================================
// Tests: plug into the shared invariant battery.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn passes_full_invariant_battery() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
