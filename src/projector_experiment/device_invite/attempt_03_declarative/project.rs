//! Device-invite projector expressed as a top-to-bottom security checklist.
//!
//! # Idiom
//!
//! The projector's logic is a single ordered list of invariants. Each entry is
//! a `Check` enum variant that names what it enforces. A short interpreter
//! walks the list in order; the first failing check produces the error, and
//! when every check passes the projector emits its row and offers.
//!
//! # Why this shape
//!
//! Reviewers reading this file can scan `POLICY_*` once and see the entire
//! contract a device_invite must satisfy. The variant names read like sentences
//! in a security spec ("WorkspacePayloadMustDecodeAsWorkspace",
//! "UserInviteKeyMustMatchUserKey"). The interpreter is a 3-line loop, so
//! there is no hidden orchestration: what you see in `POLICY_*` is what runs.
//!
//! # Two shapes tried
//!
//! A *closure-driven* shape was sketched: `&[fn(&Scene) -> Result<()>]`. It
//! loses the named-invariant property because closures cannot be named at the
//! type level — reviewers lose the scannable variant list and the compiler can
//! no longer flag a missing arm when a variant is added. Rejected in favor of
//! enum + per-variant inline predicates.
//!
//! # Tradeoffs of the chosen shape
//!
//! - One layer of indirection: jumping from a `Check::` variant to its `apply`
//!   arm. Mitigated by keeping every arm to a single `ensure(predicate, msg)`.
//! - Two paths (user-signed, endpoint-signed) share the workspace prelude but
//!   diverge after. The list is split into `POLICY_SHARED_PRELUDE` plus per-
//!   path tails to make the divergence obvious without duplicating checks.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::{
    fact::DeviceInviteFact, layout, rows::device_invite_row,
};
use crate::event_modules::identity_endpoint_shared::{
    fact::EndpointSharedFact, layout as endpoint_shared_layout,
};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::{fact::UserFact, layout as user_layout};
use crate::event_modules::identity_user_invite::{
    fact::UserInviteFact, layout as user_invite_layout,
};
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact::{self, fact::SignedFactEnvelope};

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DeviceInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // (1) Parse the envelope + body so the policy can speak in typed values.
        let parsed = parse(fact)?;
        // (2) Declare context needs so the matcher can resume us.
        let needs = authority_needs(fact.id, &parsed.invite, parsed.envelope.signer_id);
        // (3) If any need is unfulfilled, park.
        if !context_complete(&needs, context) {
            return Ok(needs_output(&needs));
        }
        // (4) Full context present: walk the policy. First failure is the error.
        let scene = Scene::gather(&parsed, &needs, context);
        for check in policy_for(&scene) {
            check.apply(&scene)?;
        }
        // (5) Every invariant satisfied: emit the row plus the two offers.
        materialize(&needs, fact.id, &parsed.invite)
    }
}

// =============================================================================
// THE POLICY                                  (read me top-to-bottom)
// =============================================================================

/// Every device_invite must satisfy these workspace checks regardless of signer.
const POLICY_SHARED_PRELUDE: &[Check] = &[
    Check::WorkspaceContextPayloadIdMustEqualWorkspaceId,
    Check::WorkspacePayloadMustDecodeAsWorkspace,
];

/// User-signed invites: the signer IS the user; we ride the user's admission
/// chain (user_invite) back one step.
const POLICY_USER_SIGNED: &[Check] = &[
    Check::SignerIdMustEqualUserAuthority,
    Check::UserContextPayloadIdMustEqualUserAuthority,
    Check::UserPayloadMustDecodeAsSignedUser,
    Check::SignerKeyMustEqualUserKey,
    Check::UserMustBelongToInviteWorkspace,
    Check::UserMustBeSignedByNamedUserInvite,
    Check::UserInviteContextPayloadIdMustEqualUserInviteId,
    Check::UserInvitePayloadMustDecodeAsSignedUserInvite,
    Check::UserInviteMustBelongToInviteWorkspace,
    Check::UserInviteKeyMustMatchUserKey,
];

/// Endpoint-signed invites: the signer is an already-projected endpoint_shared
/// fact for the same user authority.
const POLICY_ENDPOINT_SIGNED: &[Check] = &[
    Check::EndpointSharedContextPayloadIdMustEqualSignerId,
    Check::EndpointSharedPayloadMustDecodeAsSignedEndpointShared,
    Check::SignerKeyMustEqualEndpointSigningKey,
    Check::EndpointSharedWorkspaceMustMatchInviteWorkspace,
    Check::EndpointSharedUserAuthorityMustMatchInviteUserAuthority,
];

#[derive(Debug, Clone, Copy)]
enum Check {
    // shared
    WorkspaceContextPayloadIdMustEqualWorkspaceId,
    WorkspacePayloadMustDecodeAsWorkspace,
    // user-signed path
    SignerIdMustEqualUserAuthority,
    UserContextPayloadIdMustEqualUserAuthority,
    UserPayloadMustDecodeAsSignedUser,
    SignerKeyMustEqualUserKey,
    UserMustBelongToInviteWorkspace,
    UserMustBeSignedByNamedUserInvite,
    UserInviteContextPayloadIdMustEqualUserInviteId,
    UserInvitePayloadMustDecodeAsSignedUserInvite,
    UserInviteMustBelongToInviteWorkspace,
    UserInviteKeyMustMatchUserKey,
    // endpoint-signed path
    EndpointSharedContextPayloadIdMustEqualSignerId,
    EndpointSharedPayloadMustDecodeAsSignedEndpointShared,
    SignerKeyMustEqualEndpointSigningKey,
    EndpointSharedWorkspaceMustMatchInviteWorkspace,
    EndpointSharedUserAuthorityMustMatchInviteUserAuthority,
}

fn policy_for(scene: &Scene<'_>) -> impl Iterator<Item = Check> {
    let tail = if scene.is_user_signed() {
        POLICY_USER_SIGNED
    } else {
        POLICY_ENDPOINT_SIGNED
    };
    POLICY_SHARED_PRELUDE.iter().chain(tail.iter()).copied()
}

// =============================================================================
// THE INTERPRETER                             (one ensure() per Check)
// =============================================================================
//
// Each arm produces a Result. The compiler enforces exhaustiveness: add a
// variant above and the match below stops compiling until you cover it.

impl Check {
    fn apply(self, s: &Scene<'_>) -> Result<(), String> {
        use Check::*;
        match self {
            WorkspaceContextPayloadIdMustEqualWorkspaceId => ensure(
                s.workspace_payload.id == s.parsed.invite.workspace_id,
                "device_invite workspace context payload id mismatch",
            ),
            WorkspacePayloadMustDecodeAsWorkspace => {
                workspace_layout::decode_fact(&s.workspace_payload.bytes)
                    .map(drop)
                    .map_err(|_| "device_invite workspace dependency is not a workspace".into())
            }

            SignerIdMustEqualUserAuthority => ensure(
                s.parsed.envelope.signer_id == s.parsed.invite.user_authority_event_id,
                "user-signed device_invite authority must match signer user",
            ),
            UserContextPayloadIdMustEqualUserAuthority => ensure(
                s.user_payload().id == s.parsed.invite.user_authority_event_id,
                "device_invite user context payload id mismatch",
            ),
            UserPayloadMustDecodeAsSignedUser => s.signed_user().map(drop),
            SignerKeyMustEqualUserKey => ensure(
                s.parsed.envelope.signer_public_key == s.signed_user()?.body.public_key,
                "device_invite signer public key does not match user",
            ),
            UserMustBelongToInviteWorkspace => ensure(
                s.signed_user()?.body.workspace_id == s.parsed.invite.workspace_id,
                "device_invite user authority belongs to a different workspace",
            ),
            UserMustBeSignedByNamedUserInvite => ensure(
                s.signed_user()?.envelope.signer_id == s.named_user_invite(),
                "device_invite user_invite dependency does not match signed user",
            ),
            UserInviteContextPayloadIdMustEqualUserInviteId => ensure(
                s.user_invite_payload().id == s.named_user_invite(),
                "device_invite user_invite context payload id mismatch",
            ),
            UserInvitePayloadMustDecodeAsSignedUserInvite => s.signed_user_invite().map(drop),
            UserInviteMustBelongToInviteWorkspace => ensure(
                s.signed_user_invite()?.body.workspace_id == s.parsed.invite.workspace_id,
                "device_invite user_invite belongs to a different workspace",
            ),
            UserInviteKeyMustMatchUserKey => ensure(
                s.signed_user_invite()?.body.public_key
                    == s.signed_user()?.envelope.signer_public_key,
                "device_invite user_invite key does not match user",
            ),

            EndpointSharedContextPayloadIdMustEqualSignerId => ensure(
                s.endpoint_payload().id == s.parsed.envelope.signer_id,
                "device_invite endpoint_shared context payload id mismatch",
            ),
            EndpointSharedPayloadMustDecodeAsSignedEndpointShared => {
                s.signed_endpoint_shared().map(drop)
            }
            SignerKeyMustEqualEndpointSigningKey => ensure(
                s.parsed.envelope.signer_public_key
                    == s.signed_endpoint_shared()?.body.signing_public_key,
                "device_invite signer public key does not match endpoint_shared signing key",
            ),
            EndpointSharedWorkspaceMustMatchInviteWorkspace => ensure(
                s.signed_endpoint_shared()?.body.workspace_id == s.parsed.invite.workspace_id,
                "endpoint_shared-signed device_invite workspace does not match signer",
            ),
            EndpointSharedUserAuthorityMustMatchInviteUserAuthority => ensure(
                s.signed_endpoint_shared()?.body.user_authority_event_id
                    == s.parsed.invite.user_authority_event_id,
                "endpoint_shared-signed device_invite user authority does not match signer",
            ),
        }
    }
}

// =============================================================================
// STRUCTURAL PARSING
// =============================================================================

struct Parsed {
    envelope: SignedFactEnvelope,
    invite: DeviceInviteFact,
}

fn parse(fact: &Fact) -> Result<Parsed, String> {
    if fact.scope != FactScope::Global {
        return Err("device_invite fact must have global scope".into());
    }
    let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
        .map_err(|_| "device_invite fact must be signed".to_string())?;
    if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
        return Err("signed fact does not contain a device_invite".into());
    }
    let invite = layout::decode_fact(&envelope.payload)?;
    if invite.workspace_id == [0; 32] {
        return Err("device_invite fact has empty workspace_id".into());
    }
    if invite.user_authority_event_id == [0; 32] {
        return Err("device_invite fact has empty user_authority_event_id".into());
    }
    if invite.public_key == [0; 32] {
        return Err("device_invite fact has empty public_key".into());
    }
    Ok(Parsed { envelope, invite })
}

// =============================================================================
// SCENE: typed view of the parsed inputs + matched context payloads
// =============================================================================

struct Scene<'a> {
    parsed: &'a Parsed,
    workspace_payload: &'a Fact,
    /// Present on the user-signed path; None on the endpoint-signed path.
    user_payload: Option<&'a Fact>,
    /// Present on the user-signed path; None on the endpoint-signed path.
    user_invite_payload: Option<&'a Fact>,
    /// Present on the endpoint-signed path; None on the user-signed path.
    endpoint_payload: Option<&'a Fact>,
}

impl<'a> Scene<'a> {
    fn gather(parsed: &'a Parsed, needs: &[ContextNeed], context: &'a ProjectionContext) -> Self {
        // needs[0] is always the workspace need (see `authority_needs`).
        let workspace_payload = payload(&needs[0], context);
        if parsed.invite.user_invite_event_id.is_some() {
            Self {
                parsed,
                workspace_payload,
                user_payload: Some(payload(&needs[1], context)),
                user_invite_payload: Some(payload(&needs[2], context)),
                endpoint_payload: None,
            }
        } else {
            Self {
                parsed,
                workspace_payload,
                user_payload: None,
                user_invite_payload: None,
                endpoint_payload: Some(payload(&needs[1], context)),
            }
        }
    }

    fn is_user_signed(&self) -> bool {
        self.parsed.invite.user_invite_event_id.is_some()
    }

    fn named_user_invite(&self) -> [u8; 32] {
        self.parsed
            .invite
            .user_invite_event_id
            .expect("only called from the user-signed policy tail")
    }

    fn user_payload(&self) -> &Fact {
        self.user_payload
            .expect("only called from the user-signed policy tail")
    }

    fn user_invite_payload(&self) -> &Fact {
        self.user_invite_payload
            .expect("only called from the user-signed policy tail")
    }

    fn endpoint_payload(&self) -> &Fact {
        self.endpoint_payload
            .expect("only called from the endpoint-signed policy tail")
    }

    fn signed_user(&self) -> Result<Signed<UserFact>, String> {
        decode_signed(
            self.user_payload(),
            user_layout::TYPE_USER,
            user_layout::decode_fact,
            "device_invite signer must be user or endpoint_shared",
            "device_invite user signer payload is invalid",
        )
    }

    fn signed_user_invite(&self) -> Result<Signed<UserInviteFact>, String> {
        decode_signed(
            self.user_invite_payload(),
            user_invite_layout::TYPE_USER_INVITE,
            user_invite_layout::decode_fact,
            "device_invite user_invite context is not a user_invite fact",
            "device_invite user_invite context is not a user_invite fact",
        )
    }

    fn signed_endpoint_shared(&self) -> Result<Signed<EndpointSharedFact>, String> {
        decode_signed(
            self.endpoint_payload(),
            endpoint_shared_layout::TYPE_ENDPOINT_SHARED,
            endpoint_shared_layout::decode_fact,
            "device_invite signer must be user or endpoint_shared",
            "device_invite endpoint_shared signer payload is invalid",
        )
    }
}

// =============================================================================
// SHARED PRIMITIVES
// =============================================================================

struct Signed<T> {
    envelope: SignedFactEnvelope,
    body: T,
}

fn decode_signed<T>(
    payload: &Fact,
    expected_inner_type: u8,
    decode_body: fn(&[u8]) -> Result<T, String>,
    bad_envelope_msg: &str,
    bad_body_msg: &str,
) -> Result<Signed<T>, String> {
    let envelope = signed_fact::layout::decode_signed_fact(&payload.bytes)
        .map_err(|_| bad_envelope_msg.to_string())?;
    if envelope.inner_type != expected_inner_type {
        return Err(bad_envelope_msg.into());
    }
    let body = decode_body(&envelope.payload).map_err(|_| bad_body_msg.to_string())?;
    Ok(Signed { envelope, body })
}

fn ensure(predicate: bool, message: &str) -> Result<(), String> {
    if predicate {
        Ok(())
    } else {
        Err(message.into())
    }
}

// =============================================================================
// NEEDS DECLARATION + OUTPUT ASSEMBLY
// =============================================================================

fn authority_needs(
    owner: [u8; 32],
    invite: &DeviceInviteFact,
    signer_id: [u8; 32],
) -> Vec<ContextNeed> {
    let workspace = identity_matchers::exact_need(
        owner,
        identity_matchers::workspace_role(),
        invite.workspace_id,
    );
    match invite.user_invite_event_id {
        Some(user_invite_id) => vec![
            workspace,
            identity_matchers::exact_need(
                owner,
                identity_matchers::user_role(),
                invite.user_authority_event_id,
            ),
            identity_matchers::exact_need(
                owner,
                identity_matchers::user_invite_role(),
                user_invite_id,
            ),
        ],
        None => vec![
            workspace,
            identity_matchers::exact_need(
                owner,
                identity_matchers::endpoint_shared_role(),
                signer_id,
            ),
        ],
    }
}

fn context_complete(needs: &[ContextNeed], context: &ProjectionContext) -> bool {
    needs.iter().all(|need| context.payload_for(need).is_some())
}

fn payload<'a>(need: &ContextNeed, context: &'a ProjectionContext) -> &'a Fact {
    context
        .payload_for(need)
        .expect("context_complete already verified")
}

fn needs_output(needs: &[ContextNeed]) -> ProjectionOutput {
    needs
        .iter()
        .cloned()
        .fold(ProjectionOutput::new(), |out, need| out.need(need))
}

fn materialize(
    needs: &[ContextNeed],
    fact_id: [u8; 32],
    invite: &DeviceInviteFact,
) -> Result<ProjectionOutput, String> {
    Ok(needs_output(needs)
        .intent(AtomicIntent::PutRow(device_invite_row(fact_id, invite)?).into_intent())
        .offer(identity_matchers::exact_offer(
            fact_id,
            identity_matchers::device_invite_role(),
        ))
        .offer(identity_matchers::scoped_key_offer(
            fact_id,
            identity_matchers::device_invite_key_role(),
            invite.workspace_id,
            identity_matchers::device_invite_key(invite.user_authority_event_id, invite.public_key),
        )))
}
