//! Device-invite projector built around a typed context accessor.
//!
//! Idiom: `Ctx` wraps `ProjectionContext` and exposes one accessor per
//! dependency role. Each accessor records its `need` on the wrapper (so
//! `park()` always reports the full set) and returns the decoded typed
//! payload, or `Ok(None)` if the payload hasn't been delivered yet.
//! `project()` reads top-to-bottom: shape-check, declare every need, park
//! on miss, then state every cross-field rule inline as a security policy.
//!
//! No helper hides authority logic. No positional `&needs[N]` indexing.

use crate::core::context::{ContextNeed, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::layout;
use crate::event_modules::identity_device_invite::rows::device_invite_row;
use crate::event_modules::identity_endpoint_shared::fact::EndpointSharedFact;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::fact::UserFact;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::fact::UserInviteFact;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::fact::WorkspaceFact;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact::fact::SignedFactEnvelope;
use crate::event_modules::signed_fact::layout as signed_fact_layout;

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
        // 1. Shape: scope + signed envelope + invite payload.
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".into());
        }
        let envelope = signed_fact_layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
            return Err("signed fact does not contain a device_invite".into());
        }
        let invite = layout::decode_fact(&envelope.payload)?;
        non_zero(&invite.workspace_id, "device_invite fact has empty workspace_id")?;
        non_zero(&invite.user_authority_event_id, "device_invite fact has empty user_authority_event_id")?;
        non_zero(&invite.public_key, "device_invite fact has empty public_key")?;

        // 2. Declare every dependency; accessors record needs even on miss.
        let mut ctx = Ctx::new(fact.id, context);
        let workspace = ctx.workspace(invite.workspace_id)?;
        let (user, user_invite, endpoint) = match invite.user_invite_event_id {
            Some(uid) => (
                ctx.user(invite.user_authority_event_id)?,
                ctx.user_invite(uid)?,
                None,
            ),
            None => (None, None, ctx.endpoint_shared(envelope.signer_id)?),
        };

        // 3. Park while any dependency is still missing.
        let Some(_workspace) = workspace else { return Ok(ctx.park()) };

        // 4. Authority policy. Every rule stated inline.
        if let Some(user_invite_id) = invite.user_invite_event_id {
            if envelope.signer_id != invite.user_authority_event_id {
                return Err("user-signed device_invite authority must match signer user".into());
            }
            let Some((user_env, user)) = user else { return Ok(ctx.park()) };
            let Some((_, user_invite)) = user_invite else { return Ok(ctx.park()) };

            require(envelope.signer_public_key == user.public_key,
                "device_invite signer public key does not match user")?;
            require(user.workspace_id == invite.workspace_id,
                "device_invite user authority belongs to a different workspace")?;
            require(user_env.signer_id == user_invite_id,
                "device_invite user_invite dependency does not match signed user")?;
            require(user_invite.workspace_id == invite.workspace_id,
                "device_invite user_invite belongs to a different workspace")?;
            require(user_invite.public_key == user_env.signer_public_key,
                "device_invite user_invite key does not match user")?;
        } else {
            let Some((_, endpoint)) = endpoint else { return Ok(ctx.park()) };

            require(envelope.signer_public_key == endpoint.signing_public_key,
                "device_invite signer public key does not match endpoint_shared signing key")?;
            require(endpoint.workspace_id == invite.workspace_id,
                "endpoint_shared-signed device_invite workspace does not match signer")?;
            require(endpoint.user_authority_event_id == invite.user_authority_event_id,
                "endpoint_shared-signed device_invite user authority does not match signer")?;
        }

        // 5. Materialize.
        Ok(ctx.park()
            .intent(AtomicIntent::PutRow(device_invite_row(fact.id, &invite)?).into_intent())
            .offer(identity_matchers::exact_offer(fact.id, identity_matchers::device_invite_role()))
            .offer(identity_matchers::scoped_key_offer(
                fact.id,
                identity_matchers::device_invite_key_role(),
                invite.workspace_id,
                identity_matchers::device_invite_key(invite.user_authority_event_id, invite.public_key),
            )))
    }
}

// --- typed context accessor ------------------------------------------------
//
// `Ctx` records every declared need so `park()` reports the full set. Each
// accessor: (1) records the need, (2) returns `Ok(None)` on a miss,
// (3) validates payload id and decodes the typed payload on a hit.

type Signed<T> = (SignedFactEnvelope, T);

/// Specification for fetching a signed-envelope dependency.
struct SignedDep<T> {
    role: Role,
    id_mismatch: &'static str,
    inner_type: u8,
    kind_err: fn() -> String,
    payload_err: &'static str,
    decode: fn(&[u8]) -> Result<T, String>,
}

struct Ctx<'a> {
    owner: FactId,
    context: &'a ProjectionContext,
    needs: Vec<ContextNeed>,
}

impl<'a> Ctx<'a> {
    fn new(owner: FactId, context: &'a ProjectionContext) -> Self {
        Self { owner, context, needs: Vec::new() }
    }

    fn park(&self) -> ProjectionOutput {
        self.needs.iter().cloned().fold(ProjectionOutput::new(), ProjectionOutput::need)
    }

    fn workspace(&mut self, id: FactId) -> Result<Option<WorkspaceFact>, String> {
        let Some(payload) = self.declare(identity_matchers::workspace_role(), id) else {
            return Ok(None);
        };
        if payload.id != id {
            return Err("device_invite workspace context payload id mismatch".into());
        }
        workspace_layout::decode_fact(&payload.bytes)
            .map(Some)
            .map_err(|_| "device_invite workspace dependency is not a workspace".into())
    }

    fn user(&mut self, id: FactId) -> Result<Option<Signed<UserFact>>, String> {
        self.signed(id, SignedDep {
            role: identity_matchers::user_role(),
            id_mismatch: "device_invite user context payload id mismatch",
            inner_type: user_layout::TYPE_USER,
            kind_err: signer_kind_error,
            payload_err: "device_invite user signer payload is invalid",
            decode: user_layout::decode_fact,
        })
    }

    fn user_invite(&mut self, id: FactId) -> Result<Option<Signed<UserInviteFact>>, String> {
        self.signed(id, SignedDep {
            role: identity_matchers::user_invite_role(),
            id_mismatch: "device_invite user_invite context payload id mismatch",
            inner_type: user_invite_layout::TYPE_USER_INVITE,
            kind_err: user_invite_kind_error,
            payload_err: "device_invite user_invite context is not a user_invite fact",
            decode: user_invite_layout::decode_fact,
        })
    }

    fn endpoint_shared(&mut self, id: FactId) -> Result<Option<Signed<EndpointSharedFact>>, String> {
        self.signed(id, SignedDep {
            role: identity_matchers::endpoint_shared_role(),
            id_mismatch: "device_invite endpoint_shared context payload id mismatch",
            inner_type: endpoint_shared_layout::TYPE_ENDPOINT_SHARED,
            kind_err: signer_kind_error,
            payload_err: "device_invite endpoint_shared signer payload is invalid",
            decode: endpoint_shared_layout::decode_fact,
        })
    }

    /// Fetch a signed-envelope dependency. Validates payload id, envelope
    /// shape, expected `inner_type`, and inner payload decoding.
    fn signed<T>(&mut self, id: FactId, dep: SignedDep<T>) -> Result<Option<Signed<T>>, String> {
        let Some(payload) = self.declare(dep.role, id) else { return Ok(None) };
        if payload.id != id {
            return Err(dep.id_mismatch.into());
        }
        let env = signed_fact_layout::decode_signed_fact(&payload.bytes)
            .map_err(|_| (dep.kind_err)())?;
        if env.inner_type != dep.inner_type {
            return Err((dep.kind_err)());
        }
        let fact = (dep.decode)(&env.payload).map_err(|_| dep.payload_err.to_string())?;
        Ok(Some((env, fact)))
    }

    /// Record a need and return the matching payload (if any).
    fn declare(&mut self, role: Role, id: FactId) -> Option<&'a Fact> {
        let need = identity_matchers::exact_need(self.owner, role, id);
        let payload = self.context.payload_for(&need);
        self.needs.push(need);
        payload
    }
}

// --- helpers ---------------------------------------------------------------

fn non_zero(value: &[u8; 32], err: &str) -> Result<(), String> {
    if value == &[0; 32] { Err(err.into()) } else { Ok(()) }
}

fn require(cond: bool, err: &str) -> Result<(), String> {
    if cond { Ok(()) } else { Err(err.into()) }
}

fn signer_kind_error() -> String {
    "device_invite signer must be user or endpoint_shared".into()
}

fn user_invite_kind_error() -> String {
    "device_invite user_invite context is not a user_invite fact".into()
}
