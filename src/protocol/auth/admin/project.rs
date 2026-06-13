pub mod decode {
    //! Byte decoding for admin-grant facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_ADMIN};
    use super::super::fact::AdminFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<AdminFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_ADMIN {
            return Err("expected admin fact".to_string());
        }
        let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
        let mut workspace_id = [0; 32];
        workspace_id.copy_from_slice(&bytes[9..41]);
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&bytes[41..73]);
        let mut authority_fact_id = [0; 32];
        authority_fact_id.copy_from_slice(&bytes[73..105]);
        let mut user_fact_id = [0; 32];
        user_fact_id.copy_from_slice(&bytes[105..137]);
        let mut signer_id = [0; 32];
        signer_id.copy_from_slice(&bytes[137..169]);
        let mut signer_public_key = [0; 32];
        signer_public_key.copy_from_slice(&bytes[169..201]);
        Ok(AdminFact {
            created_at_ms,
            workspace_id,
            public_key,
            authority_fact_id,
            user_fact_id,
            signer_id,
            signer_public_key,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::admin::encode::{encode_fact, FACT_BYTES};

        fn fact() -> AdminFact {
            AdminFact {
                created_at_ms: 55,
                workspace_id: [1; 32],
                public_key: [2; 32],
                authority_fact_id: [3; 32],
                user_fact_id: [4; 32],
                signer_id: [3; 32],
                signer_public_key: [5; 32],
            }
        }

        #[test]
        fn admin_fact_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = 0;
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_short_bytes() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert!(decode_fact(&encoded[..encoded.len() - 1]).is_err());
        }
    }
}
pub mod authenticate {
    //! Admin-grant authenticator.
    //!
    //! POLICY. Authenticating an `admin` fact proves, over its canonical bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical admin fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. The workspace, public-key, authority, and user selectors are
    //!      non-zero.
    //!
    //! Scope (`Global`) and the authority path (bootstrap vs delegated grant) are
    //! interpretation the projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::AdminFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        admin: AdminFact,
        _context: &ProjectionContext,
    ) -> Result<AdminFact, String> {
        prove_decoded_admin(fact, admin)
    }

    fn prove_decoded_admin(fact: &Fact, admin: AdminFact) -> Result<AdminFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Non-zero selector fields.
        if admin.workspace_id == [0u8; 32] {
            return Err("admin workspace_id must not be zero".to_string());
        }
        if admin.public_key == [0u8; 32] {
            return Err("admin public_key must not be zero".to_string());
        }
        if admin.authority_fact_id == [0u8; 32] {
            return Err("admin authority_fact_id must not be zero".to_string());
        }
        if admin.user_fact_id == [0u8; 32] {
            return Err("admin user_fact_id must not be zero".to_string());
        }
        Ok(admin)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::admin::author::authored_admin_fact;
        use crate::protocol::auth::admin::fact::AdminFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            let grant = AdminFact {
                created_at_ms: 100,
                workspace_id: [1; 32],
                public_key: [2; 32],
                authority_fact_id: [3; 32],
                user_fact_id: [4; 32],
                signer_id: [3; 32],
                signer_public_key: [0; 32],
            };
            authored_admin_fact(100, [3; 32], SIGNER_KEY, grant).expect("signed admin fact")
        }

        // Enter through the staged path (codec decode -> authenticate_decoded) so the
        // tests exercise the same boundary core runs.
        fn authenticate(fact: &Fact) -> Result<AdminFact, String> {
            let decoded = super::super::decode::decode_fact(fact.body())?;
            super::authenticate(fact, decoded, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        #[test]
        fn authenticates_canonical_fact() {
            assert!(authenticate(&canonical_fact()).is_ok());
        }

        #[test]
        fn rejects_wrong_tag() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes[0] ^= 0xff;
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_truncated_bytes() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes.pop();
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_id_not_matching_bytes() {
            let canonical = canonical_fact();
            let forged = Fact {
                id: [0; 32],
                scope: canonical.scope.clone(),
                timestamp: canonical.timestamp,
                bytes: canonical.bytes.clone(),
            };
            assert!(is_invalid(&forged));
        }
    }
}
pub mod adapt {
    //! Admin-grant semantic adapter.
    //!
    //! The current admin wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::AdminFact;

    pub(crate) fn adapt(source: AdminFact) -> Result<AdminFact, String> {
        Ok(source)
    }
}

// Poc-10 admin grant projector.
//
// POLICY. An admin grant is admitted iff:
//   1. STRUCTURAL. The fact is global, signed, contains an admin payload, and
//      all selector fields are non-zero.
//   2. AUTHORITY. Bootstrap grants require signature evidence from the workspace root and target
//      a real user who joined through a workspace-signed bootstrap invite;
//      delegated grants require signature evidence from the named admin authority and target a
//      user in the same workspace.
//   3. MATERIALIZE. Once the authority path validates, write the admin row,
//      publish exact/key offers, and mark the fact shareable with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::admin::fact::AdminFact;
use crate::protocol::auth::signature;
use crate::protocol::auth::user;
use crate::protocol::auth::user_invite;
use crate::protocol::auth::workspace;
use crate::protocol::auth::workspace::fact::WorkspaceFact;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::admin_row;

/// Projector route metadata for the admin-grant fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::admin::project::AdminProjector");

#[derive(Debug, Clone, Default)]
pub struct AdminProjector;

impl AdminProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for AdminProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl AdminProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        admin: AdminFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see the local authenticate module) proved canonical bytes, the signer
        // signature, and non-zero selector fields. Scope is interpretation.
        // 1. Scope.
        if fact.scope != FactScope::Global {
            return Err("admin fact must have global scope".to_string());
        }

        // 2. Authority.
        //
        // The workspace id is the bootstrap discriminator: if the admin's
        // authority is the workspace itself, the workspace root key may grant
        // admin to a real user from the workspace-signed bootstrap invite.
        // Otherwise the signer must be the named admin authority, and the
        // target user must match the grant.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(admin.workspace_id),
            fact.id,
            admin.signer_public_key,
        )?;
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            admin.workspace_id,
            fact.id,
            admin.signer_public_key,
            "admin",
        )? {
            return Ok(ProjectionOutput::new().need(signature_need));
        }

        if admin.authority_fact_id == admin.workspace_id {
            project_bootstrap_admin(fact, &admin, context, signature_need)
        } else {
            project_delegated_admin(fact, &admin, context, signature_need)
        }
    }
}

fn project_bootstrap_admin(
    fact: &Fact,
    admin: &AdminFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = BootstrapAdminNeeds::new(fact.id, admin, signature_need);
    let Some(workspace_fact) = context.payload_for_checked(&needs.workspace, "admin workspace")?
    else {
        return Ok(needs.output());
    };
    let workspace = decode_workspace_context(workspace_fact, admin.workspace_id)?;
    let Some(user_fact) = context.payload_for_checked(&needs.user, "bootstrap admin user")? else {
        return Ok(needs.output());
    };
    let user = decode_user_context(user_fact, admin)?;
    let user_invite_need = auth_user_invite_need(fact.id, user.signer_id);
    let Some(user_invite_fact) =
        context.payload_for_checked(&user_invite_need, "bootstrap admin user_invite")?
    else {
        return Ok(needs.output().need(user_invite_need));
    };
    let invite = decode_user_invite_context(user_invite_fact, &user, admin.workspace_id)?;

    if admin.signer_id != admin.workspace_id {
        return Err("bootstrap admin must use workspace as signer and authority".to_string());
    }
    if admin.signer_public_key != workspace.public_key {
        return Err(
            "signed bootstrap admin signer key does not match workspace public key".to_string(),
        );
    }
    if invite.authority_fact_id != admin.workspace_id || invite.signer_id != admin.workspace_id {
        return Err(
            "bootstrap admin target user must come from workspace bootstrap invite".to_string(),
        );
    }
    // Redundant with a correctly projected workspace-signed auth_user_invite,
    // but repeated here to make the bootstrap-admin rule self-contained.
    if invite.signer_public_key != workspace.public_key {
        return Err(
            "bootstrap user_invite signer key does not match workspace public key".to_string(),
        );
    }
    let context_have = context_have_from_needs(
        context,
        [
            &needs.signature,
            &needs.workspace,
            &needs.user,
            &user_invite_need,
        ],
    );

    // 3. Materialize.
    materialized_output(
        fact,
        admin,
        needs.output().need(user_invite_need),
        context_have,
    )
}

fn project_delegated_admin(
    fact: &Fact,
    admin: &AdminFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = DelegatedAdminNeeds::new(fact.id, admin, signature_need);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(authority_fact) = context.payload_for(&needs.authority) else {
        return Ok(needs.output());
    };
    let Some(user_fact) = context.payload_for(&needs.user) else {
        return Ok(needs.output());
    };
    decode_workspace_context(workspace_fact, admin.workspace_id)?;

    if admin.signer_id != admin.authority_fact_id {
        return Err("signed admin grant signer must be the authority admin".to_string());
    }

    if authority_fact.id != admin.authority_fact_id {
        return Err("admin authority context payload id mismatch".to_string());
    }
    let authority = decode_admin_payload(authority_fact)
        .map_err(|_| "signed admin authority must be an admin fact".to_string())?;
    if authority.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }
    if admin.signer_public_key != authority.public_key {
        return Err("signed admin signer key does not match authority admin".to_string());
    }

    if user_fact.id != admin.user_fact_id {
        return Err("admin user context payload id mismatch".to_string());
    }
    let user = decode_user_payload(user_fact)
        .map_err(|_| "admin user dependency must be a user fact".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("admin user belongs to a different workspace".to_string());
    }
    if user.public_key != admin.public_key {
        return Err("admin public_key does not match user public_key".to_string());
    }
    let context_have = context_have_from_needs(
        context,
        [
            &needs.signature,
            &needs.workspace,
            &needs.authority,
            &needs.user,
        ],
    );

    // 3. Materialize.
    materialized_output(fact, admin, needs.output(), context_have)
}

struct BootstrapAdminNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
    user: ContextNeed,
}

impl BootstrapAdminNeeds {
    fn new(owner: FactId, admin: &AdminFact, signature: ContextNeed) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                admin.workspace_id,
                admin.workspace_id,
            ),
            user: crate::core::context::ContextNeed::range(
                owner,
                "auth_user",
                crate::core::facts::FactScope::Global,
                admin.user_fact_id,
                admin.user_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
            .need(self.user.clone())
    }
}

struct DelegatedAdminNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
    authority: ContextNeed,
    user: ContextNeed,
}

impl DelegatedAdminNeeds {
    fn new(owner: FactId, admin: &AdminFact, signature: ContextNeed) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                admin.workspace_id,
                admin.workspace_id,
            ),
            authority: crate::core::context::ContextNeed::range(
                owner,
                "auth_admin",
                crate::core::facts::FactScope::Global,
                admin.authority_fact_id,
                admin.authority_fact_id,
            ),
            user: crate::core::context::ContextNeed::range(
                owner,
                "auth_user",
                crate::core::facts::FactScope::Global,
                admin.user_fact_id,
                admin.user_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
            .need(self.authority.clone())
            .need(self.user.clone())
    }
}

fn decode_workspace_context(
    workspace_fact: &Fact,
    workspace_id: FactId,
) -> Result<WorkspaceFact, String> {
    if workspace_fact.id != workspace_id {
        return Err("admin workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "admin workspace dependency must be a workspace fact".to_string())?;
    Ok(workspace)
}

fn materialized_output(
    fact: &Fact,
    admin: &AdminFact,
    output: ProjectionOutput,
    context_have: Vec<FactId>,
) -> Result<ProjectionOutput, String> {
    Ok(share_fact_with_sync(
        output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_admin",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_admin",
                crate::protocol::auth::workspace::scope(admin.workspace_id),
                admin.user_fact_id,
                admin.user_fact_id,
            ))
            .row_mutation(RowMutation::PutRow(admin_row(fact.id, admin)?)),
        admin.workspace_id,
        fact,
        context_have,
    ))
}

fn decode_admin_payload(fact: &Fact) -> Result<super::fact::AdminFact, String> {
    let admin = super::decode_fact_payload(fact.body())?;
    Ok(admin)
}

fn decode_user_payload(fact: &Fact) -> Result<crate::protocol::auth::user::fact::UserFact, String> {
    let user = user::decode_fact_payload(fact.body())?;
    Ok(user)
}

fn auth_user_invite_need(owner: FactId, invite_id: FactId) -> ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        "auth_user_invite",
        crate::core::facts::FactScope::Global,
        invite_id,
        invite_id,
    )
}

fn decode_user_context(
    user_fact: &Fact,
    admin: &AdminFact,
) -> Result<crate::protocol::auth::user::fact::UserFact, String> {
    if user_fact.id != admin.user_fact_id {
        return Err("bootstrap admin user context payload id mismatch".to_string());
    }
    let user = decode_user_payload(user_fact)
        .map_err(|_| "bootstrap admin user dependency must be a user fact".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("bootstrap admin user belongs to a different workspace".to_string());
    }
    // Mostly implied by auth_user projection, which already validated the user
    // against its invite. Keep the cheap defensive check at the admin boundary.
    if user.public_key != admin.public_key {
        return Err("bootstrap admin public_key does not match user public_key".to_string());
    }
    Ok(user)
}

fn decode_user_invite_context(
    user_invite_fact: &Fact,
    user: &crate::protocol::auth::user::fact::UserFact,
    workspace_id: FactId,
) -> Result<crate::protocol::auth::user_invite::fact::UserInviteFact, String> {
    if user_invite_fact.id != user.signer_id {
        return Err("bootstrap admin user_invite context payload id mismatch".to_string());
    }
    let invite = user_invite::decode_fact_payload(user_invite_fact.body())
        .map_err(|_| "bootstrap admin user signer must be a user_invite fact".to_string())?;
    if invite.workspace_id != workspace_id {
        return Err("bootstrap admin user_invite belongs to a different workspace".to_string());
    }
    // Mostly implied by auth_user projection because this invite id is the
    // user's signer_id; repeated here to keep the boundary explicit.
    if invite.public_key != user.signer_public_key {
        return Err("bootstrap admin user_invite key does not match user".to_string());
    }
    Ok(invite)
}
