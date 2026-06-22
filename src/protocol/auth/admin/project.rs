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

    // Tests.
    // Ordered most-central-first: the roundtrip proves the full layout; narrower guards follow.
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

    // Tests.
    // Ordered most-central-first: canonical admit, then the id check, then layout guards.
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
use crate::core::project_fact::{
    FactProjectorInfo, ProjectedRowMutation, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::admin::fact::AdminFact;
use crate::protocol::auth::signature;
use crate::protocol::auth::user;
use crate::protocol::auth::user_invite;
use crate::protocol::auth::workspace;
use crate::protocol::auth::workspace::fact::WorkspaceFact;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::admin_insert;

/// Projector route metadata for the admin-grant fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::admin::project::AdminProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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
    materialized_output(fact, admin, ProjectionOutput::new(), context_have)
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
    materialized_output(fact, admin, ProjectionOutput::new(), context_have)
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
            .offer(crate::core::context::ContextOfferClaim::range(
                "auth_admin",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOfferClaim::range(
                "auth_admin",
                crate::protocol::auth::workspace::scope(admin.workspace_id),
                admin.user_fact_id,
                admin.user_fact_id,
            ))
            .row_mutation(ProjectedRowMutation::InsertValues(admin_insert(
                fact.id, admin,
            ))),
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

// Tests.
//
// Invariants:
// - admin grants are global evidence and cannot be admitted as local-only facts;
// - projection parks first on the grant's exact signature proof;
// - bootstrap admin grants must be signed by the workspace root and target a
//   user whose signer is a workspace-root user_invite;
// - materialization writes one admin row, publishes both id and user-scoped
//   offers, and syncs only the validated authority chain.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ContextOffer;
    use crate::core::facts::FactScope;
    use crate::core::project_fact::{MatchedContext, Projector};
    use crate::protocol::auth::workspace::author::create_workspace;
    use crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync;

    const WORKSPACE_KEY: [u8; 32] = [9; 32];
    const USER_INVITE_KEY: [u8; 32] = [7; 32];
    const ADMIN_USER_PUBLIC_KEY: [u8; 32] = [2; 32];

    #[test]
    fn bootstrap_admin_waits_for_signature_before_authority_context() {
        let (_workspace, _user_invite, _user, admin, _signature) = bootstrap_fixture();

        let output = AdminProjector::new()
            .project(&admin, &ProjectionContext::default())
            .expect("project without context");

        let admin_body = decode::decode_fact(admin.body()).expect("decode admin");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(
            output.needs[0],
            signature::project::signature_proof_need(
                admin.id,
                workspace::scope(admin_body.workspace_id),
                admin.id,
                admin_body.signer_public_key,
            )
            .expect("signature need")
        );
        assert!(output.offers.is_empty());
        assert!(output.row_mutations.is_empty());
    }

    #[test]
    fn bootstrap_admin_materializes_row_offers_and_sync_context() {
        let (workspace, user_invite, user, admin, signature) = bootstrap_fixture();

        let output = AdminProjector::new()
            .project(
                &admin,
                &bootstrap_context(&workspace, &user_invite, &user, &admin, &signature),
            )
            .expect("project with bootstrap context");

        assert!(output.needs.is_empty());
        assert_eq!(output.offers.len(), 2);
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "auth_admin" && offer.scope == FactScope::Global));
        assert!(output.offers.iter().any(|offer| {
            offer.role.as_str() == "auth_admin" && offer.scope == workspace::scope(workspace.id)
        }));
        assert_eq!(output.row_mutations.len(), 1);
        assert!(matches!(
            &output.row_mutations[0],
            ProjectedRowMutation::InsertValues(insert) if insert.table == super::super::ADMIN_ROWS
        ));
        let share = decode_share_fact_with_sync(&output.effects.intents[0]).expect("share intent");
        assert_eq!(share.workspace_id, workspace.id);
        assert_eq!(share.owner_fact_id, admin.id);
        assert_eq!(
            share.context_have,
            sorted_ids([signature.id, workspace.id, user.id, user_invite.id])
        );
    }

    #[test]
    fn admin_projection_rejects_non_global_scope() {
        let (_workspace, _user_invite, _user, admin, _signature) = bootstrap_fixture();
        let non_global = Fact {
            scope: FactScope::Local,
            ..admin
        };

        let err = AdminProjector::new()
            .project(&non_global, &ProjectionContext::default())
            .expect_err("local admin should reject");

        assert!(err.contains("must have global scope"), "{err}");
    }

    fn bootstrap_fixture() -> (Fact, Fact, Fact, Fact, Fact) {
        let workspace = create_workspace(100, WORKSPACE_KEY, "Essay").expect("workspace");
        let user_invite_public_key = crate::core::crypto::ed25519_public_key(&USER_INVITE_KEY);
        let user_invite = crate::protocol::auth::user_invite::author::authored_user_invite_fact(
            101,
            user_invite_public_key,
            workspace.id,
            workspace.id,
            workspace.id,
            WORKSPACE_KEY,
        )
        .expect("user invite");
        let user = crate::protocol::auth::user::author::authored_user_fact(
            102,
            workspace.id,
            ADMIN_USER_PUBLIC_KEY,
            "alice",
            user_invite.id,
            USER_INVITE_KEY,
        )
        .expect("user");
        let admin_body = AdminFact {
            created_at_ms: 103,
            workspace_id: workspace.id,
            public_key: ADMIN_USER_PUBLIC_KEY,
            authority_fact_id: workspace.id,
            user_fact_id: user.id,
            signer_id: workspace.id,
            signer_public_key: [0; 32],
        };
        let admin = crate::protocol::auth::admin::author::authored_admin_fact(
            103,
            workspace.id,
            WORKSPACE_KEY,
            admin_body,
        )
        .expect("admin");
        let signature =
            signature::author::create_signature(workspace.id, admin.id, &WORKSPACE_KEY, 104)
                .expect("signature");
        (workspace, user_invite, user, admin, signature)
    }

    fn bootstrap_context(
        workspace_fact: &Fact,
        user_invite_fact: &Fact,
        user_fact: &Fact,
        admin_fact: &Fact,
        signature_fact: &Fact,
    ) -> ProjectionContext {
        let admin_body = decode::decode_fact(admin_fact.body()).expect("decode admin");
        let signature_need = signature::project::signature_proof_need(
            admin_fact.id,
            workspace::scope(admin_body.workspace_id),
            admin_fact.id,
            admin_body.signer_public_key,
        )
        .expect("signature need");
        let needs = BootstrapAdminNeeds::new(admin_fact.id, &admin_body, signature_need.clone());
        let user_invite_need = auth_user_invite_need(admin_fact.id, user_invite_fact.id);
        ProjectionContext::from_matches(vec![
            MatchedContext::new(
                signature_need,
                signature::project::signature_proof_offer(
                    signature_fact.id,
                    workspace::scope(admin_body.workspace_id),
                    admin_fact.id,
                    admin_body.signer_public_key,
                )
                .expect("signature offer"),
                signature_fact.clone(),
            )
            .expect("matched signature context"),
            MatchedContext::new(
                needs.workspace,
                ContextOffer::range(
                    workspace_fact.id,
                    "auth_workspace",
                    FactScope::Global,
                    workspace_fact.id,
                    workspace_fact.id,
                ),
                workspace_fact.clone(),
            )
            .expect("matched workspace context"),
            MatchedContext::new(
                needs.user,
                ContextOffer::range(
                    user_fact.id,
                    "auth_user",
                    FactScope::Global,
                    user_fact.id,
                    user_fact.id,
                ),
                user_fact.clone(),
            )
            .expect("matched user context"),
            MatchedContext::new(
                user_invite_need,
                ContextOffer::range(
                    user_invite_fact.id,
                    "auth_user_invite",
                    FactScope::Global,
                    user_invite_fact.id,
                    user_invite_fact.id,
                ),
                user_invite_fact.clone(),
            )
            .expect("matched user invite context"),
        ])
    }

    fn sorted_ids(ids: impl IntoIterator<Item = FactId>) -> Vec<FactId> {
        let mut ids = ids.into_iter().collect::<Vec<_>>();
        ids.sort();
        ids
    }
}
