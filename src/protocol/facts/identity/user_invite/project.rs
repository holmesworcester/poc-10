//! Poc-10 user-invite projector.
//!
//! POLICY. A user_invite is admitted iff:
//!   1. STRUCTURAL. The fact is global, signed, contains a user_invite payload,
//!      and all selector fields are non-zero.
//!   2. AUTHORITY. Bootstrap invites are signed directly by the workspace root;
//!      delegated invites are signed by an endpoint_shared fact whose user owns
//!      the named admin grant in the same workspace.
//!   3. MATERIALIZE. Once the authority path validates, write the user_invite
//!      row, publish exact/key offers, and mark the fact shareable.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user_invite::fact::UserInviteFact;
use crate::protocol::facts::identity::{admin, endpoint_shared, workspace};
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::rows::user_invite_row;

#[derive(Debug, Clone, Default)]
pub struct UserInviteProjector;

impl UserInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for UserInviteProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: identity::signed_fact::SignedPayload<UserInviteFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user_invite fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let user_invite = signed.payload;
        if user_invite.workspace_id == [0; 32] {
            return Err("user_invite fact has empty workspace_id".to_string());
        }
        if user_invite.authority_fact_id == [0; 32] {
            return Err("user_invite fact has empty authority_fact_id".to_string());
        }
        if user_invite.public_key == [0; 32] {
            return Err("user_invite fact has empty public_key".to_string());
        }

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        if user_invite.authority_fact_id == user_invite.workspace_id {
            project_workspace_signed(fact, &user_invite, &envelope, context)
        } else {
            project_endpoint_signed(fact, &user_invite, &envelope, context)
        }
    }
}

fn project_workspace_signed(
    fact: &Fact,
    invite: &UserInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceSignedNeeds::new(fact.id, invite);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if envelope.signer_id != invite.workspace_id {
        return Err("bootstrap user_invite must use workspace as signer and authority".to_string());
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("user_invite workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "user_invite authority is not a workspace fact".to_string())?;
    if workspace.public_key != envelope.signer_public_key {
        return Err(
            "signed user_invite signer key does not match workspace public key".to_string(),
        );
    }

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &UserInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointAdminNeeds::new(fact.id, invite, envelope.signer_id);
    let Some(endpoint_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };
    let Some(admin_fact) = context.payload_for(&needs.admin) else {
        return Ok(needs.output());
    };

    if endpoint_fact.id != envelope.signer_id {
        return Err("user_invite signer endpoint context payload id mismatch".to_string());
    }
    let endpoint_envelope = identity::signed_fact::decode_envelope(endpoint_fact.body())
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err("user_invite signer must be workspace or endpoint_shared".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(&endpoint_envelope.payload)
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != envelope.signer_public_key {
        return Err(
            "signed user_invite signer key does not match endpoint_shared signing key".to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("user_invite signer endpoint belongs to a different workspace".to_string());
    }

    if admin_fact.id != invite.authority_fact_id {
        return Err("user_invite admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "user_invite authority must be an admin event".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("user_invite admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("user_invite signer user does not match admin authority user".to_string());
    }

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

struct WorkspaceSignedNeeds {
    workspace: ContextNeed,
}

impl WorkspaceSignedNeeds {
    fn new(owner: FactId, invite: &UserInviteFact) -> Self {
        Self {
            workspace: matchers::exact_need(owner, matchers::workspace_role(), invite.workspace_id),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new().need(self.workspace.clone())
    }
}

struct EndpointAdminNeeds {
    endpoint_shared: ContextNeed,
    admin: ContextNeed,
}

impl EndpointAdminNeeds {
    fn new(owner: FactId, invite: &UserInviteFact, signer_id: FactId) -> Self {
        Self {
            endpoint_shared: matchers::exact_need(
                owner,
                matchers::endpoint_shared_role(),
                signer_id,
            ),
            admin: matchers::exact_need(owner, matchers::admin_role(), invite.authority_fact_id),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.endpoint_shared.clone())
            .need(self.admin.clone())
    }
}

fn materialized_output(
    fact: &Fact,
    invite: &UserInviteFact,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    Ok(output
        .offer(matchers::user_invite_offer(fact.id))
        .offer(matchers::user_invite_key_offer(
            fact.id,
            invite.workspace_id,
            invite.public_key,
        ))
        .intent(AtomicIntent::PutRow(user_invite_row(fact.id, invite)?).into_intent())
        .intent(share_fact_with_workspace_intent_for_fact(
            invite.workspace_id,
            fact,
        )))
}

fn decode_admin_payload(
    fact: &Fact,
) -> Result<crate::protocol::facts::identity::admin::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(admin::TYPE_ADMIN) => admin::decode_fact_payload(fact.body()),
        Some(identity::signed_fact::TYPE_SIGNED_FACT) => {
            let envelope = identity::signed_fact::decode_envelope(fact.body())?;
            if envelope.inner_type != admin::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            admin::decode_fact_payload(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::matchers::ContextMatcher;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::identity;
    use topo::protocol::facts::identity::user_invite::fact::UserInviteFact;
    use topo::protocol::facts::identity::user_invite::{layout, project, rows};
    use topo::protocol::facts::identity::workspace::{
        fact::WorkspaceFact, layout as workspace_layout,
    };
    use topo::protocol::facts::identity::workspace::{
        project as workspace_project, rows as workspace_rows,
    };
    use topo::protocol::matchers as identity_context;
    use topo::protocol::matchers::ExactSelectorMatcher;

    const WORKSPACE_PRIVATE_KEY: [u8; 32] = [9; 32];

    fn sample_fact() -> UserInviteFact {
        UserInviteFact {
            created_at_ms: 5,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [2; 32],
        }
    }

    #[test]
    fn user_invite_projector_materializes_row_through_atomic_intent() {
        let user_invite = sample_fact();
        let fact = signed_user_invite_fact(
            &user_invite,
            user_invite.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );
        let workspace_fact = workspace_fact(user_invite.workspace_id, WORKSPACE_PRIVATE_KEY);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: identity_context::exact_need(
                fact.id,
                identity_context::workspace_role(),
                workspace_fact.id,
            ),
            offer: identity_context::exact_offer(
                workspace_fact.id,
                identity_context::workspace_role(),
            ),
            payload: workspace_fact,
        }]);

        let output = project::UserInviteProjector::new()
            .project(&fact, &context)
            .expect("project user_invite");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 2);
        let row_intent = output
            .intents
            .iter()
            .find_map(|intent| AtomicIntent::from_intent(intent, &[rows::USER_INVITE_ROWS]).ok())
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_user_invite_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [2; 32]);
        assert_eq!(row.user_invite_id, fact.id);
        assert_eq!(row.created_at_ms, 5);
        assert_eq!(row.public_key, [1; 32]);
        assert_eq!(row.authority_fact_id, [2; 32]);
    }

    #[test]
    fn user_invite_projector_waits_for_workspace_authority() {
        let user_invite = sample_fact();
        let fact = signed_user_invite_fact(
            &user_invite,
            user_invite.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );

        let output = project::UserInviteProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::workspace_role());
        assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
    }

    #[test]
    fn user_invite_projector_wakes_when_workspace_authority_offer_arrives() {
        let user_invite = sample_fact();
        let fact = signed_user_invite_fact(
            &user_invite,
            user_invite.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );
        let workspace_fact = workspace_fact(user_invite.workspace_id, WORKSPACE_PRIVATE_KEY);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let matcher = ExactSelectorMatcher::new(identity_context::workspace_role());
        let matchers = [&matcher as &dyn ContextMatcher];
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let waiting = bus
            .drain_applying_atomic_rows(
                &project::UserInviteProjector::new(),
                &matchers,
                &store,
                &[rows::USER_INVITE_ROWS],
                10,
            )
            .expect("user invite waits");
        assert_eq!(waiting.projections, 1);
        assert_eq!(waiting.intents, 0);

        assert!(bus.submit_fact(workspace_fact));
        let authority = bus
            .drain_applying_atomic_rows(
                &workspace_project::WorkspaceProjector::new(),
                &matchers,
                &store,
                &[workspace_rows::WORKSPACE_ROWS],
                1,
            )
            .expect("workspace projects");
        assert_eq!(authority.wakes, 1);

        let projected = bus
            .drain_applying_atomic_rows(
                &project::UserInviteProjector::new(),
                &matchers,
                &store,
                &[rows::USER_INVITE_ROWS],
                10,
            )
            .expect("user invite reprojects");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 2);
    }

    fn workspace_fact(workspace_id: [u8; 32], private_key: [u8; 32]) -> Fact {
        Fact {
            id: workspace_id,
            scope: FactScope::Global,
            timestamp: 1,
            bytes: workspace_layout::encode_fact(&WorkspaceFact {
                created_at_ms: 1,
                public_key: crypto::ed25519_public_key(&private_key),
                name: "Workspace".to_string(),
            })
            .expect("encode workspace"),
        }
    }

    fn signed_user_invite_fact(
        invite: &UserInviteFact,
        signer_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Fact {
        let payload = layout::encode_fact(invite).expect("encode user_invite");
        let bytes =
            identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
                .expect("sign user_invite");
        Fact::new(FactScope::Global, invite.created_at_ms, bytes)
    }

    #[test]
    fn user_invite_projector_rejects_empty_authority() {
        let mut user_invite = sample_fact();
        user_invite.authority_fact_id = [0; 32];
        let fact = signed_user_invite_fact(&user_invite, [2; 32], WORKSPACE_PRIVATE_KEY);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::UserInviteProjector::new(),
                &[],
                &store,
                &[rows::USER_INVITE_ROWS],
                10,
            )
            .expect_err("empty authority must fail");
        assert!(err.contains("authority"), "{err}");
    }

    #[test]
    fn user_invite_projector_rejects_unsigned_fact() {
        let user_invite = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            user_invite.created_at_ms,
            layout::encode_fact(&user_invite).expect("encode user_invite"),
        );

        let err = project::UserInviteProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("unsigned user_invite must fail");

        assert_eq!(err, "user_invite fact must be signed");
    }
}
