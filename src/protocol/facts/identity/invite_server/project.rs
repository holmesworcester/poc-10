//! Poc-10 invite-server projector.
//!
//! POLICY. An invite_server grant is admitted iff:
//!   1. STRUCTURAL. The fact is global, signed, contains an invite_server
//!      payload, and all selector fields are non-zero.
//!   2. AUTHORITY. Bootstrap grants are signed directly by the workspace root;
//!      delegated grants are signed by an endpoint_shared fact whose user owns
//!      the named admin grant in the same workspace.
//!   3. MATERIALIZE. Once the authority path validates, write the invite_server
//!      row, publish exact/key offers, and mark the fact shareable.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::invite_server::fact::InviteServerFact;
use crate::protocol::facts::identity::{admin, endpoint_shared, workspace};
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::rows::invite_server_row;

#[derive(Debug, Clone, Default)]
pub struct InviteServerProjector;

impl InviteServerProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteServerProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for InviteServerProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: identity::signed_fact::SignedPayload<InviteServerFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("invite_server fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let invite_server = signed.payload;
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_fact_id == [0; 32] {
            return Err("invite_server fact has empty authority_fact_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        if invite_server.authority_fact_id == invite_server.workspace_id {
            project_workspace_signed(fact, &invite_server, &envelope, context)
        } else {
            project_endpoint_signed(fact, &invite_server, &envelope, context)
        }
    }
}

fn project_workspace_signed(
    fact: &Fact,
    invite: &InviteServerFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceSignedNeeds::new(fact.id, invite);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if envelope.signer_id != invite.workspace_id {
        return Err(
            "bootstrap invite_server must use workspace as signer and authority".to_string(),
        );
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("invite_server workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "invite_server authority is not a workspace fact".to_string())?;
    if workspace.public_key != envelope.signer_public_key {
        return Err(
            "signed invite_server signer key does not match workspace public key".to_string(),
        );
    }

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &InviteServerFact,
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
        return Err("invite_server signer endpoint context payload id mismatch".to_string());
    }
    let endpoint_envelope = identity::signed_fact::decode_envelope(endpoint_fact.body())
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err("invite_server signer must be workspace or endpoint_shared".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(&endpoint_envelope.payload)
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != envelope.signer_public_key {
        return Err(
            "signed invite_server signer key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("invite_server signer endpoint belongs to a different workspace".to_string());
    }

    if admin_fact.id != invite.authority_fact_id {
        return Err("invite_server admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "invite_server authority must be an admin event".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("invite_server signer user does not match admin authority user".to_string());
    }

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

struct WorkspaceSignedNeeds {
    workspace: ContextNeed,
}

impl WorkspaceSignedNeeds {
    fn new(owner: FactId, invite: &InviteServerFact) -> Self {
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
    fn new(owner: FactId, invite: &InviteServerFact, signer_id: FactId) -> Self {
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
    invite: &InviteServerFact,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    Ok(output
        .offer(matchers::invite_server_offer(fact.id))
        .offer(matchers::invite_server_key_offer(
            fact.id,
            invite.workspace_id,
            invite.public_key,
        ))
        .intent(AtomicIntent::PutRow(invite_server_row(fact.id, invite)?).into_intent())
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
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::identity;
    use topo::protocol::facts::identity::invite_server::fact::InviteServerFact;
    use topo::protocol::facts::identity::invite_server::{layout, project, rows};
    use topo::protocol::facts::identity::workspace::{
        fact::WorkspaceFact, layout as workspace_layout,
    };
    use topo::protocol::matchers as identity_context;

    const WORKSPACE_PRIVATE_KEY: [u8; 32] = [9; 32];

    fn sample_fact() -> InviteServerFact {
        InviteServerFact {
            created_at_ms: 9,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [2; 32],
        }
    }

    #[test]
    fn invite_server_projector_materializes_row_through_atomic_intent() {
        let invite_server = sample_fact();
        let fact = signed_invite_server_fact(
            &invite_server,
            invite_server.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );
        let workspace_fact = workspace_fact(invite_server.workspace_id, WORKSPACE_PRIVATE_KEY);
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

        let output = project::InviteServerProjector::new()
            .project(&fact, &context)
            .expect("project invite_server");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 2);
        let row_intent = output
            .intents
            .iter()
            .find_map(|intent| AtomicIntent::from_intent(intent, &[rows::INVITE_SERVER_ROWS]).ok())
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_invite_server_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [2; 32]);
        assert_eq!(row.invite_server_id, fact.id);
        assert_eq!(row.created_at_ms, 9);
        assert_eq!(row.public_key, [1; 32]);
        assert_eq!(row.authority_fact_id, [2; 32]);
    }

    #[test]
    fn invite_server_projector_waits_for_workspace_authority() {
        let invite_server = sample_fact();
        let fact = signed_invite_server_fact(
            &invite_server,
            invite_server.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );

        let output = project::InviteServerProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::workspace_role());
        assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
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

    fn signed_invite_server_fact(
        invite_server: &InviteServerFact,
        signer_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Fact {
        let payload = layout::encode_fact(invite_server).expect("encode invite_server");
        let bytes =
            identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
                .expect("sign invite_server");
        Fact::new(FactScope::Global, invite_server.created_at_ms, bytes)
    }

    #[test]
    fn invite_server_projector_rejects_empty_authority() {
        let mut invite_server = sample_fact();
        invite_server.authority_fact_id = [0; 32];
        let fact = signed_invite_server_fact(&invite_server, [2; 32], WORKSPACE_PRIVATE_KEY);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::InviteServerProjector::new(),
                &[],
                &store,
                &[rows::INVITE_SERVER_ROWS],
                10,
            )
            .expect_err("empty authority must fail");
        assert!(err.contains("authority"), "{err}");
    }

    #[test]
    fn invite_server_projector_rejects_unsigned_fact() {
        let invite_server = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            invite_server.created_at_ms,
            layout::encode_fact(&invite_server).expect("encode invite_server"),
        );

        let err = project::InviteServerProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("unsigned invite_server must fail");

        assert_eq!(err, "invite_server fact must be signed");
    }
}
