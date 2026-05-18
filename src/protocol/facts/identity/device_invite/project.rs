//! Poc-10 device-invite projector.
//!
//! POLICY. A device_invite is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains a device_invite,
//!      and all selector fields are non-zero.
//!   2. AUTHORITY. The invite follows one of two named authority paths:
//!      user-signed invites require workspace, user, and user_invite context;
//!      endpoint-signed invites require workspace and endpoint_shared context.
//!   3. MATERIALIZE. Once the path validates, write the row, publish exact/key
//!      offers, and mark the fact shareable with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::device_invite::fact::DeviceInviteFact;
use crate::protocol::facts::identity::{endpoint_shared, user, user_invite, workspace};
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::layout;
use super::rows::device_invite_row;

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
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        let envelope = identity::signed_fact::decode_envelope(fact.body())
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
            return Err("signed fact does not contain a device_invite".to_string());
        }
        let device_invite = layout::decode_fact(&envelope.payload)?;
        if device_invite.workspace_id == [0; 32] {
            return Err("device_invite fact has empty workspace_id".to_string());
        }
        if device_invite.user_authority_fact_id == [0; 32] {
            return Err("device_invite fact has empty user_authority_fact_id".to_string());
        }
        if device_invite.public_key == [0; 32] {
            return Err("device_invite fact has empty public_key".to_string());
        }

        // 2. Authority.
        //
        // `user_invite_fact_id` is the authority-chain discriminator:
        // Some(id) means the device invite must be signed by the user fact
        // authorized by that user_invite; None means it must be signed by an
        // already-trusted endpoint_shared fact for the same user/workspace.
        match device_invite.user_invite_fact_id {
            Some(user_invite_fact_id) => project_user_signed(
                fact,
                &device_invite,
                &envelope,
                user_invite_fact_id,
                context,
            ),
            None => project_endpoint_signed(fact, &device_invite, &envelope, context),
        }
    }
}

fn project_user_signed(
    fact: &Fact,
    invite: &DeviceInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    user_invite_fact_id: FactId,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = UserSignedNeeds::new(fact.id, invite, user_invite_fact_id);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(user_fact) = context.payload_for(&needs.user) else {
        return Ok(needs.output());
    };
    let Some(user_invite_fact) = context.payload_for(&needs.user_invite) else {
        return Ok(needs.output());
    };

    validate_workspace_context(workspace_fact, invite.workspace_id)?;

    if envelope.signer_id != invite.user_authority_fact_id {
        return Err("user-signed device_invite authority must match signer user".to_string());
    }
    if user_fact.id != invite.user_authority_fact_id {
        return Err("device_invite user context payload id mismatch".to_string());
    }
    let user_envelope = identity::signed_fact::decode_envelope(user_fact.body())
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if user_envelope.inner_type != user::TYPE_USER {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let user = user::decode_fact_payload(&user_envelope.payload)
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
    if envelope.signer_public_key != user.public_key {
        return Err("device_invite signer public key does not match user".to_string());
    }
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }

    if user_envelope.signer_id != user_invite_fact_id {
        return Err("device_invite user_invite dependency does not match signed user".to_string());
    }
    if user_invite_fact.id != user_invite_fact_id {
        return Err("device_invite user_invite context payload id mismatch".to_string());
    }
    let invite_envelope = identity::signed_fact::decode_envelope(user_invite_fact.body())
        .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
    if invite_envelope.inner_type != user_invite::TYPE_USER_INVITE {
        return Err("device_invite user_invite dependency is not a user_invite".to_string());
    }
    let user_invite = user_invite::decode_fact_payload(&invite_envelope.payload)
        .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
    if user_invite.workspace_id != invite.workspace_id {
        return Err("device_invite user_invite belongs to a different workspace".to_string());
    }
    if user_invite.public_key != user_envelope.signer_public_key {
        return Err("device_invite user_invite key does not match user".to_string());
    }

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &DeviceInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointSignedNeeds::new(fact.id, invite, envelope.signer_id);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(signer_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };

    validate_workspace_context(workspace_fact, invite.workspace_id)?;

    if signer_fact.id != envelope.signer_id {
        return Err("device_invite endpoint_shared context payload id mismatch".to_string());
    }
    let signer_envelope = identity::signed_fact::decode_envelope(signer_fact.body())
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let signer = endpoint_shared::decode_fact_payload(&signer_envelope.payload)
        .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
    if envelope.signer_public_key != signer.signing_public_key {
        return Err(
            "device_invite signer public key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if signer.workspace_id != invite.workspace_id {
        return Err(
            "endpoint_shared-signed device_invite workspace does not match signer".to_string(),
        );
    }
    if signer.user_authority_fact_id != invite.user_authority_fact_id {
        return Err(
            "endpoint_shared-signed device_invite user authority does not match signer".to_string(),
        );
    }

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

struct UserSignedNeeds {
    workspace: ContextNeed,
    user: ContextNeed,
    user_invite: ContextNeed,
}

impl UserSignedNeeds {
    fn new(owner: FactId, invite: &DeviceInviteFact, user_invite_fact_id: FactId) -> Self {
        Self {
            workspace: matchers::exact_need(owner, matchers::workspace_role(), invite.workspace_id),
            user: matchers::exact_need(owner, matchers::user_role(), invite.user_authority_fact_id),
            user_invite: matchers::exact_need(
                owner,
                matchers::user_invite_role(),
                user_invite_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.workspace.clone())
            .need(self.user.clone())
            .need(self.user_invite.clone())
    }
}

struct EndpointSignedNeeds {
    workspace: ContextNeed,
    endpoint_shared: ContextNeed,
}

impl EndpointSignedNeeds {
    fn new(owner: FactId, invite: &DeviceInviteFact, signer_id: FactId) -> Self {
        Self {
            workspace: matchers::exact_need(owner, matchers::workspace_role(), invite.workspace_id),
            endpoint_shared: matchers::exact_need(
                owner,
                matchers::endpoint_shared_role(),
                signer_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.workspace.clone())
            .need(self.endpoint_shared.clone())
    }
}

fn validate_workspace_context(workspace_fact: &Fact, workspace_id: FactId) -> Result<(), String> {
    if workspace_fact.id != workspace_id {
        return Err("device_invite workspace context payload id mismatch".to_string());
    }
    workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;
    Ok(())
}

fn materialized_output(
    fact: &Fact,
    invite: &DeviceInviteFact,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    Ok(output
        .intent(AtomicIntent::PutRow(device_invite_row(fact.id, invite)?).into_intent())
        .offer(matchers::exact_offer(
            fact.id,
            matchers::device_invite_role(),
        ))
        .offer(matchers::scoped_key_offer(
            fact.id,
            matchers::device_invite_key_role(),
            invite.workspace_id,
            matchers::device_invite_key(invite.user_authority_fact_id, invite.public_key),
        ))
        .intent(share_fact_with_workspace_intent_for_fact(
            invite.workspace_id,
            fact,
        )))
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
    use topo::protocol::facts::identity::device_invite::fact::DeviceInviteFact;
    use topo::protocol::facts::identity::device_invite::{layout, project, rows};
    use topo::protocol::facts::identity::endpoint_shared::{
        fact::{EndpointRole, EndpointSharedFact},
        layout as endpoint_shared_layout,
    };
    use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};
    use topo::protocol::facts::identity::user_invite::{
        fact::UserInviteFact, layout as user_invite_layout,
    };
    use topo::protocol::facts::identity::workspace::{
        fact::WorkspaceFact, layout as workspace_layout,
    };
    use topo::protocol::matchers as identity_context;

    const WORKSPACE_ID: [u8; 32] = [1; 32];
    const USER_INVITE_PRIVATE_KEY: [u8; 32] = [8; 32];
    const USER_PRIVATE_KEY: [u8; 32] = [9; 32];
    const DEVICE_INVITE_PRIVATE_KEY: [u8; 32] = [10; 32];
    const ENDPOINT_SIGNER_PRIVATE_KEY: [u8; 32] = [11; 32];

    struct UserSignedScenario {
        invite: DeviceInviteFact,
        fact: Fact,
        user_fact: Fact,
        user_invite_fact: Fact,
        workspace_fact: Fact,
    }

    fn user_signed_scenario() -> UserSignedScenario {
        let workspace_fact = workspace_fact(WORKSPACE_ID);
        let user_invite = UserInviteFact {
            created_at_ms: 1,
            public_key: crypto::ed25519_public_key(&USER_INVITE_PRIVATE_KEY),
            workspace_id: WORKSPACE_ID,
            authority_fact_id: WORKSPACE_ID,
        };
        let user_invite_fact = signed_fact_with_payload(
            WORKSPACE_ID,
            USER_INVITE_PRIVATE_KEY,
            user_invite_layout::encode_fact(&user_invite).expect("encode user_invite"),
            1,
        );
        let user = UserFact {
            created_at_ms: 2,
            workspace_id: WORKSPACE_ID,
            public_key: crypto::ed25519_public_key(&USER_PRIVATE_KEY),
            username: "alice".to_string(),
        };
        let user_fact = signed_fact_with_payload(
            user_invite_fact.id,
            USER_INVITE_PRIVATE_KEY,
            user_layout::encode_fact(&user).expect("encode user"),
            2,
        );
        let invite = DeviceInviteFact {
            created_at_ms: 11,
            workspace_id: WORKSPACE_ID,
            user_authority_fact_id: user_fact.id,
            user_invite_fact_id: Some(user_invite_fact.id),
            public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
        };
        let fact = signed_fact_with_payload(
            user_fact.id,
            USER_PRIVATE_KEY,
            layout::encode_fact(&invite).expect("encode device_invite"),
            invite.created_at_ms,
        );
        UserSignedScenario {
            invite,
            fact,
            user_fact,
            user_invite_fact,
            workspace_fact,
        }
    }

    #[test]
    fn device_invite_projector_materializes_row_through_atomic_intent() {
        let scenario = user_signed_scenario();
        let context = user_signed_context(&scenario);

        let output = project::DeviceInviteProjector::new()
            .project(&scenario.fact, &context)
            .expect("project device_invite");
        assert_eq!(output.needs.len(), 3);
        assert_eq!(output.intents.len(), 2);
        let row_intent = output
            .intents
            .iter()
            .find_map(|intent| AtomicIntent::from_intent(intent, &[rows::DEVICE_INVITE_ROWS]).ok())
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_device_invite_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, WORKSPACE_ID);
        assert_eq!(row.device_invite_id, scenario.fact.id);
        assert_eq!(row.created_at_ms, 11);
        assert_eq!(row.user_authority_fact_id, scenario.user_fact.id);
        assert_eq!(row.user_invite_fact_id, Some(scenario.user_invite_fact.id));
        assert_eq!(row.public_key, scenario.invite.public_key);
    }

    #[test]
    fn device_invite_projector_waits_for_user_authority() {
        let scenario = user_signed_scenario();

        let output = project::DeviceInviteProjector::new()
            .project(&scenario.fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 3);
        assert!(output.intents.is_empty());
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == identity_context::user_role()
                && need.selector.as_bytes() == &scenario.user_fact.id));
    }

    #[test]
    fn device_invite_endpoint_shared_signed_form_waits_for_endpoint_context() {
        let (invite, fact, _endpoint_fact, workspace_fact) = endpoint_signed_scenario();
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: identity_context::exact_need(
                fact.id,
                identity_context::workspace_role(),
                invite.workspace_id,
            ),
            offer: identity_context::workspace_offer(workspace_fact.id),
            payload: workspace_fact,
        }]);

        let output = project::DeviceInviteProjector::new()
            .project(&fact, &context)
            .expect("endpoint signed form waits");

        assert_eq!(output.needs.len(), 2);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == identity_context::endpoint_shared_role()));
    }

    #[test]
    fn device_invite_endpoint_shared_signed_form_should_project_after_endpoint_context_matches() {
        let (_invite, fact, endpoint_fact, workspace_fact) = endpoint_signed_scenario();
        let context = ProjectionContext::from_matches(vec![
            MatchedContext {
                need: identity_context::exact_need(
                    fact.id,
                    identity_context::workspace_role(),
                    WORKSPACE_ID,
                ),
                offer: identity_context::workspace_offer(workspace_fact.id),
                payload: workspace_fact,
            },
            MatchedContext {
                need: identity_context::exact_need(
                    fact.id,
                    identity_context::endpoint_shared_role(),
                    endpoint_fact.id,
                ),
                offer: identity_context::exact_offer(
                    endpoint_fact.id,
                    identity_context::endpoint_shared_role(),
                ),
                payload: endpoint_fact,
            },
        ]);

        let output = project::DeviceInviteProjector::new()
            .project(&fact, &context)
            .expect("signed endpoint_shared context should authorize device_invite");

        assert_eq!(output.needs.len(), 2);
        assert_eq!(output.intents.len(), 2);
    }

    #[test]
    fn device_invite_projector_rejects_empty_user_authority() {
        let scenario = user_signed_scenario();
        let mut device_invite = scenario.invite;
        device_invite.user_authority_fact_id = [0; 32];
        let fact = signed_fact_with_payload(
            scenario.user_fact.id,
            USER_PRIVATE_KEY,
            layout::encode_fact(&device_invite).expect("encode"),
            1,
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::DeviceInviteProjector::new(),
                &[],
                &store,
                &[rows::DEVICE_INVITE_ROWS],
                10,
            )
            .expect_err("empty user_authority must fail");
        assert!(err.contains("user_authority"), "{err}");
    }

    fn user_signed_context(scenario: &UserSignedScenario) -> ProjectionContext {
        ProjectionContext::from_matches(vec![
            MatchedContext {
                need: identity_context::exact_need(
                    scenario.fact.id,
                    identity_context::workspace_role(),
                    scenario.workspace_fact.id,
                ),
                offer: identity_context::workspace_offer(scenario.workspace_fact.id),
                payload: scenario.workspace_fact.clone(),
            },
            MatchedContext {
                need: identity_context::exact_need(
                    scenario.fact.id,
                    identity_context::user_role(),
                    scenario.user_fact.id,
                ),
                offer: identity_context::exact_offer(
                    scenario.user_fact.id,
                    identity_context::user_role(),
                ),
                payload: scenario.user_fact.clone(),
            },
            MatchedContext {
                need: identity_context::exact_need(
                    scenario.fact.id,
                    identity_context::user_invite_role(),
                    scenario.user_invite_fact.id,
                ),
                offer: identity_context::user_invite_offer(scenario.user_invite_fact.id),
                payload: scenario.user_invite_fact.clone(),
            },
        ])
    }

    fn endpoint_signed_scenario() -> (DeviceInviteFact, Fact, Fact, Fact) {
        let workspace_fact = workspace_fact(WORKSPACE_ID);
        let endpoint = EndpointSharedFact {
            created_at_ms: 4,
            workspace_id: WORKSPACE_ID,
            user_authority_fact_id: [50; 32],
            endpoint_id: [3; 32],
            signing_public_key: crypto::ed25519_public_key(&ENDPOINT_SIGNER_PRIVATE_KEY),
            endpoint_role: EndpointRole::Device,
            device_name: "laptop".to_string(),
        };
        let endpoint_fact = signed_fact_with_payload(
            [44; 32],
            [45; 32],
            endpoint_shared_layout::encode_fact(&endpoint).expect("encode endpoint_shared"),
            4,
        );
        let invite = DeviceInviteFact {
            created_at_ms: 11,
            workspace_id: WORKSPACE_ID,
            user_authority_fact_id: endpoint.user_authority_fact_id,
            user_invite_fact_id: None,
            public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
        };
        let fact = signed_fact_with_payload(
            endpoint_fact.id,
            ENDPOINT_SIGNER_PRIVATE_KEY,
            layout::encode_fact(&invite).expect("encode device_invite"),
            11,
        );
        (invite, fact, endpoint_fact, workspace_fact)
    }

    fn workspace_fact(workspace_id: [u8; 32]) -> Fact {
        Fact {
            id: workspace_id,
            scope: FactScope::Global,
            timestamp: 1,
            bytes: workspace_layout::encode_fact(&WorkspaceFact {
                created_at_ms: 1,
                public_key: [7; 32],
                name: "Workspace".to_string(),
            })
            .expect("encode workspace"),
        }
    }

    fn signed_fact_with_payload(
        signer_id: [u8; 32],
        private_key: [u8; 32],
        payload: Vec<u8>,
        timestamp: u64,
    ) -> Fact {
        let bytes =
            identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
                .expect("sign fact");
        Fact::new(FactScope::Global, timestamp, bytes)
    }
}
