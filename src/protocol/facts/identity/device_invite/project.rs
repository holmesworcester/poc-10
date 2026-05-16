//! Poc-10 device-invite projector.
//!
//! Device invites are signed either by the invited user or by an existing
//! endpoint_shared signer for that user. Projection validates the envelope
//! signer against the matching authority context before writing the invite.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::endpoint_shared::layout as endpoint_shared_layout;
use crate::protocol::facts::identity::user::layout as user_layout;
use crate::protocol::facts::identity::user_invite::layout as user_invite_layout;
use crate::protocol::facts::identity::workspace::layout as workspace_layout;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

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
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        let envelope = identity::signed_fact::layout::decode_signed_fact(&fact.bytes)
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
        let needs = authority_needs(fact.id, &device_invite, envelope.signer_id);
        let output = output_with_needs(&needs);
        if !has_all_context(&needs, context) {
            return Ok(output);
        }
        validate_authority(&needs, &device_invite, &envelope, context)?;
        Ok(output
            .intent(AtomicIntent::PutRow(device_invite_row(fact.id, &device_invite)?).into_intent())
            .offer(crate::protocol::matchers::exact_offer(
                fact.id,
                crate::protocol::matchers::device_invite_role(),
            ))
            .offer(crate::protocol::matchers::scoped_key_offer(
                fact.id,
                crate::protocol::matchers::device_invite_key_role(),
                device_invite.workspace_id,
                crate::protocol::matchers::device_invite_key(
                    device_invite.user_authority_fact_id,
                    device_invite.public_key,
                ),
            ))
            .intent(share_fact_with_workspace_intent_for_fact(
                device_invite.workspace_id,
                fact,
            )))
    }
}

fn authority_needs(
    owner: [u8; 32],
    invite: &super::fact::DeviceInviteFact,
    signer_id: [u8; 32],
) -> Vec<crate::core::context::ContextNeed> {
    let workspace_need = crate::protocol::matchers::exact_need(
        owner,
        crate::protocol::matchers::workspace_role(),
        invite.workspace_id,
    );
    if let Some(user_invite_fact_id) = invite.user_invite_fact_id {
        vec![
            workspace_need,
            crate::protocol::matchers::exact_need(
                owner,
                crate::protocol::matchers::user_role(),
                invite.user_authority_fact_id,
            ),
            crate::protocol::matchers::exact_need(
                owner,
                crate::protocol::matchers::user_invite_role(),
                user_invite_fact_id,
            ),
        ]
    } else {
        vec![
            workspace_need,
            crate::protocol::matchers::exact_need(
                owner,
                crate::protocol::matchers::endpoint_shared_role(),
                signer_id,
            ),
        ]
    }
}

fn output_with_needs(needs: &[crate::core::context::ContextNeed]) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for need in needs {
        output = output.need(need.clone());
    }
    output
}

fn has_all_context(
    needs: &[crate::core::context::ContextNeed],
    context: &ProjectionContext,
) -> bool {
    needs.iter().all(|need| context.payload_for(need).is_some())
}

fn validate_authority(
    needs: &[crate::core::context::ContextNeed],
    invite: &super::fact::DeviceInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    let workspace_fact = context
        .payload_for(&needs[0])
        .expect("checked by has_all_context");
    if workspace_fact.id != invite.workspace_id {
        return Err("device_invite workspace context payload id mismatch".to_string());
    }
    workspace_layout::decode_fact(&workspace_fact.bytes)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;

    if invite.user_invite_fact_id.is_none() {
        return validate_endpoint_shared_authority(&needs[1], invite, envelope, context);
    }

    if envelope.signer_id != invite.user_authority_fact_id {
        return Err("user-signed device_invite authority must match signer user".to_string());
    }
    let user_need = &needs[1];
    let user_fact = context
        .payload_for(user_need)
        .expect("checked by has_all_context");
    if user_fact.id != invite.user_authority_fact_id {
        return Err("device_invite user context payload id mismatch".to_string());
    }
    let user_envelope = identity::signed_fact::layout::decode_signed_fact(&user_fact.bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if user_envelope.inner_type != user_layout::TYPE_USER {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let user = user_layout::decode_fact(&user_envelope.payload)
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
    if envelope.signer_public_key != user.public_key {
        return Err("device_invite signer public key does not match user".to_string());
    }
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }

    if let Some(user_invite_fact_id) = invite.user_invite_fact_id {
        if user_envelope.signer_id != user_invite_fact_id {
            return Err(
                "device_invite user_invite dependency does not match signed user".to_string(),
            );
        }
        let invite_need = &needs[2];
        let invite_fact = context
            .payload_for(invite_need)
            .expect("checked by has_all_context");
        if invite_fact.id != user_invite_fact_id {
            return Err("device_invite user_invite context payload id mismatch".to_string());
        }
        let invite_envelope = identity::signed_fact::layout::decode_signed_fact(&invite_fact.bytes)
            .map_err(|_| {
                "device_invite user_invite context is not a user_invite fact".to_string()
            })?;
        if invite_envelope.inner_type != user_invite_layout::TYPE_USER_INVITE {
            return Err("device_invite user_invite dependency is not a user_invite".to_string());
        }
        let user_invite =
            user_invite_layout::decode_fact(&invite_envelope.payload).map_err(|_| {
                "device_invite user_invite context is not a user_invite fact".to_string()
            })?;
        if user_invite.workspace_id != invite.workspace_id {
            return Err("device_invite user_invite belongs to a different workspace".to_string());
        }
        if user_invite.public_key != user_envelope.signer_public_key {
            return Err("device_invite user_invite key does not match user".to_string());
        }
    }
    Ok(())
}

fn validate_endpoint_shared_authority(
    need: &crate::core::context::ContextNeed,
    invite: &super::fact::DeviceInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    let signer_fact = context
        .payload_for(need)
        .expect("checked by has_all_context");
    if signer_fact.id != envelope.signer_id {
        return Err("device_invite endpoint_shared context payload id mismatch".to_string());
    }
    let signer_envelope = identity::signed_fact::layout::decode_signed_fact(&signer_fact.bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let signer = endpoint_shared_layout::decode_fact(&signer_envelope.payload)
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
    Ok(())
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::FACTS_SCHEMA_SOURCE;
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
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
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
