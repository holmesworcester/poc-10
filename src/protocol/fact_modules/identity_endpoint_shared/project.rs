//! Poc-10 endpoint-shared projector.
//!
//! Endpoint-shared facts are signed by the device invite or invite-server grant
//! that authorizes one endpoint in one workspace. Projection re-checks the
//! signer id, signer public key, workspace, user authority, and endpoint role
//! before materializing the shared endpoint row.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::fact_modules::identity_device_invite::layout as device_invite_layout;
use crate::protocol::fact_modules::identity_invite_server::layout as invite_server_layout;
use crate::protocol::fact_modules::signed_fact;

use super::fact::EndpointRole;
use super::layout;
use super::rows::endpoint_shared_row;

#[derive(Debug, Clone, Default)]
pub struct EndpointSharedProjector;

impl EndpointSharedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointSharedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("endpoint shared fact must have global scope".to_string());
        }
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "endpoint_shared fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_ENDPOINT_SHARED {
            return Err("signed fact does not contain an endpoint_shared".to_string());
        }
        let event = layout::decode_fact(&envelope.payload)?;
        if event.endpoint_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared endpoint_id cannot be empty".to_string());
        }
        if event.signing_public_key.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared signing_public_key cannot be empty".to_string());
        }
        if event.workspace_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared workspace_id cannot be empty".to_string());
        }
        if event.device_name.as_bytes().contains(&0) {
            return Err("endpoint device name cannot contain NUL".to_string());
        }
        let authority_need = authority_need(fact, &event, envelope.signer_id);
        if !has_valid_authority(&authority_need, &event, &envelope, context)? {
            return Ok(ProjectionOutput::new().need(authority_need));
        }
        Ok(ProjectionOutput::new()
            .need(authority_need)
            .offer(crate::protocol::matchers::signer_offer(
                fact.id,
                crate::protocol::matchers::workspace_scope(event.workspace_id),
                event.endpoint_id,
            ))
            .offer(crate::protocol::matchers::exact_offer(
                fact.id,
                crate::protocol::matchers::endpoint_shared_role(),
            ))
            .intent(AtomicIntent::PutRow(endpoint_shared_row(fact.id, &event)?).into_intent()))
    }
}

fn authority_need(
    fact: &Fact,
    event: &super::fact::EndpointSharedFact,
    signer_id: [u8; 32],
) -> ContextNeed {
    match event.endpoint_role {
        EndpointRole::InviteServer => crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::invite_server_role(),
            signer_id,
        ),
        EndpointRole::Device => crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::device_invite_role(),
            signer_id,
        ),
    }
}

fn has_valid_authority(
    need: &ContextNeed,
    event: &super::fact::EndpointSharedFact,
    envelope: &signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<bool, String> {
    let Some(authority_fact) = context.payload_for(need) else {
        return Ok(false);
    };
    if authority_fact.id != envelope.signer_id {
        return Err("endpoint_shared authority context payload id mismatch".to_string());
    }
    if authority_fact.scope != FactScope::Global {
        return Err("endpoint_shared authority must have global scope".to_string());
    }
    if event.endpoint_role == EndpointRole::Device {
        let invite_envelope = signed_fact::layout::decode_signed_fact(&authority_fact.bytes)
            .map_err(|_| {
                "endpoint_shared dependency is not a signed endpoint invite".to_string()
            })?;
        if invite_envelope.inner_type != device_invite_layout::TYPE_DEVICE_INVITE {
            return Err("endpoint_shared dependency is not a signed endpoint invite".to_string());
        }
        let invite = device_invite_layout::decode_fact(&invite_envelope.payload).map_err(|_| {
            "endpoint_shared dependency is not a signed endpoint invite".to_string()
        })?;
        if invite.public_key != envelope.signer_public_key {
            return Err(
                "endpoint_shared signer public key does not match device_invite".to_string(),
            );
        }
        if invite.workspace_id != event.workspace_id {
            return Err("endpoint_shared workspace does not match device_invite".to_string());
        }
        if invite.user_authority_event_id != event.user_authority_event_id {
            return Err("endpoint_shared user authority does not match device_invite".to_string());
        }
        return Ok(true);
    }

    let invite_envelope = signed_fact::layout::decode_signed_fact(&authority_fact.bytes)
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite_envelope.inner_type != invite_server_layout::TYPE_INVITE_SERVER {
        return Err("endpoint_shared dependency is not a signed endpoint invite".to_string());
    }
    let invite_server = invite_server_layout::decode_fact(&invite_envelope.payload)
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite_server.workspace_id != event.workspace_id {
        return Err("endpoint_shared workspace does not match invite_server".to_string());
    }
    if invite_server.public_key != envelope.signer_public_key {
        return Err("endpoint_shared signer public key does not match invite_server".to_string());
    }
    if envelope.signer_id != event.user_authority_event_id {
        return Err("endpoint_shared user authority does not match invite_server".to_string());
    }
    Ok(true)
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::FACT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::fact_modules::identity_endpoint_shared::fact::{
        EndpointRole, EndpointSharedFact,
    };
    use topo::protocol::fact_modules::identity_endpoint_shared::{layout, project, rows};
    use topo::protocol::fact_modules::identity_invite_server::{
        fact::InviteServerFact, layout as invite_server_layout,
    };

    use topo::protocol::fact_modules::signed_fact;

    const INVITE_SERVER_PRIVATE_KEY: [u8; 32] = [7; 32];

    fn sample_fact() -> EndpointSharedFact {
        EndpointSharedFact {
            created_at_ms: 77,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            endpoint_id: [3; 32],
            signing_public_key: [4; 32],
            endpoint_role: EndpointRole::InviteServer,
            device_name: "relay".to_string(),
        }
    }

    #[test]
    fn endpoint_shared_projector_waits_for_invite_server_authority() {
        let payload = sample_fact();
        let fact = signed_endpoint_shared_fact(
            &payload,
            payload.user_authority_event_id,
            INVITE_SERVER_PRIVATE_KEY,
        );

        let output = project::EndpointSharedProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(
            output.needs[0].role,
            crate::protocol::matchers::invite_server_role()
        );
        assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
    }

    #[test]
    fn endpoint_shared_projector_materializes_row_with_invite_server_context() {
        let (_payload, fact, invite_server_fact) = invite_server_endpoint_shared();
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: crate::protocol::matchers::exact_need(
                fact.id,
                crate::protocol::matchers::invite_server_role(),
                invite_server_fact.id,
            ),
            offer: crate::protocol::matchers::invite_server_offer(invite_server_fact.id),
            payload: invite_server_fact,
        }]);

        let output = project::EndpointSharedProjector::new()
            .project(&fact, &context)
            .expect("project endpoint shared");

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 2);
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == crate::protocol::matchers::endpoint_shared_role()));
        assert_eq!(output.intents.len(), 1);
        let row_intent =
            AtomicIntent::from_intent(&output.intents[0], &[rows::ENDPOINT_SHARED_ROWS])
                .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_endpoint_shared_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.endpoint_shared_id, fact.id);
        assert_eq!(row.created_at_ms, 77);
        assert_eq!(row.endpoint_id, [3; 32]);
        assert_eq!(row.signing_public_key, [4; 32]);
        assert_eq!(row.endpoint_role, EndpointRole::InviteServer);
        assert_eq!(row.user_authority_event_id, [2; 32]);
        assert_eq!(row.device_name, "relay");
    }

    #[test]
    fn endpoint_shared_projector_rejects_local_scope() {
        let payload = sample_fact();
        let mut fact = signed_endpoint_shared_fact(
            &payload,
            payload.user_authority_event_id,
            INVITE_SERVER_PRIVATE_KEY,
        );
        fact.scope = FactScope::Local;
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::EndpointSharedProjector::new(),
                &[],
                &store,
                &[rows::ENDPOINT_SHARED_ROWS],
                10,
            )
            .expect_err("local scope must fail");
        assert!(err.contains("global scope"), "{err}");
    }

    #[test]
    fn endpoint_shared_projector_rejects_empty_endpoint_id() {
        let mut payload = sample_fact();
        payload.endpoint_id = [0; 32];
        let fact = signed_endpoint_shared_fact(
            &payload,
            payload.user_authority_event_id,
            INVITE_SERVER_PRIVATE_KEY,
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::EndpointSharedProjector::new(),
                &[],
                &store,
                &[rows::ENDPOINT_SHARED_ROWS],
                10,
            )
            .expect_err("empty endpoint must fail");
        assert!(err.contains("endpoint_id"), "{err}");
    }

    #[test]
    fn endpoint_shared_projector_rejects_empty_signing_public_key() {
        let mut payload = sample_fact();
        payload.signing_public_key = [0; 32];
        let fact = signed_endpoint_shared_fact(
            &payload,
            payload.user_authority_event_id,
            INVITE_SERVER_PRIVATE_KEY,
        );
        let store = Store::open_memory_with_schema_sources(&[FACT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::EndpointSharedProjector::new(),
                &[],
                &store,
                &[rows::ENDPOINT_SHARED_ROWS],
                10,
            )
            .expect_err("empty signing key must fail");
        assert!(err.contains("signing_public_key"), "{err}");
    }

    #[test]
    fn endpoint_shared_projector_rejects_invite_server_workspace_mismatch() {
        let (payload, fact, mut invite_server_fact) = invite_server_endpoint_shared();
        invite_server_fact = signed_invite_server_fact(
            invite_server_fact.id,
            [9; 32],
            crypto::ed25519_public_key(&INVITE_SERVER_PRIVATE_KEY),
        );
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: crate::protocol::matchers::exact_need(
                fact.id,
                crate::protocol::matchers::invite_server_role(),
                payload.user_authority_event_id,
            ),
            offer: crate::protocol::matchers::invite_server_offer(invite_server_fact.id),
            payload: invite_server_fact,
        }]);

        let err = project::EndpointSharedProjector::new()
            .project(&fact, &context)
            .expect_err("workspace mismatch must fail");

        assert_eq!(
            err,
            "endpoint_shared workspace does not match invite_server"
        );
    }

    #[test]
    fn endpoint_shared_projector_rejects_invite_server_signing_key_mismatch() {
        let (payload, fact, mut invite_server_fact) = invite_server_endpoint_shared();
        invite_server_fact =
            signed_invite_server_fact(invite_server_fact.id, payload.workspace_id, [9; 32]);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: crate::protocol::matchers::exact_need(
                fact.id,
                crate::protocol::matchers::invite_server_role(),
                payload.user_authority_event_id,
            ),
            offer: crate::protocol::matchers::invite_server_offer(invite_server_fact.id),
            payload: invite_server_fact,
        }]);

        let err = project::EndpointSharedProjector::new()
            .project(&fact, &context)
            .expect_err("signing key mismatch must fail");

        assert_eq!(
            err,
            "endpoint_shared signer public key does not match invite_server"
        );
    }

    #[test]
    fn endpoint_shared_device_role_waits_for_device_invite_context() {
        let mut payload = sample_fact();
        payload.endpoint_role = EndpointRole::Device;
        payload.device_name = "phone".to_string();
        let fact = signed_endpoint_shared_fact(&payload, [8; 32], [8; 32]);

        let output = project::EndpointSharedProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("device role waits");

        assert_eq!(output.needs.len(), 1);
        assert_eq!(
            output.needs[0].role,
            crate::protocol::matchers::device_invite_role()
        );
    }

    #[test]
    fn endpoint_shared_device_role_should_project_after_signed_device_invite_context_matches() {
        let device_invite_fact = signed_device_invite_fact([1; 32], [2; 32], [8; 32]);
        let payload = EndpointSharedFact {
            endpoint_role: EndpointRole::Device,
            device_name: "phone".to_string(),
            user_authority_event_id: [2; 32],
            ..sample_fact()
        };
        let fact = signed_endpoint_shared_fact(&payload, device_invite_fact.id, [8; 32]);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: crate::protocol::matchers::exact_need(
                fact.id,
                crate::protocol::matchers::device_invite_role(),
                device_invite_fact.id,
            ),
            offer: crate::protocol::matchers::exact_offer(
                device_invite_fact.id,
                crate::protocol::matchers::device_invite_role(),
            ),
            payload: device_invite_fact,
        }]);

        let output = project::EndpointSharedProjector::new()
            .project(&fact, &context)
            .expect("signed device_invite context authorizes device endpoint_shared");

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 1);
    }

    fn invite_server_endpoint_shared() -> (EndpointSharedFact, Fact, Fact) {
        let invite_server_fact = signed_invite_server_fact(
            [2; 32],
            [1; 32],
            crypto::ed25519_public_key(&INVITE_SERVER_PRIVATE_KEY),
        );
        let payload = EndpointSharedFact {
            user_authority_event_id: invite_server_fact.id,
            ..sample_fact()
        };
        let fact =
            signed_endpoint_shared_fact(&payload, invite_server_fact.id, INVITE_SERVER_PRIVATE_KEY);
        (payload, fact, invite_server_fact)
    }

    fn signed_invite_server_fact(
        invite_server_id: [u8; 32],
        workspace_id: [u8; 32],
        public_key: [u8; 32],
    ) -> Fact {
        Fact {
            id: invite_server_id,
            scope: FactScope::Global,
            timestamp: 1,
            bytes: signed_fact::create::sign_payload_bytes(
                workspace_id,
                &INVITE_SERVER_PRIVATE_KEY,
                invite_server_layout::encode_fact(&InviteServerFact {
                    created_at_ms: 1,
                    public_key,
                    workspace_id,
                    authority_event_id: workspace_id,
                })
                .expect("encode invite_server"),
            )
            .expect("sign invite_server"),
        }
    }

    fn signed_device_invite_fact(
        workspace_id: [u8; 32],
        user_authority_event_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Fact {
        let payload = topo::protocol::fact_modules::identity_device_invite::layout::encode_fact(
            &topo::protocol::fact_modules::identity_device_invite::fact::DeviceInviteFact {
                created_at_ms: 1,
                workspace_id,
                user_authority_event_id,
                user_invite_event_id: Some([6; 32]),
                public_key: crypto::ed25519_public_key(&private_key),
            },
        )
        .expect("encode device_invite");
        let bytes =
            signed_fact::create::sign_payload_bytes(user_authority_event_id, &private_key, payload)
                .expect("sign device_invite");
        Fact::new(FactScope::Global, 1, bytes)
    }

    fn signed_endpoint_shared_fact(
        payload: &EndpointSharedFact,
        signer_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Fact {
        let bytes = signed_fact::create::sign_payload_bytes(
            signer_id,
            &private_key,
            layout::encode_fact(payload).expect("encode endpoint_shared"),
        )
        .expect("sign endpoint_shared");
        Fact::new(FactScope::Global, payload.created_at_ms, bytes)
    }
}
