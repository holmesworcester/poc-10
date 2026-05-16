use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_endpoint_shared::fact::{EndpointRole, EndpointSharedFact};
use topo::event_modules::identity_endpoint_shared::{layout, project, rows};
use topo::event_modules::identity_invite_server::{
    fact::InviteServerFact, layout as invite_server_layout,
};
use topo::event_modules::identity_matchers;

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
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );

    let output = project::EndpointSharedProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(
        output.needs[0].role,
        identity_matchers::invite_server_role()
    );
    assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
}

#[test]
fn endpoint_shared_projector_materializes_row_with_invite_server_context() {
    let payload = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_matchers::exact_need(
            fact.id,
            identity_matchers::invite_server_role(),
            payload.user_authority_event_id,
        ),
        offer: identity_matchers::exact_offer(
            payload.user_authority_event_id,
            identity_matchers::invite_server_role(),
        ),
        payload: invite_server_fact(payload.user_authority_event_id, payload.workspace_id),
    }]);

    let output = project::EndpointSharedProjector::new()
        .project(&fact, &context)
        .expect("project endpoint shared");

    assert!(output.needs.is_empty());
    assert_eq!(output.offers.len(), 1);
    assert_eq!(
        output.offers[0].role,
        identity_matchers::endpoint_shared_role()
    );
    assert_eq!(output.intents.len(), 1);
    let row_intent = AtomicIntent::from_intent(&output.intents[0], &[rows::ENDPOINT_SHARED_ROWS])
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
    let fact = Fact::new(
        FactScope::Local,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
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
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
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
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
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
    let payload = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_matchers::exact_need(
            fact.id,
            identity_matchers::invite_server_role(),
            payload.user_authority_event_id,
        ),
        offer: identity_matchers::exact_offer(
            payload.user_authority_event_id,
            identity_matchers::invite_server_role(),
        ),
        payload: invite_server_fact(payload.user_authority_event_id, [9; 32]),
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
    let payload = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_matchers::exact_need(
            fact.id,
            identity_matchers::invite_server_role(),
            payload.user_authority_event_id,
        ),
        offer: identity_matchers::exact_offer(
            payload.user_authority_event_id,
            identity_matchers::invite_server_role(),
        ),
        payload: invite_server_fact_with_key(
            payload.user_authority_event_id,
            payload.workspace_id,
            [9; 32],
        ),
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
fn endpoint_shared_device_role_is_blocked_until_signed_envelope_context_exists() {
    let mut payload = sample_fact();
    payload.endpoint_role = EndpointRole::Device;
    payload.device_name = "phone".to_string();
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );

    let err = project::EndpointSharedProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("device role cannot be validated from raw payload");

    assert_eq!(
        err,
        "endpoint_shared device authority requires signed envelope context"
    );
}

#[test]
#[ignore = "blocked: raw endpoint_shared facts do not carry signed envelope signer_event_id or signer_public_key, so the projector cannot identify and verify the authorizing device_invite"]
fn endpoint_shared_device_role_should_project_after_signed_device_invite_context_matches() {
    let payload = EndpointSharedFact {
        endpoint_role: EndpointRole::Device,
        device_name: "phone".to_string(),
        ..sample_fact()
    };
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );

    let output = project::EndpointSharedProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("future signed-envelope context should authorize device endpoint_shared");

    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
}

fn invite_server_fact(invite_server_id: [u8; 32], workspace_id: [u8; 32]) -> Fact {
    invite_server_fact_with_key(invite_server_id, workspace_id, [4; 32])
}

fn invite_server_fact_with_key(
    invite_server_id: [u8; 32],
    workspace_id: [u8; 32],
    public_key: [u8; 32],
) -> Fact {
    Fact {
        id: invite_server_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: invite_server_layout::encode_fact(&InviteServerFact {
            created_at_ms: 1,
            public_key,
            workspace_id,
            authority_event_id: workspace_id,
        })
        .expect("encode invite_server"),
    }
}
