use topo::core::crypto;
use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_endpoint::fact::EndpointFact;
use topo::event_modules::identity_endpoint::{layout, project, rows};

fn keypair() -> EndpointFact {
    let secret = [3u8; 32];
    let signing_secret = [5u8; 32];
    EndpointFact {
        endpoint: crypto::x25519_public_key(&secret),
        secret,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    }
}

#[test]
fn endpoint_projector_materializes_four_local_rows() {
    let endpoint = keypair();
    let fact = Fact::new(
        FactScope::Local,
        7,
        layout::encode_fact(&endpoint).expect("encode endpoint"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::EndpointProjector::new(),
            &[],
            &store,
            &[
                rows::LOCAL_ENDPOINT_ROWS,
                rows::LOCAL_ENDPOINT_SECRET_ROWS,
                rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
                rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
            ],
            10,
        )
        .expect("project endpoint");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 4);
    assert!(bus.intents().is_empty());

    let endpoint_rows = store
        .table_rows(rows::LOCAL_ENDPOINT_ROWS)
        .expect("endpoint rows");
    assert_eq!(endpoint_rows.len(), 1);
    assert_eq!(endpoint_rows[0].0, rows::LOCAL_KEY.to_vec());
    assert_eq!(endpoint_rows[0].1, endpoint.endpoint.to_vec());

    let secret_rows = store
        .table_rows(rows::LOCAL_ENDPOINT_SECRET_ROWS)
        .expect("secret rows");
    assert_eq!(secret_rows[0].1, endpoint.secret.to_vec());

    let signing_pub = store
        .table_rows(rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS)
        .expect("signing pub rows");
    assert_eq!(signing_pub[0].1, endpoint.signing_public_key.to_vec());

    let signing_sec = store
        .table_rows(rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS)
        .expect("signing sec rows");
    assert_eq!(signing_sec[0].1, endpoint.signing_secret.to_vec());

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::EndpointProjector::new(),
            &[],
            &store,
            &[
                rows::LOCAL_ENDPOINT_ROWS,
                rows::LOCAL_ENDPOINT_SECRET_ROWS,
                rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
                rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
            ],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn endpoint_projector_rejects_non_local_scope() {
    let endpoint = keypair();
    let fact = Fact::new(
        FactScope::Global,
        7,
        layout::encode_fact(&endpoint).expect("encode endpoint"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::EndpointProjector::new(),
            &[],
            &store,
            &[
                rows::LOCAL_ENDPOINT_ROWS,
                rows::LOCAL_ENDPOINT_SECRET_ROWS,
                rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
                rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
            ],
            10,
        )
        .expect_err("global scope must fail");
    assert!(err.contains("local scope"), "{err}");
}
