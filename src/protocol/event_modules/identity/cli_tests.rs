use crate::core::crypto;
use crate::protocol::event_modules::identity::{
    admin, device_invite, endpoint_shared, user, user_invite, workspace,
};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::{self, CommandOutput};
use crate::protocol::Protocol;

#[test]
fn bootstrap_two_users_and_two_endpoints_replay_without_daemon() {
    let protocol = Protocol::new();
    let creator = Protocol::open_memory_store().expect("open creator");
    let receiver = Protocol::open_memory_store().expect("open receiver");
    let workspace_private_key = [7; 32];
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);

    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: workspace_public_key,
        name: "Workspace".to_string(),
    })
    .expect("create workspace");
    let workspace_id = workspace.value.workspace_id;
    let workspace_records = admit(&creator, &protocol, workspace);

    let bootstrap = admin::commands::create_bootstrap(admin::commands::CreateBootstrapAdmin {
        created_at_ms: 2,
        workspace_id,
        root_public_key: workspace_public_key,
        root_user_event_id: workspace_id,
    })
    .expect("create bootstrap admin");
    let bootstrap_admin_id = bootstrap.value.admin_id;
    let bootstrap_records = admit(&creator, &protocol, bootstrap);

    let alice = create_user(
        &creator,
        &protocol,
        UserInput {
            workspace_id,
            workspace_private_key,
            timestamp: 10,
            username: "alice",
            invite_private_key: [8; 32],
            user_private_key: [18; 32],
        },
    );
    let bob = create_user(
        &creator,
        &protocol,
        UserInput {
            workspace_id,
            workspace_private_key,
            timestamp: 20,
            username: "bob",
            invite_private_key: [9; 32],
            user_private_key: [19; 32],
        },
    );

    let alice_endpoint = crypto::ed25519_public_key(&[31; 32]);
    let bob_endpoint = crypto::ed25519_public_key(&[32; 32]);
    let alice_join = share_endpoint(
        &creator,
        &protocol,
        EndpointJoinInput {
            workspace_id,
            user_id: alice.user_id,
            endpoint_id: alice_endpoint,
            device_name: "alice-laptop",
            timestamp: 30,
            device_invite_private_key: [40; 32],
        },
    );
    let bob_join = share_endpoint(
        &creator,
        &protocol,
        EndpointJoinInput {
            workspace_id,
            user_id: bob.user_id,
            endpoint_id: bob_endpoint,
            device_name: "bob-phone",
            timestamp: 40,
            device_invite_private_key: [41; 32],
        },
    );

    let received = reversed_records(vec![
        workspace_records,
        bootstrap_records,
        alice.records,
        bob.records,
        alice_join.records,
        bob_join.records,
    ]);
    let inserted = received.len();
    let report = worker::run(
        &receiver,
        &protocol,
        worker::AdmitRecords { records: received },
    )
    .expect("admit out-of-order identity graph");
    assert_eq!(report.inserted_events, inserted);
    assert_eq!(report.applied_events, 1);
    assert!(
        report.blocked_events > 0,
        "out-of-order receipt should block children until dependencies apply"
    );

    let drained = worker::run(
        &receiver,
        &protocol,
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .expect("drain ready identity graph");
    assert_eq!(drained.applied_events, inserted - 1);

    let statuses = event_schema::status_counts(&receiver).expect("status counts");
    assert_eq!(statuses.applied, inserted);
    assert_eq!(statuses.blocked, 0);
    assert_eq!(statuses.rejected, 0);
    assert_eq!(statuses.blocked_edges, 0);

    assert_eq!(row_count(&receiver, admin::schema::ADMINS), 1);
    assert_eq!(row_count(&receiver, user_invite::schema::USER_INVITES), 2);
    assert_eq!(row_count(&receiver, user::schema::USERS), 2);
    assert_eq!(
        row_count(&receiver, device_invite::schema::DEVICE_INVITES),
        2
    );
    assert_eq!(
        row_count(&receiver, endpoint_shared::schema::ENDPOINT_SHARED),
        2
    );
    assert_eq!(
        row_count(&receiver, endpoint_shared::schema::ENDPOINT_MEMBERSHIPS),
        2
    );

    assert_admin(
        &receiver,
        workspace_id,
        bootstrap_admin_id,
        workspace_public_key,
    );
    assert_user(&receiver, workspace_id, alice.user_id, "alice");
    assert_user(&receiver, workspace_id, bob.user_id, "bob");
    assert_membership(&receiver, workspace_id, alice_endpoint, alice.user_id);
    assert_membership(&receiver, workspace_id, bob_endpoint, bob.user_id);

    let duplicate = endpoint_shared::commands::share_endpoint(
        &receiver,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: 50,
            workspace_id,
            user_authority_event_id: alice.user_id,
            endpoint_id: alice_endpoint,
            device_name: "alice-second-join".to_string(),
            device_invite_id: alice_join.device_invite_id,
            device_invite_private_key: alice_join.device_invite_private_key,
        },
    )
    .expect_err("same endpoint cannot join same workspace twice");
    assert_eq!(duplicate, "endpoint is already joined to workspace");
}

struct CreatedUser {
    user_id: EventId,
    records: Vec<EventRecord>,
}

struct UserInput {
    workspace_id: EventId,
    workspace_private_key: [u8; 32],
    timestamp: u64,
    username: &'static str,
    invite_private_key: [u8; 32],
    user_private_key: [u8; 32],
}

struct EndpointJoin {
    device_invite_id: EventId,
    device_invite_private_key: [u8; 32],
    records: Vec<EventRecord>,
}

struct EndpointJoinInput {
    workspace_id: EventId,
    user_id: EventId,
    endpoint_id: [u8; 32],
    device_name: &'static str,
    timestamp: u64,
    device_invite_private_key: [u8; 32],
}

fn create_user(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    input: UserInput,
) -> CreatedUser {
    let invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: input.timestamp,
        public_key: crypto::ed25519_public_key(&input.invite_private_key),
        workspace_id: input.workspace_id,
        authority_event_id: input.workspace_id,
        signer_event_id: input.workspace_id,
        signer_private_key: input.workspace_private_key,
    })
    .expect("create user invite");
    let user_invite_id = invite.value.user_invite_id;
    let mut records = admit(store, protocol, invite);

    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: input.timestamp + 1,
        public_key: crypto::ed25519_public_key(&input.user_private_key),
        username: input.username.to_string(),
        user_invite_event_id: user_invite_id,
        user_invite_private_key: input.invite_private_key,
    })
    .expect("create user");
    let user_id = user.value.user_id;
    records.extend(admit(store, protocol, user));

    CreatedUser { user_id, records }
}

fn share_endpoint(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    input: EndpointJoinInput,
) -> EndpointJoin {
    let invite = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: input.timestamp,
            workspace_id: input.workspace_id,
            user_authority_event_id: input.user_id,
        },
        input.device_invite_private_key,
    )
    .expect("create device invite");
    let device_invite_id = invite.value.device_invite_id;
    let mut records = admit(store, protocol, invite);

    let shared = endpoint_shared::commands::share_endpoint(
        store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: input.timestamp + 1,
            workspace_id: input.workspace_id,
            user_authority_event_id: input.user_id,
            endpoint_id: input.endpoint_id,
            device_name: input.device_name.to_string(),
            device_invite_id,
            device_invite_private_key: input.device_invite_private_key,
        },
    )
    .expect("share endpoint");
    records.extend(admit(store, protocol, shared));

    EndpointJoin {
        device_invite_id,
        device_invite_private_key: input.device_invite_private_key,
        records,
    }
}

fn admit<T>(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    output: CommandOutput<T>,
) -> Vec<EventRecord> {
    let records = output
        .events
        .iter()
        .map(|event| event.record().clone())
        .collect::<Vec<_>>();
    worker::run(store, protocol, output).expect("admit command output");
    records
}

fn reversed_records(groups: Vec<Vec<EventRecord>>) -> Vec<EventRecord> {
    groups
        .into_iter()
        .flatten()
        .rev()
        .collect::<Vec<EventRecord>>()
}

fn row_count(store: &crate::core::store::Store, table: crate::core::store::TableName) -> usize {
    store.table_row_count(table).expect("row count")
}

fn assert_admin(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    admin_id: EventId,
    public_key: [u8; 32],
) {
    let key = admin::schema::admin_key(&workspace_id, &admin_id);
    let value = store
        .table_row(admin::schema::ADMINS, &key)
        .expect("read admin row")
        .expect("admin row");
    let row = admin::schema::decode_admin_row(&key, &value).expect("decode admin");
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.admin_id, admin_id);
    assert_eq!(row.authority_event_id, workspace_id);
    assert_eq!(row.user_event_id, workspace_id);
    assert_eq!(row.public_key, public_key);
}

fn assert_user(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    user_id: EventId,
    username: &str,
) {
    let key = user::schema::user_key(&workspace_id, &user_id);
    let value = store
        .table_row(user::schema::USERS, &key)
        .expect("read user row")
        .expect("user row");
    let row = user::schema::decode_user_row(&key, &value).expect("decode user");
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.username, username);
}

fn assert_membership(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    endpoint_id: [u8; 32],
    user_id: EventId,
) {
    let key = endpoint_shared::schema::endpoint_membership_key(endpoint_id, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .expect("read endpoint membership")
        .expect("endpoint membership");
    let row =
        endpoint_shared::schema::decode_endpoint_membership_row(&key, &value).expect("decode row");
    assert_eq!(row.endpoint_id, endpoint_id);
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.user_authority_event_id, user_id);
}
