use std::cell::Cell;
use std::net::SocketAddr;

use topo::core::store::Store;
use topo::protocol::event_modules::identity::{endpoint, endpoint_shared};
use topo::protocol::event_modules::schema::{self as event_schema, EventLabel};
use topo::protocol::event_modules::types::{
    event_id, EventId, EventRecord, EventScope, ReceiveMetadata,
};
use topo::protocol::event_modules::worker::{
    self, CommandOutput, EventRegistry, EventWithContext, ProjectionOutput,
};
use topo::protocol::event_modules::Modules;
use topo::protocol::Protocol;

#[test]
fn command_admission_returns_event_ids_for_chaining() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("worker.db")).unwrap();
    let modules = Modules::new();
    let (workspace_id, _) = install_local_content_signer(&store);

    let output = modules
        .generate_content(&store, workspace_id, 3, 64)
        .unwrap();
    let proposed_ids = output
        .events
        .iter()
        .map(|event| {
            assert_eq!(event.event_id(), event_id(&event.record().canonical_bytes));
            event.event_id()
        })
        .collect::<Vec<_>>();
    let (_, report) = worker::run(&store, &modules, output).unwrap();

    assert_eq!(report.event_ids, proposed_ids);
    for event_id in report.event_ids {
        assert!(event_schema::has_shared_event(&store, &event_id).unwrap());
    }
}

fn install_local_content_signer(store: &Store) -> (EventId, EventId) {
    let local = endpoint::commands::create_local_keypair().value;
    store
        .insert_table_rows(endpoint::projector::local_endpoint(local))
        .expect("insert local endpoint");
    let workspace_id = [1; 32];
    let endpoint_shared_id = [2; 32];
    let device_invite_id = [3; 32];
    let event = endpoint_shared::types::EndpointSharedEvent {
        created_at_ms: 1,
        workspace_id,
        user_authority_event_id: [4; 32],
        endpoint_id: local.endpoint,
        signing_public_key: local.signing_public_key,
        device_name: "worker".to_string(),
    };
    store
        .insert_table_rows(vec![endpoint_shared::schema::endpoint_membership_row(
            endpoint_shared_id,
            device_invite_id,
            &event,
        )])
        .expect("insert local membership");
    (workspace_id, endpoint_shared_id)
}

#[test]
fn worker_fetches_dependency_records_and_labels_before_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("context.db")).unwrap();

    let dep_bytes = b"dep".to_vec();
    let child_bytes = b"child".to_vec();
    let dep_id = event_id(&dep_bytes);
    let child_id = event_id(&child_bytes);
    let registry = ContextRegistry {
        dep_id,
        child_id,
        dep_bytes: dep_bytes.clone(),
        child_bytes: child_bytes.clone(),
        child_saw_context: Cell::new(false),
    };

    let child = registry.record_for(child_bytes).unwrap();
    let (_, child_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![child]),
    )
    .unwrap();
    assert_eq!(child_report.blocked_events, 1);
    assert_eq!(child_report.applied_events, 0);

    let dep = registry.record_for(dep_bytes).unwrap();
    let (_, dep_report) =
        worker::run(&store, &registry, CommandOutput::with_events((), vec![dep])).unwrap();
    assert_eq!(dep_report.applied_events, 1);

    let drain = worker::run(&store, &registry, worker::DrainUntilIdle { batch_size: 10 }).unwrap();
    assert_eq!(drain.applied_events, 1);
    assert!(registry.child_saw_context.get());
}

#[test]
fn worker_never_surfaces_failed_projection_as_dependency_context() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("invalid-context.db")).unwrap();

    let gate_bytes = b"gate".to_vec();
    let bad_dep_bytes = b"bad-dep".to_vec();
    let child_bytes = b"child-after-bad-dep".to_vec();
    let gate_id = event_id(&gate_bytes);
    let bad_dep_id = event_id(&bad_dep_bytes);
    let child_id = event_id(&child_bytes);
    let registry = ValidDependencyContextRegistry {
        gate_id,
        bad_dep_id,
        child_id,
        gate_bytes: gate_bytes.clone(),
        bad_dep_bytes: bad_dep_bytes.clone(),
        child_bytes: child_bytes.clone(),
        child_saw_context: Cell::new(false),
    };

    let bad_dep = registry.record_for(bad_dep_bytes).unwrap();
    let child = registry.record_for(child_bytes).unwrap();
    let (_, blocked_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![child, bad_dep]),
    )
    .unwrap();
    assert_eq!(blocked_report.blocked_events, 2);
    assert_eq!(blocked_report.applied_events, 0);

    let gate = registry.record_for(gate_bytes).unwrap();
    let (_, gate_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![gate]),
    )
    .unwrap();
    assert_eq!(gate_report.applied_events, 1);

    let err = worker::run(&store, &registry, worker::DrainUntilIdle { batch_size: 10 })
        .expect_err("invalid dependency projection must fail");
    assert!(
        err.contains("bad dependency rejected by projector"),
        "{err}"
    );

    let statuses = event_schema::status_counts(&store).expect("status counts");
    assert_eq!(statuses.applied, 1, "only the gate event should apply");
    assert_eq!(statuses.ready, 1, "failed dependency should remain ready");
    assert_eq!(
        statuses.blocked, 1,
        "child should remain blocked on bad dep"
    );
    assert_eq!(statuses.blocked_edges, 1);
    assert!(
        !registry.child_saw_context.get(),
        "child projector must not receive failed dependency in context"
    );
    assert!(!event_schema::event_is_applied(&store, &bad_dep_id).unwrap());
    assert!(!event_schema::event_is_applied(&store, &child_id).unwrap());
}

#[test]
fn worker_rejects_blocked_durable_receive_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("receive-metadata.db")).unwrap();

    let bytes = b"durable-with-receive-metadata".to_vec();
    let registry = RejectReceiveMetadataRegistry {
        bytes: bytes.clone(),
    };
    let event = EventRecord {
        timestamp: 1,
        body_len: bytes.len(),
        canonical_bytes: bytes,
        dependencies: vec![[9; 32]],
        workspace_id: None,
        scope: EventScope::Shared,
        receive: Some(ReceiveMetadata {
            origin: "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
            local_endpoint: [7; 32],
            remember_route: true,
        }),
    };

    let err = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![event]),
    )
    .expect_err("blocked durable receive metadata must be rejected");
    assert!(
        err.contains("durable receive metadata cannot be preserved while blocked"),
        "{err}"
    );
}

struct ContextRegistry {
    dep_id: EventId,
    child_id: EventId,
    dep_bytes: Vec<u8>,
    child_bytes: Vec<u8>,
    child_saw_context: Cell<bool>,
}

struct ValidDependencyContextRegistry {
    gate_id: EventId,
    bad_dep_id: EventId,
    child_id: EventId,
    gate_bytes: Vec<u8>,
    bad_dep_bytes: Vec<u8>,
    child_bytes: Vec<u8>,
    child_saw_context: Cell<bool>,
}

struct RejectReceiveMetadataRegistry {
    bytes: Vec<u8>,
}

impl EventRegistry for RejectReceiveMetadataRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.bytes {
            Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
                receive: None,
            })
        } else {
            Err("unknown test event".to_string())
        }
    }

    fn project_record(
        &self,
        _store: &Store,
        _event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        panic!("durable receive metadata should be rejected before projection");
    }
}

impl ContextRegistry {
    fn record_for(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.dep_bytes {
            return Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
                receive: None,
            });
        }
        if bytes == self.child_bytes {
            return Ok(EventRecord {
                timestamp: 2,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.dep_id],
                workspace_id: None,
                scope: EventScope::Shared,
                receive: None,
            });
        }
        Err("unknown test event".to_string())
    }
}

impl ValidDependencyContextRegistry {
    fn record_for(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.gate_bytes {
            return Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
                receive: None,
            });
        }
        if bytes == self.bad_dep_bytes {
            return Ok(EventRecord {
                timestamp: 2,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.gate_id],
                workspace_id: None,
                scope: EventScope::Shared,
                receive: None,
            });
        }
        if bytes == self.child_bytes {
            return Ok(EventRecord {
                timestamp: 3,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.bad_dep_id],
                workspace_id: None,
                scope: EventScope::Shared,
                receive: None,
            });
        }
        Err("unknown test event".to_string())
    }
}

impl EventRegistry for ContextRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_for(bytes)
    }

    fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        if event.context.event_id == self.dep_id {
            return Ok(ProjectionOutput::labels(vec![EventLabel {
                event_id: self.child_id,
                label: b"dep-applied".to_vec(),
            }]));
        }
        if event.context.event_id == self.child_id {
            assert_eq!(
                event
                    .context
                    .dependency(&self.dep_id)
                    .expect("dependency context")
                    .canonical_bytes,
                self.dep_bytes
            );
            assert!(event.context.has_label(b"dep-applied"));
            self.child_saw_context.set(true);
            return Ok(ProjectionOutput::default());
        }
        Err("unknown projection".to_string())
    }
}

impl EventRegistry for ValidDependencyContextRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_for(bytes)
    }

    fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        if event.context.event_id == self.gate_id {
            assert!(event.context.dependencies.is_empty());
            return Ok(ProjectionOutput::default());
        }
        if event.context.event_id == self.bad_dep_id {
            assert_eq!(
                event
                    .context
                    .dependency(&self.gate_id)
                    .expect("gate dependency")
                    .canonical_bytes,
                self.gate_bytes
            );
            return Err("bad dependency rejected by projector".to_string());
        }
        if event.context.event_id == self.child_id {
            self.child_saw_context.set(true);
            panic!("child must remain blocked until bad dependency is applied");
        }
        Err("unknown projection".to_string())
    }
}
