use std::cell::Cell;
use std::net::SocketAddr;

use topo::core::store::Store;
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

    let output = modules.generate_content(&store, [1; 32], 3, 64).unwrap();
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
