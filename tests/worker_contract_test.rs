use topo::core::store::{event_id, Store};
use topo::protocol::event_modules::{worker, Modules};

#[test]
fn command_admission_returns_event_ids_for_chaining() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("worker.db")).unwrap();
    let modules = Modules::new();

    let output = modules.generate_content(&store, 3, 64).unwrap();
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
        assert!(store.has_shared_event(&event_id).unwrap());
    }
}
