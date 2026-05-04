use topo::core::{pipeline, store::Store};
use topo::protocol::event_modules::Modules;

#[test]
fn command_admission_returns_event_ids_for_chaining() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("pipeline.db")).unwrap();
    let modules = Modules::new();

    let output = modules.generate_content(&store, 3, 64).unwrap();
    let (_, report) = pipeline::run_command(&store, &modules, output).unwrap();

    assert_eq!(report.event_ids.len(), 3);
    for event_id in report.event_ids {
        assert!(store.has_shared_event(&event_id).unwrap());
    }
}
