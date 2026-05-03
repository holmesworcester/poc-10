mod cli_harness;

use cli_harness::*;

#[test]
fn generate_cli_uses_real_store_and_reports_applied_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "generate.db");

    let generated = generate(&db, 7, 128);
    assert!(generated.contains("generated_events: 7"), "{generated}");
    assert!(generated.contains("applied_events: 7"), "{generated}");
    assert!(generated.contains("event_size_bytes: 128"), "{generated}");
    assert!(generated.contains("first_timestamp: 1"), "{generated}");
    assert!(generated.contains("last_timestamp: 7"), "{generated}");

    assert_eq!(count(&db), 7);
    let status = assert_success(topo(&db, &["count"]));
    assert_eq!(line_value(&status, "payload_bytes"), "896");
    assert_eq!(line_value(&status, "applied_events"), "7");
    assert_eq!(line_value(&status, "ready_events"), "0");
    assert_eq!(line_value(&status, "blocked_events"), "0");
}
