mod cli_harness;

use cli_harness::*;
use topo::core::crypto;
use topo::protocol::event_modules::identity::workspace;
use topo::protocol::event_modules::types::EventId;
use topo::protocol::event_modules::worker;
use topo::protocol::Protocol;

#[test]
fn generate_cli_uses_real_store_and_reports_applied_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "generate.db");
    let workspace_id = create_workspace(&db);
    let workspace_hex = hex_id(workspace_id);

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_hex, "7", "128"]));
    assert!(generated.contains("generated_events: 7"), "{generated}");
    assert!(generated.contains("applied_events: 7"), "{generated}");
    assert!(generated.contains("event_size_bytes: 128"), "{generated}");
    assert!(generated.contains("first_timestamp: 1"), "{generated}");
    assert!(generated.contains("last_timestamp: 7"), "{generated}");

    let content = assert_success(topo(&["--db", &db, "content-count", &workspace_hex]));
    assert_eq!(line_value(&content, "content_events"), "7");
    assert_eq!(line_value(&content, "content_payload_bytes"), "896");

    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(line_value(&status, "events"), "8");
    assert_eq!(line_value(&status, "applied_events"), "8");
    assert_eq!(line_value(&status, "ready_events"), "0");
    assert_eq!(line_value(&status, "blocked_events"), "0");
}

fn create_workspace(db: &str) -> EventId {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open store");
    let output = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&[7; 32]),
        name: "Generate".to_string(),
    })
    .expect("create workspace");
    let workspace_id = output.value.workspace_id;
    worker::run(&store, &protocol, output).expect("admit workspace");
    workspace_id
}

fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
