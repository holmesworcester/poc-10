//! Black-box CLI tests for protocol updates and deterministic state summaries.
//!
//! Setup goes through the real `con` binary: a workspace and content messages
//! are authored, then protocol `update` rebuilds derived state from retained
//! facts through ordinary runtime turns.

mod cli_harness;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::*;
use rusqlite::{params, Connection, OptionalExtension};

fn create_workspace(db: &str, name: &str, username: &str, device_name: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
    ]));
    let workspace_id = line_value(&out, "workspace_id");
    wait_for_users_contains(db, &workspace_id, username);
    wait_for_identity_contains(db, "endpoint_role=device");
    workspace_id
}

fn seed_workspace_with_content(db: &str) -> String {
    let _daemon = spawn_worker_daemon(db);
    let workspace_id = create_workspace(db, "Replay", "alice", "laptop");
    create_local_content_key(db, &workspace_id);
    assert_success(topo(&["--db", db, "send", &workspace_id, "first message"]));
    wait_for_message_text(db, &workspace_id, "alice: first message");
    assert_success(topo(&["--db", db, "send", &workspace_id, "second message"]));
    wait_for_message_text(db, &workspace_id, "alice: second message");
    wait_for_runtime_idle(db);
    workspace_id
}

struct StartedDaemon {
    db: String,
    child: Child,
    stdout: Option<thread::JoinHandle<String>>,
    stderr: Option<thread::JoinHandle<String>>,
}

impl Drop for StartedDaemon {
    fn drop(&mut self) {
        let _ = topo(&["--db", &self.db, "stop"]);
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            if let Ok(text) = stderr.join() {
                if !text.trim().is_empty() {
                    eprintln!("[daemon-stderr db={}] {}", self.db, text.trim_end());
                }
            }
        }
    }
}

fn spawn_worker_daemon(db: &str) -> StartedDaemon {
    let port = free_port().to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--tick-ms",
        "25",
        "--quiet-ms",
        "25",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let stderr = child.stderr.take().expect("daemon stderr");
    let mut line = String::new();
    let mut stdout_reader = BufReader::new(stdout);
    stdout_reader
        .read_line(&mut line)
        .expect("read daemon ready line");
    assert!(line.contains("listening:"), "daemon did not start: {line}");
    let stdout_handle = thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout_reader.read_to_string(&mut text);
        text
    });
    let stderr_handle = thread::spawn(move || {
        let mut text = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut text);
        text
    });
    StartedDaemon {
        db: db.to_string(),
        child,
        stdout: Some(stdout_handle),
        stderr: Some(stderr_handle),
    }
}

fn wait_for_runtime_idle(db: &str) {
    let started = Instant::now();
    let timeout = env_u64("TOPO_RUNTIME_IDLE_TIMEOUT_MS")
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(10));
    loop {
        let output = topo(&["--db", db, "count"]);
        if !output.status.success() {
            let last = stderr(&output);
            assert!(
                started.elapsed() < timeout,
                "runtime queues did not become queryable:\n{last}"
            );
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        let last_count = stdout(&output);
        let facts: u64 = line_value(&last_count, "facts")
            .parse()
            .expect("facts count");
        let applied: u64 = line_value(&last_count, "applied_facts")
            .parse()
            .expect("applied facts count");
        let pending_intents: u64 = line_value(&last_count, "pending_intents")
            .parse()
            .expect("pending intents count");
        if facts == applied && pending_intents == 0 {
            return;
        }
        assert!(
            started.elapsed() < timeout,
            "daemon did not drain runtime queues:\n{last_count}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    out
}

fn wait_for_keys_value(db: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "keys", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, key) == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("keys {key} did not reach {expected}:\n{last}");
}

fn wait_for_message_text(db: &str, workspace_id: &str, expected_suffix: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if out
                .lines()
                .any(|line| line.trim_end().ends_with(expected_suffix))
            {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("message text {expected_suffix:?} never appeared in {db}:\n{last}");
}

fn wait_for_users_contains(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let users = topo(&["--db", db, "users", workspace_id]);
        if users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = stderr(&users);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("user {username} never appeared in {db}: {last}");
}

fn wait_for_identity_contains(db: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let identity = topo(&["--db", db, "identity"]);
        if identity.status.success() {
            let identity = stdout(&identity);
            if identity.contains(expected) {
                return;
            }
            last = identity;
        } else {
            last = stderr(&identity);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("identity never contained {expected}: {last}");
}

fn replace_stored_storage_version(db: &str, version: u32) {
    let conn = Connection::open(db).expect("open fixture db");
    conn.execute("DELETE FROM protocol_version_rows", [])
        .expect("clear protocol version marker");
    conn.execute(
        "INSERT INTO protocol_version_rows (update_fact_id, protocol_version, applied_at_ms)
         VALUES (?1, ?2, ?3)",
        params![vec![0x55_u8; 32], i64::from(version), 1_i64],
    )
    .expect("write stale protocol version marker");
}

fn stored_storage_version(db: &str) -> u32 {
    stored_storage_version_option(db).expect("read protocol version marker") as u32
}

fn stored_storage_version_option(db: &str) -> Option<i64> {
    let conn = Connection::open(db).expect("open fixture db");
    let has_table: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'protocol_version_rows'
             )",
            [],
            |row| row.get(0),
        )
        .expect("check protocol version table");
    if !has_table {
        return None;
    }
    conn.query_row(
        "SELECT protocol_version
         FROM protocol_version_rows
         ORDER BY applied_at_ms DESC, update_fact_id DESC
         LIMIT 1",
        [],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .expect("read protocol version marker")
}

fn insert_poison_opened_message_row(db: &str, workspace_id_hex: &str, text: &str) {
    let conn = Connection::open(db).expect("open fixture db");
    let workspace_id = decode_hex_32(workspace_id_hex);
    let fake_id = vec![0x42_u8; 32];
    conn.execute(
        "INSERT OR REPLACE INTO opened_message_rows
            (workspace_id, message_id, created_at_ms, author_user_id, signer_id, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            workspace_id,
            fake_id,
            9_999_999_i64,
            vec![0x43_u8; 32],
            vec![0x44_u8; 32],
            text.as_bytes().to_vec(),
        ],
    )
    .expect("insert poison opened message row");
}

fn decode_hex_32(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 64, "expected 32-byte hex id");
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).expect("fixture hex id should decode")
        })
        .collect()
}

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--tick-ms",
        "50",
        "--quiet-ms",
        "50",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).expect("daemon first line");
    assert!(
        first.starts_with("listening: "),
        "daemon did not report listening: {first}"
    );
    RunningDaemon { child }
}

#[test]
fn update_command_records_current_protocol_version() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");

    let update = assert_success(topo(&["--db", &db, "update"]));

    assert_eq!(line_value(&update, "protocol_version"), "1", "{update}");
    line_value(&update, "pending_projection")
        .parse::<u64>()
        .expect("pending projection count");
    assert_eq!(stored_storage_version(&db), 1);
}

#[test]
fn fresh_cli_turn_initializes_protocol_marker_without_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "fresh.db");
    assert_eq!(stored_storage_version_option(&db), None);

    assert_success(topo(&["--db", &db, "state-summary"]));

    assert_eq!(stored_storage_version(&db), 1);
}

#[test]
fn update_rebuilds_derived_state_and_unblocks_queries() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = seed_workspace_with_content(&db);

    assert_success(topo(&["--db", &db, "update"]));
    let _daemon = spawn_worker_daemon(&db);
    wait_for_runtime_idle(&db);

    // The rebuilt read model still answers content queries.
    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(messages.contains("first message"), "{messages}");
    assert!(messages.contains("second message"), "{messages}");
}

#[test]
fn stale_version_marker_repairs_before_cli_queries_read_materialized_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = seed_workspace_with_content(&db);
    let current_storage_version = stored_storage_version(&db);
    assert!(
        current_storage_version > 0,
        "fixture version must be positive"
    );
    let poison = "poisoned row from stale materialized storage";

    insert_poison_opened_message_row(&db, &workspace_id, poison);
    replace_stored_storage_version(&db, current_storage_version - 1);

    let output = topo(&["--db", &db, "messages", &workspace_id]);
    assert!(
        output.status.success(),
        "stale storage should repair before queries read materialized rows\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains(poison) && !stderr(&output).contains(poison),
        "query leaked data from stale materialized rows\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        stored_storage_version(&db),
        current_storage_version,
        "runtime preflight should restore the current version marker"
    );
    assert!(
        stdout(&output).contains("first message") && stdout(&output).contains("second message"),
        "query should read rebuilt rows, not the poison row:\n{}",
        stdout(&output)
    );
}

#[test]
fn runtime_turn_repairs_stale_marker_and_replays_pending_fact() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = seed_workspace_with_content(&db);
    let current_storage_version = stored_storage_version(&db);
    assert!(
        current_storage_version > 0,
        "fixture version must be positive"
    );

    let sync_setting = assert_success(topo(&[
        "--db",
        &db,
        "sync",
        "range",
        "--start-ms",
        "100",
        "--end-ms",
        "200",
    ]));
    assert_eq!(line_value(&sync_setting, "mode"), "range", "{sync_setting}");

    let before = assert_success(topo(&["--db", &db, "count"]));
    let facts_before_repair: u64 = line_value(&before, "facts")
        .parse()
        .expect("facts before repair");
    let applied_before_repair: u64 = line_value(&before, "applied_facts")
        .parse()
        .expect("applied before repair");
    assert_eq!(
        applied_before_repair, facts_before_repair,
        "command runtime turn should drain the sync setting before reporting count:\n{before}"
    );

    replace_stored_storage_version(&db, current_storage_version - 1);
    let sync_show = assert_success(topo(&["--db", &db, "sync", "show"]));

    let repaired = assert_success(topo(&["--db", &db, "count"]));
    let facts_after_repair: u64 = line_value(&repaired, "facts")
        .parse()
        .expect("facts after repair");
    assert!(
        facts_after_repair > facts_before_repair,
        "runtime turn should have authored a local update fact:\nbefore={before}\nafter={repaired}"
    );
    assert_eq!(
        stored_storage_version(&db),
        current_storage_version,
        "recurring update projection should store the current version marker"
    );

    assert_eq!(line_value(&sync_show, "mode"), "range", "{sync_show}");
    assert_eq!(line_value(&sync_show, "start_ms"), "100", "{sync_show}");
    assert_eq!(line_value(&sync_show, "end_ms"), "200", "{sync_show}");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(messages.contains("first message"), "{messages}");
    assert!(messages.contains("second message"), "{messages}");
}

#[test]
#[ignore = "manual replay throughput fixture; run with cargo test --release -- --ignored when measuring one-client derived-state rebuild"]
fn replay_cli_generated_messages_perf_rebuilds_normal_message_facts() {
    assert_release_perf_fixture();

    let tmp = tempfile::tempdir().unwrap();
    let message_count = env_usize("TOPO_REPLAY_PERF_MESSAGES").unwrap_or(1_000);
    let message_text_bytes = env_usize("TOPO_REPLAY_PERF_MESSAGE_TEXT_BYTES").unwrap_or(128);
    let timeout_ms = env_u64("TOPO_REPLAY_PERF_TIMEOUT_MS")
        .unwrap_or_else(|| 120_000_u64.max(message_count as u64 * 120));
    let random_seed = env_u64("TOPO_REPLAY_PERF_RANDOM_SEED").unwrap_or(0x5eed_5eed_cafe_babe);

    for order in replay_perf_orders() {
        run_replay_generated_messages_perf_order(
            &tmp,
            order,
            message_count,
            message_text_bytes,
            timeout_ms,
            random_seed,
        );
    }
}

fn run_replay_generated_messages_perf_order(
    tmp: &tempfile::TempDir,
    order: ReplayPerfOrder,
    message_count: usize,
    message_text_bytes: usize,
    timeout_ms: u64,
    random_seed: u64,
) {
    let db = temp_db(
        tmp,
        &format!("replay-generated-messages-perf-{}.db", order.as_str()),
    );
    let setup_started = Instant::now();
    let workspace_id = create_workspace(&db, "Replay Perf", "alice", "laptop");
    let daemon = spawn_worker_daemon(&db);
    create_local_content_key(&db, &workspace_id);
    let generated = con_cli_with_env(
        &[
            "--db",
            &db,
            "--at",
            "4000000000000",
            "generate",
            &workspace_id,
            &message_count.to_string(),
            &message_text_bytes.to_string(),
        ],
        &[("TOPO_PROFILE_GENERATE", "1")],
    );
    assert!(
        generated.status.success(),
        "generate failed\nstdout={}\nstderr={}",
        stdout(&generated),
        stderr(&generated)
    );
    assert_eq!(
        line_value(&stdout(&generated), "generated_facts"),
        message_count.to_string()
    );
    wait_for_content_count_at_least(
        &db,
        &workspace_id,
        message_count,
        Duration::from_millis(timeout_ms),
    );
    wait_for_runtime_idle(&db);
    drop(daemon);
    let setup_ms = setup_started.elapsed().as_millis();

    let before = assert_success(topo(&["--db", &db, "count"]));
    let retained_before = parse_count_value(&before, "facts");
    assert_eq!(
        content_message_count(&db, &workspace_id),
        message_count,
        "setup should fully project generated messages before replay"
    );

    let replay_started = Instant::now();
    let update_started = Instant::now();
    let update = assert_success(topo(&["--db", &db, "update"]));
    let update_ms = update_started.elapsed().as_millis();
    let pending_after_update = parse_count_value(&update, "pending_projection");
    assert_eq!(
        pending_after_update, 1,
        "CLI update should first queue the update fact; daemon projection performs the rebuild\n{update}"
    );
    let mut prepared_replay = 0;
    let mut prepare_ms = 0;
    if order.uses_manual_queue_setup() {
        let prepare_started = Instant::now();
        prepared_replay = prepare_ordered_replay_queue(&db, order, random_seed);
        prepare_ms = prepare_started.elapsed().as_millis();
        assert!(
            prepared_replay >= retained_before,
            "ordered replay setup should queue retained facts\nbefore={before}\nprepared={prepared_replay}"
        );
    }

    let drain_started = Instant::now();
    let replay_daemon = spawn_worker_daemon(&db);
    wait_for_content_count_at_least(
        &db,
        &workspace_id,
        message_count,
        Duration::from_millis(timeout_ms),
    );
    wait_for_runtime_idle(&db);
    let drain_ms = drain_started.elapsed().as_millis();
    drop(replay_daemon);
    let total_ms = replay_started.elapsed().as_millis();

    let after = assert_success(topo(&["--db", &db, "count"]));
    let retained_after = parse_count_value(&after, "facts");
    let applied_after = parse_count_value(&after, "applied_facts");
    let pending_intents_after = parse_count_value(&after, "pending_intents");
    assert_eq!(
        retained_after, applied_after,
        "replay should drain:\n{after}"
    );
    assert_eq!(
        pending_intents_after, 0,
        "replay should drain intents:\n{after}"
    );
    assert_eq!(
        content_message_count(&db, &workspace_id),
        message_count,
        "replay should rebuild generated message rows"
    );

    let replayed_retained_facts = if order.uses_manual_queue_setup() {
        prepared_replay
    } else {
        retained_after
    };
    let drain_seconds = (drain_ms as f64 / 1000.0).max(0.001);
    let total_seconds = (total_ms as f64 / 1000.0).max(0.001);
    let drain_facts_per_second = replayed_retained_facts as f64 / drain_seconds;
    let total_facts_per_second = replayed_retained_facts as f64 / total_seconds;
    let drain_messages_per_second = message_count as f64 / drain_seconds;
    eprintln!(
        "black_box_replay_generated_messages_perf order={} messages={} message_text_bytes={} setup_ms={} update_ms={} prepare_ms={} drain_ms={} total_ms={} retained_before={} retained_after={} pending_after_update={} prepared_replay={} replayed_retained_facts={} drain_facts_per_s={:.2} total_facts_per_s={:.2} drain_messages_per_s={:.2} random_seed={} generate_profile={}",
        order.as_str(),
        message_count,
        message_text_bytes,
        setup_ms,
        update_ms,
        prepare_ms,
        drain_ms,
        total_ms,
        retained_before,
        retained_after,
        pending_after_update,
        prepared_replay,
        replayed_retained_facts,
        drain_facts_per_second,
        total_facts_per_second,
        drain_messages_per_second,
        random_seed,
        stderr(&generated).trim()
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayPerfOrder {
    Runtime,
    Reverse,
    Random,
}

impl ReplayPerfOrder {
    fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Reverse => "reverse",
            Self::Random => "random",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "runtime" | "normal" => Self::Runtime,
            "reverse" => Self::Reverse,
            "random" => Self::Random,
            other => panic!(
                "unknown TOPO_REPLAY_PERF_ORDER {other:?}; expected runtime, reverse, random, or all"
            ),
        }
    }

    fn uses_manual_queue_setup(self) -> bool {
        !matches!(self, Self::Runtime)
    }
}

fn replay_perf_orders() -> Vec<ReplayPerfOrder> {
    let configured =
        std::env::var("TOPO_REPLAY_PERF_ORDER").unwrap_or_else(|_| "runtime".to_string());
    let orders = configured
        .split(',')
        .flat_map(|value| {
            let value = value.trim().to_ascii_lowercase();
            if value.is_empty() {
                Vec::new()
            } else if value == "all" {
                vec![
                    ReplayPerfOrder::Runtime,
                    ReplayPerfOrder::Reverse,
                    ReplayPerfOrder::Random,
                ]
            } else {
                vec![ReplayPerfOrder::parse(&value)]
            }
        })
        .collect::<Vec<_>>();
    if orders.is_empty() {
        vec![ReplayPerfOrder::Runtime]
    } else {
        orders
    }
}

fn prepare_ordered_replay_queue(db: &str, order: ReplayPerfOrder, random_seed: u64) -> usize {
    let mut conn = Connection::open(db).expect("open replay perf db");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("set busy timeout");
    let tx = conn.transaction().expect("begin replay queue setup");
    for table in replay_reset_table_names() {
        if sqlite_table_exists(&tx, table) {
            tx.execute(&format!("DELETE FROM {}", quote_ident(table)), [])
                .unwrap_or_else(|err| panic!("clear replay reset table {table}: {err}"));
        }
    }
    tx.execute(
        "INSERT OR IGNORE INTO pending_projection (owner, queued_at, priority, replay)
         SELECT f.id, m.received_at, 100, 1
         FROM facts f
         JOIN local_fact_admissions m ON m.fact_id = f.id",
        [],
    )
    .expect("queue retained facts for replay");

    let mut owners = pending_projection_owners(&tx);
    match order {
        ReplayPerfOrder::Runtime => {}
        ReplayPerfOrder::Reverse => owners.reverse(),
        ReplayPerfOrder::Random => {
            owners.sort_by_key(|owner| replay_random_key(owner, random_seed))
        }
    }
    for (queued_at, owner) in owners.iter().enumerate() {
        tx.execute(
            "UPDATE pending_projection
             SET queued_at = ?1,
                 priority = 100,
                 replay = 1
             WHERE owner = ?2",
            params![queued_at as i64, owner.as_slice()],
        )
        .expect("rewrite replay queue order");
    }
    let queued = owners.len();
    tx.commit().expect("commit replay queue setup");
    queued
}

fn replay_reset_table_names() -> Vec<&'static str> {
    let mut names = BTreeSet::new();
    names.extend(
        topo::core::schema::CORE_SCHEMA_SOURCE
            .replay
            .reset
            .iter()
            .map(|table| table.as_str()),
    );
    for source in topo::protocol::app::CONTEXT_RUNTIME.schema_sources {
        names.extend(source.replay.reset.iter().map(|table| table.as_str()));
    }
    names.into_iter().collect()
}

fn sqlite_table_exists(tx: &rusqlite::Transaction<'_>, table: &str) -> bool {
    tx.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
            UNION ALL
            SELECT 1 FROM sqlite_temp_master WHERE type = 'table' AND name = ?1
         )",
        params![table],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .unwrap_or(false)
}

fn pending_projection_owners(tx: &rusqlite::Transaction<'_>) -> Vec<Vec<u8>> {
    let mut stmt = tx
        .prepare(
            "SELECT owner
             FROM pending_projection
             ORDER BY priority, queued_at, owner",
        )
        .expect("prepare replay queue order query");
    stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query replay queue owners")
        .map(|row| row.expect("replay queue owner"))
        .collect()
}

fn replay_random_key(owner: &[u8], seed: u64) -> (u64, Vec<u8>) {
    let mut hash = seed ^ 0xcbf2_9ce4_8422_2325;
    for byte in owner {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    (hash, owner.to_vec())
}

fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn area_line(summary: &str, area: &str) -> String {
    summary
        .lines()
        .find(|line| line.starts_with(&format!("area_{area}:")))
        .unwrap_or_else(|| panic!("state-summary missing area {area}:\n{summary}"))
        .to_string()
}

fn wait_for_content_count_at_least(
    db: &str,
    workspace_id: &str,
    expected: usize,
    timeout: Duration,
) {
    let started = Instant::now();
    loop {
        let output = topo(&["--db", db, "content-count", workspace_id]);
        let last = if output.status.success() {
            let out = stdout(&output);
            if parse_count_value(&out, "content_messages") >= expected {
                return;
            }
            out
        } else {
            stderr(&output)
        };
        assert!(
            started.elapsed() < timeout,
            "content count did not reach {expected} within {:?}:\n{last}",
            timeout
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn content_message_count(db: &str, workspace_id: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "content-count", workspace_id]));
    parse_count_value(&out, "content_messages")
}

fn parse_count_value(output: &str, key: &str) -> usize {
    line_value(output, key)
        .parse()
        .unwrap_or_else(|err| panic!("parse {key} from output as usize: {err}\n{output}"))
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().expect("usize env var"))
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().expect("u64 env var"))
}

fn area_count(summary: &str, area: &str) -> u64 {
    let line = area_line(summary, area);
    line.split_whitespace()
        .nth(1)
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("state-summary area {area} count is invalid: {line}"))
}

fn wait_for_area_count_at_least(db: &str, area: &str, expected_min: u64) -> String {
    let mut last = String::new();
    for _ in 0..40 {
        let output = topo(&["--db", db, "state-summary"]);
        if output.status.success() {
            let summary = stdout(&output);
            if area_count(&summary, area) >= expected_min {
                return summary;
            }
            last = summary;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("state-summary area {area} did not reach {expected_min}:\n{last}");
}

#[test]
fn update_rebuild_preserves_key_material_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let daemon_port = free_port();
    let _daemon = spawn_daemon(&db, daemon_port);
    let workspace_id = create_workspace(&db, "Keys", "alice", "laptop");
    create_local_content_key(&db, &workspace_id);
    assert_success(topo(&["--db", &db, "key-recipient", &workspace_id]));
    assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "secret message",
    ]));
    wait_for_runtime_idle(&db);

    let summary_before = wait_for_area_count_at_least(&db, "key_wrap_rows", 1);
    let key_wrap_before = area_line(&summary_before, "key_wrap_rows");
    // The recipient scenario materializes at least one key wrap.
    let key_wrap_count = area_count(&summary_before, "key_wrap_rows");
    assert!(key_wrap_count > 0, "{key_wrap_before}");
    assert_success(topo(&["--db", &db, "update"]));
    wait_for_runtime_idle(&db);

    let summary_after = assert_success(topo(&["--db", &db, "state-summary"]));
    assert_eq!(
        area_line(&summary_after, "key_wrap_rows"),
        key_wrap_before,
        "key wrap rows must be byte-identical after update rebuild"
    );
}

#[test]
fn state_summary_is_stable_and_exposes_per_area_digests() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let first = assert_success(topo(&["--db", &db, "state-summary"]));
    let second = assert_success(topo(&["--db", &db, "state-summary"]));
    assert_eq!(first, second, "state summary is a stable read");
    assert!(
        first.lines().any(|line| line.starts_with("area_facts:")),
        "state summary exposes the retained facts area: {first}"
    );
    assert!(
        first
            .lines()
            .any(|line| line.starts_with("area_content_messages:")),
        "state summary exposes the materialized message rows area: {first}"
    );
    // Volatile scheduler/socket state is excluded from the digest areas.
    assert!(
        !first
            .lines()
            .any(|line| line.starts_with("area_network_outgoing:")
                || line.starts_with("area_intents:")
                || line.starts_with("area_pending_projection:")),
        "state summary must exclude volatile scheduler and socket state: {first}"
    );
}
