mod cli_harness;

use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use cli_harness::{assert_success, spawn_con, topo, wait_success};
use topo::core::runtime::RuntimeTurnLock;

#[test]
fn runtime_turn_lock_serializes_process_turns() {
    let tmp = tempfile::tempdir().expect("tmp");
    let db = tmp.path().join("turn.db");
    let first = RuntimeTurnLock::acquire(&db).expect("first lock");
    let (tx, rx) = mpsc::channel();
    let contender_db = db.clone();

    let waiter = thread::spawn(move || {
        let _second = RuntimeTurnLock::acquire(&contender_db).expect("second lock");
        tx.send(()).expect("send acquired");
    });

    thread::sleep(Duration::from_millis(100));
    assert!(
        rx.try_recv().is_err(),
        "second runtime turn should block while the first is held"
    );

    drop(first);
    rx.recv_timeout(Duration::from_secs(2))
        .expect("second lock should acquire after first drops");
    waiter.join().expect("waiter join");
}

#[test]
fn normal_cli_commands_wait_for_the_runtime_turn() {
    assert_success(topo(&["--help"]));

    let tmp = tempfile::tempdir().expect("tmp");
    let db = tmp.path().join("cli-turn.db");
    let db = db.to_string_lossy().to_string();
    let turn = RuntimeTurnLock::acquire(Path::new(&db)).expect("lock");

    let mut child = spawn_con(&["--db", &db, "count"]);
    thread::sleep(Duration::from_millis(150));
    assert!(
        child.try_wait().expect("try wait").is_none(),
        "CLI command should wait for the held runtime turn"
    );

    drop(turn);
    let output = wait_success(child, "count");
    assert!(output.contains("facts:"), "{output}");
}
