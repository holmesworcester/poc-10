use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use topo::core::daemon::RuntimeTurnLock;

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
