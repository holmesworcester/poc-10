mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn invite_listens_and_accept_connects_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let port = free_port();

    let mut listener = spawn_invite_listener(&host, port, 1);
    let invite = listener.invite_link();
    let accepted = accept_with_retry(&joiner, &invite);
    assert!(accepted.contains("connected:"), "{accepted}");

    let host_out = listener.wait_success("single invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
    assert_eq!(connection_count(&host), 1);
    assert_eq!(connection_count(&joiner), 1);
    assert_eq!(connection_event_count(&host), 2);
    assert_eq!(connection_event_count(&joiner), 2);
}

#[test]
fn invite_listens_for_two_separate_accepting_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner_a = temp_db(&tmp, "joiner-a.db");
    let joiner_b = temp_db(&tmp, "joiner-b.db");
    let port = free_port();

    let mut listener = spawn_invite_listener(&host, port, 2);
    let invite = listener.invite_link();

    let accepted_a = accept_with_retry(&joiner_a, &invite);
    assert!(accepted_a.contains("connected:"), "{accepted_a}");
    let accepted_b = accept_with_retry(&joiner_b, &invite);
    assert!(accepted_b.contains("connected:"), "{accepted_b}");

    let host_out = listener.wait_success("two-accept invite listener");
    assert!(host_out.contains("accepted_connections: 2"), "{host_out}");
    assert_eq!(connection_count(&host), 2);
    assert_eq!(connection_count(&joiner_a), 1);
    assert_eq!(connection_count(&joiner_b), 1);
    assert_eq!(connection_event_count(&host), 4);
    assert_eq!(connection_event_count(&joiner_a), 2);
    assert_eq!(connection_event_count(&joiner_b), 2);
}

struct ListeningInvite {
    child: Child,
    invite_rx: Receiver<Result<String, String>>,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

impl ListeningInvite {
    fn invite_link(&mut self) -> String {
        match self.invite_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => {
                assert!(
                    line.starts_with("topo://invite/"),
                    "missing invite link in first listener line: {line}"
                );
                line
            }
            Ok(Err(err)) => {
                let _ = self.child.kill();
                panic!("listener did not print invite link: {err}");
            }
            Err(err) => {
                let _ = self.child.kill();
                panic!("timed out waiting for invite link: {err}");
            }
        }
    }

    fn wait_success(mut self, label: &str) -> String {
        let status = self.child.wait().expect("wait for listener");
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        assert!(
            status.success(),
            "{label} failed\nstdout={stdout}\nstderr={stderr}"
        );
        stdout
    }
}

fn spawn_invite_listener(db: &str, port: u16, accept: usize) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    let stdout = child.stdout.take().expect("listener stdout");
    let stderr = child.stderr.take().expect("listener stderr");
    let (invite_tx, invite_rx) = mpsc::channel();
    let stdout = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut output = String::new();
        let mut first = String::new();
        match reader.read_line(&mut first) {
            Ok(0) => {
                let _ = invite_tx.send(Err("stdout closed before first line".to_string()));
            }
            Ok(_) => {
                output.push_str(&first);
                let link = first.trim_end_matches(['\r', '\n']).to_string();
                let _ = invite_tx.send(Ok(link));
            }
            Err(err) => {
                let _ = invite_tx.send(Err(err.to_string()));
            }
        }

        let mut rest = String::new();
        if reader.read_to_string(&mut rest).is_ok() {
            output.push_str(&rest);
        }
        output
    });
    let stderr = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut output = String::new();
        let _ = reader.read_to_string(&mut output);
        output
    });
    ListeningInvite {
        child,
        invite_rx,
        stdout,
        stderr,
    }
}

fn accept_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "accept", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded: {last}");
}

fn connection_count(db: &str) -> usize {
    count_value(db, "connections")
}

fn connection_event_count(db: &str) -> usize {
    count_value(db, "connection_events")
}

fn count_value(db: &str, key: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, key).parse().expect("parse count value")
}
