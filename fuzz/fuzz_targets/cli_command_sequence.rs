#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use topo::core::cli::{self, CliOutput};
use topo::core::runtime::Runtime;
use topo::protocol::app::MATCH_RUNTIME;
use topo::protocol::registry::{MatchCliContext, MATCH_COMMANDS};

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let db = FuzzDb::new();
    let Ok(mut state) = bootstrap(db.path()) else {
        return;
    };

    let steps = 4 + usize::from(data.first().copied().unwrap_or_default() & 3);
    for step in 0..steps {
        let chunk = command_bytes(data, step);
        exercise_step(db.path(), &mut state, &chunk, step);
    }
});

#[derive(Debug)]
struct CliState {
    workspace_id: String,
    recipient_key_id: String,
    removal_frontier_id: String,
    expected_messages: usize,
}

fn bootstrap(db: &Path) -> Result<CliState, String> {
    let created = run_command(
        db,
        &[
            "create-workspace",
            "fuzz-workspace",
            "--username",
            "fuzz-user",
            "--devicename",
            "fuzz-device",
        ],
    )?;
    let workspace_id = line_value(&created, "workspace_id")?;
    let recipient = run_command(db, &["key-recipient", &workspace_id])?;
    let recipient_key_id = line_value(&recipient, "recipient_key_id")?;
    let frontier = run_command(db, &["key-frontier", &workspace_id])?;
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id")?;
    let _ = run_command(
        db,
        &[
            "key-wrap",
            &workspace_id,
            &removal_frontier_id,
            &recipient_key_id,
        ],
    );
    run_command(db, &["send", &workspace_id, "seed-message"])?;

    let state = CliState {
        workspace_id,
        recipient_key_id,
        removal_frontier_id,
        expected_messages: 1,
    };
    assert_content_count_at_least(db, &state);
    Ok(state)
}

fn exercise_step(db: &Path, state: &mut CliState, data: &[u8], step: usize) {
    let op = data.first().copied().unwrap_or_default() % 14;
    let workspace_arg = choose_id(data, 1, &state.workspace_id);
    let frontier_arg = choose_id(data, 2, &state.removal_frontier_id);
    let recipient_arg = choose_id(data, 3, &state.recipient_key_id);

    match op {
        0 => {
            let _ = run_command(db, &["workspaces"]);
        }
        1 => {
            let _ = run_command(db, &["users", &workspace_arg]);
        }
        2 => {
            let _ = run_command(db, &["count"]);
        }
        3 => {
            if let Ok(output) = run_command(db, &["key-recipient", &workspace_arg]) {
                if let Ok(id) = line_value(&output, "recipient_key_id") {
                    state.recipient_key_id = id;
                }
            }
        }
        4 => {
            if let Ok(output) = run_command(db, &["key-frontier", &workspace_arg]) {
                if let Ok(id) = line_value(&output, "removal_frontier_id") {
                    state.removal_frontier_id = id;
                }
            }
        }
        5 => {
            let _ = run_command(
                db,
                &["key-wrap", &workspace_arg, &frontier_arg, &recipient_arg],
            );
        }
        6 => {
            let _ = run_command(db, &["key-access", &workspace_arg, &frontier_arg]);
        }
        7 => {
            let text = fuzz_text(data, step);
            if run_command(db, &["send", &workspace_arg, &text]).is_ok()
                && workspace_arg == state.workspace_id
            {
                state.expected_messages = state.expected_messages.saturating_add(1);
                assert_content_count_at_least(db, state);
                let messages = run_command(db, &["messages", &state.workspace_id])
                    .expect("successful send should leave messages queryable");
                assert!(
                    output_text(&messages).contains(&text),
                    "messages output did not include sent text `{text}`:\n{}",
                    output_text(&messages)
                );
            }
        }
        8 => {
            let count = bounded_decimal(data.get(4).copied(), 1, 4);
            let text_bytes = bounded_decimal(data.get(5).copied(), 1, 32);
            if run_command(db, &["generate", &workspace_arg, &count, &text_bytes]).is_ok()
                && workspace_arg == state.workspace_id
            {
                let generated = count.parse::<usize>().unwrap_or(1);
                state.expected_messages = state.expected_messages.saturating_add(generated);
                assert_content_count_at_least(db, state);
            }
        }
        9 => {
            let _ = run_command(db, &["messages", &workspace_arg]);
        }
        10 => {
            let _ = run_command(db, &["content-count", &workspace_arg]);
        }
        11 => {
            let emoji = if data.get(4).copied().unwrap_or_default() & 1 == 0 {
                "+"
            } else {
                "*"
            };
            let _ = run_command(db, &["react", &workspace_arg, "1", emoji]);
        }
        12 => {
            let limit = bounded_decimal(data.get(5).copied(), 0, 8);
            if limit == "0" {
                let _ = run_command(db, &["key-derive"]);
            } else {
                let _ = run_command(db, &["key-derive", &limit]);
            }
        }
        _ => {
            let _ = run_command(db, &["clock"]);
        }
    }
}

fn command_bytes(data: &[u8], step: usize) -> [u8; 8] {
    let mut out = [0; 8];
    for (index, byte) in out.iter_mut().enumerate() {
        let salt = (step as u8)
            .wrapping_mul(31)
            .wrapping_add(index as u8)
            .rotate_left((index % 8) as u32);
        *byte = data
            .get((step * 5 + index) % data.len().max(1))
            .copied()
            .unwrap_or_default()
            ^ salt;
    }
    out
}

fn run_command(db: &Path, args: &[&str]) -> Result<CliOutput, String> {
    let runtime = Runtime::open_disk(&MATCH_RUNTIME, db)?;
    let mut context = MatchCliContext::new(runtime, Some(db.to_path_buf()));
    let owned = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    cli::run("con", MATCH_COMMANDS, &mut context, &owned)
}

fn assert_content_count_at_least(db: &Path, state: &CliState) {
    let output = run_command(db, &["content-count", &state.workspace_id])
        .expect("content-count should work after successful content command");
    let observed = line_value(&output, "content_messages")
        .expect("content-count should report content_messages")
        .parse::<usize>()
        .expect("content_messages should be numeric");
    assert!(
        observed >= state.expected_messages,
        "content-count moved backward: observed {observed}, expected at least {}\n{}",
        state.expected_messages,
        output_text(&output)
    );
}

fn choose_id(data: &[u8], offset: usize, valid: &str) -> String {
    if data.get(offset).copied().unwrap_or_default() & 3 == 0 {
        hex_id(data, offset + 1)
    } else {
        valid.to_string()
    }
}

fn hex_id(data: &[u8], offset: usize) -> String {
    let mut out = String::with_capacity(64);
    for index in 0..32 {
        let byte = data
            .get((offset + index) % data.len().max(1))
            .copied()
            .unwrap_or(index as u8);
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte));
    }
    out
}

fn hex_digit(value: u8) -> char {
    b"0123456789abcdef"[(value & 0x0f) as usize] as char
}

fn bounded_decimal(value: Option<u8>, min: usize, max: usize) -> String {
    let span = max.saturating_sub(min).saturating_add(1);
    let value = usize::from(value.unwrap_or_default()) % span + min;
    value.to_string()
}

fn fuzz_text(data: &[u8], step: usize) -> String {
    let mut text = format!("m{step}");
    for byte in data.iter().copied().skip(1).take(6) {
        let ch = b'a' + (byte % 26);
        text.push(ch as char);
    }
    text
}

fn line_value(output: &CliOutput, key: &str) -> Result<String, String> {
    let prefix = format!("{key}: ");
    output
        .lines
        .iter()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_string)
        .ok_or_else(|| format!("missing `{key}:` in output:\n{}", output_text(output)))
}

fn output_text(output: &CliOutput) -> String {
    output.lines.join("\n")
}

struct FuzzDb {
    path: PathBuf,
}

impl FuzzDb {
    fn new() -> Self {
        let id = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "topo-cli-sequence-fuzz-{}-{id}.db",
            std::process::id()
        ));
        cleanup_db(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FuzzDb {
    fn drop(&mut self) {
        cleanup_db(&self.path);
    }
}

fn cleanup_db(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(sibling(path, "-wal"));
    let _ = std::fs::remove_file(sibling(path, "-shm"));
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}
