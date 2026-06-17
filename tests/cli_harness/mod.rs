#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub fn topo(args: &[&str]) -> Output {
    con_cli(args)
}

pub fn topo_at(db: &str, at_ms: &str, command: &[&str]) -> Output {
    let mut args = vec!["--db", db, "--at", at_ms];
    args.extend_from_slice(command);
    con_cli(&args)
}

pub fn con_cli(args: &[&str]) -> Output {
    Command::new(con_bin())
        .args(args)
        .output()
        .expect("run con")
}

pub fn con_cli_with_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(con_bin());
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("run con")
}

pub fn spawn_topo(args: &[&str]) -> Child {
    spawn_con(args)
}

pub fn spawn_con(args: &[&str]) -> Child {
    Command::new(con_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn con")
}

pub fn spawn_topo_with_stderr_file(args: &[&str], stderr_path: &Path) -> Child {
    spawn_con_with_stderr_file(args, stderr_path)
}

pub fn spawn_con_with_stderr_file(args: &[&str], stderr_path: &Path) -> Child {
    if let Some(parent) = stderr_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).expect("create daemon stderr log dir");
    }
    let stderr = File::create(stderr_path).expect("create daemon stderr log");
    Command::new(con_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn con")
}

fn con_bin() -> &'static Path {
    static CON_BIN: OnceLock<PathBuf> = OnceLock::new();
    CON_BIN.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target_dir = manifest_dir.join("target").join("cli-black-box");
        let profile = std::env::var("TOPO_CLI_PROFILE").unwrap_or_else(|_| "release".to_string());
        assert!(
            profile == "release" || profile == "debug",
            "TOPO_CLI_PROFILE must be `release` or `debug`"
        );
        let mut build = Command::new("cargo");
        build
            .arg("build")
            .arg("--quiet")
            .arg("--bin")
            .arg("con")
            .arg("--manifest-path")
            .arg(manifest_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir);
        if profile == "release" {
            build.arg("--release");
        }
        let status = build.status().expect("build con binary");
        assert!(status.success(), "build con binary");
        target_dir.join(profile).join("con")
    })
}

pub fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    stdout(&output)
}

pub fn wait_success(child: Child, label: &str) -> String {
    let output = child.wait_with_output().expect("wait for child");
    assert!(
        output.status.success(),
        "{label} failed\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    stdout(&output)
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

pub fn free_port() -> u16 {
    for _ in 0..20_000 {
        let port = next_port_candidate();
        if TcpListener::bind(("127.0.0.1", port as u16)).is_ok() {
            return port as u16;
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn next_port_candidate() -> usize {
    // Keep daemon listener ports below Linux's default ephemeral client-port
    // range (typically 32768-60999). The black-box sync tests open many
    // loopback client connections in parallel, and allocating listeners from
    // that same range can race with the kernel's outgoing port selection.
    const MIN_PORT: usize = 20000;
    const MAX_PORT: usize = 32767;
    static FALLBACK_NEXT_PORT: OnceLock<AtomicUsize> = OnceLock::new();

    let path = std::env::temp_dir().join("poc10-cli-test-port-counter");
    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
    else {
        return FALLBACK_NEXT_PORT
            .get_or_init(|| AtomicUsize::new(MIN_PORT))
            .fetch_add(1, Ordering::Relaxed);
    };
    let Ok(_lock) = FileLock::exclusive(&file) else {
        return FALLBACK_NEXT_PORT
            .get_or_init(|| AtomicUsize::new(MIN_PORT))
            .fetch_add(1, Ordering::Relaxed);
    };

    let mut text = String::new();
    let _ = file.read_to_string(&mut text);
    let candidate = text
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|port| (MIN_PORT..=MAX_PORT).contains(port))
        .unwrap_or(MIN_PORT);
    let next = if candidate >= MAX_PORT {
        MIN_PORT
    } else {
        candidate + 1
    };

    file.set_len(0).expect("truncate port counter");
    file.seek(SeekFrom::Start(0)).expect("rewind port counter");
    write!(file, "{next}").expect("write port counter");
    candidate
}

struct FileLock {
    fd: std::os::fd::RawFd,
}

impl FileLock {
    fn exclusive(file: &std::fs::File) -> std::io::Result<Self> {
        let fd = file.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc == 0 {
            Ok(Self { fd })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.fd, libc::LOCK_UN) };
    }
}

pub fn temp_db(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}

pub fn daemon_lock_path(db: &str) -> PathBuf {
    sibling_file_name_path(Path::new(db), ".daemon.lock", "daemon.lock")
}

pub fn daemon_stderr_path(db: &str) -> PathBuf {
    sibling_file_name_path(Path::new(db), ".daemon.stderr", "daemon.stderr")
}

pub fn daemon_diagnostics(label: &str, db: &str) -> String {
    let lock_path = daemon_lock_path(db);
    let stderr_path = daemon_stderr_path(db);
    let mut lines = vec![
        format!("{label} daemon diagnostics:"),
        format!("db_path: {db}"),
        format!("lock_path: {}", lock_path.display()),
    ];

    match fs::read_to_string(&lock_path) {
        Ok(lock) => {
            let mut lock_lines = lock.lines();
            let pid_text = lock_lines.next().unwrap_or("").trim();
            let addr_text = lock_lines.next().unwrap_or("").trim();
            lines.push(format!(
                "lock_pid: {}",
                if pid_text.is_empty() {
                    "<missing>"
                } else {
                    pid_text
                }
            ));
            if !addr_text.is_empty() {
                lines.push(format!("lock_addr: {addr_text}"));
            }
            match pid_text.parse::<u32>() {
                Ok(pid) if pid > 0 => lines.push(format!("process_alive: {}", process_alive(pid))),
                _ => lines.push("process_alive: unknown (invalid lock pid)".to_string()),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            lines.push("lock_state: missing".to_string());
        }
        Err(err) => {
            lines.push(format!("lock_state: unreadable ({err})"));
        }
    }

    lines.push(format!("stderr_path: {}", stderr_path.display()));
    lines.push(format!("stderr_tail:\n{}", file_tail(&stderr_path, 4096)));
    lines.join("\n")
}

pub fn daemon_diagnostics_block(daemons: &[(&str, &str)]) -> String {
    daemons
        .iter()
        .map(|(label, db)| daemon_diagnostics(label, db))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn sibling_file_name_path(path: &Path, suffix: &str, fallback: &str) -> PathBuf {
    let mut sibling = path.to_path_buf();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}{suffix}"))
        .unwrap_or_else(|| fallback.to_string());
    sibling.set_file_name(name);
    sibling
}

fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn file_tail(path: &Path, max_bytes: usize) -> String {
    match fs::read(path) {
        Ok(bytes) => {
            let start = bytes.len().saturating_sub(max_bytes);
            String::from_utf8_lossy(&bytes[start..]).to_string()
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => "<missing>".to_string(),
        Err(err) => format!("<read error: {err}>"),
    }
}

pub fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}:` in output:\n{output}"))
        .to_string()
}
