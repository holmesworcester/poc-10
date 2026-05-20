#![allow(dead_code)]

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub fn topo(args: &[&str]) -> Output {
    match_cli(args)
}

pub fn match_cli(args: &[&str]) -> Output {
    Command::new(match_bin())
        .args(args)
        .output()
        .expect("run match")
}

pub fn spawn_topo(args: &[&str]) -> Child {
    spawn_match(args)
}

pub fn spawn_match(args: &[&str]) -> Child {
    Command::new(match_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn match")
}

fn match_bin() -> &'static Path {
    static MATCH_BIN: OnceLock<PathBuf> = OnceLock::new();
    MATCH_BIN.get_or_init(|| {
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
            .arg("match")
            .arg("--manifest-path")
            .arg(manifest_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir);
        if profile == "release" {
            build.arg("--release");
        }
        let status = build.status().expect("build match binary");
        assert!(status.success(), "build match binary");
        target_dir.join(profile).join("match")
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
    const MIN_PORT: usize = 42000;
    const MAX_PORT: usize = 61000;
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

pub fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}:` in output:\n{output}"))
        .to_string()
}
