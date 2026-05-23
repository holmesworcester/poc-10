#!/usr/bin/env python3
"""Run apples-to-apples-ish perf comparisons across poc-7, poc-8, and poc-10.

The runner intentionally reports only measured command output. When a worktree
does not have an equivalent harness, it records a skipped row with the reason.
Results are written under target/perf-compare/, which is ignored by git.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_WORKTREES = {
    "poc7": Path("/home/holmes/poc-7"),
    "poc8": Path("/home/holmes/poc-8"),
    "poc10": Path("/home/holmes/poc-10"),
}

PROJECTION_TESTS = {
    1_000: "messages_1k_projection_perf",
    10_000: "messages_10k_projection_perf",
    100_000: "messages_100k_projection_perf",
    500_000: "messages_500k_projection_perf",
}

METRIC_LINE = re.compile(
    r"^(perf messages |perf file |black_box_cascade_|=== |"
    r"\s+(Wall time|Messages|Msgs/s|Peak RSS|Cascade rate|Setup|Blocking|Cascade|Total):)"
)


@dataclass
class Result:
    suite: str
    worktree: str
    status: str
    command: list[str] = field(default_factory=list)
    cwd: str | None = None
    wall_seconds: float | None = None
    returncode: int | None = None
    summary: list[str] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "suite": self.suite,
            "worktree": self.worktree,
            "status": self.status,
            "command": self.command,
            "cwd": self.cwd,
            "wall_seconds": self.wall_seconds,
            "returncode": self.returncode,
            "summary": self.summary,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "reason": self.reason,
        }


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.results: list[Result] = []
        self.repo_root = Path(__file__).resolve().parents[1]
        self.out_dir = self.repo_root / "target" / "perf-compare"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.worktrees = {
            "poc7": Path(args.poc7).resolve(),
            "poc8": Path(args.poc8).resolve(),
            "poc10": Path(args.poc10).resolve(),
        }

    def run(self) -> None:
        suites = set(self.args.only)
        if "projection" in suites:
            self.run_projection()
        if "sync" in suites:
            self.run_sync()
        if "encryption-display" in suites:
            self.run_encryption_display()
        if "cascade" in suites:
            self.run_cascade()
        self.write_results()

    def command(
        self,
        suite: str,
        worktree_key: str,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> Result:
        worktree = self.worktrees[worktree_key]
        cwd = cwd or worktree
        rendered = shlex.join(command)
        print(f"\n[{suite}] {worktree_key}: {rendered}", flush=True)
        if self.args.dry_run:
            result = Result(
                suite=suite,
                worktree=worktree_key,
                status="dry-run",
                command=command,
                cwd=str(cwd),
            )
            self.results.append(result)
            return result

        started = time.perf_counter()
        proc = subprocess.run(
            command,
            cwd=cwd,
            env={**os.environ, **(env or {})},
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        wall = time.perf_counter() - started
        combined = proc.stdout + proc.stderr
        summary = extract_summary_lines(combined)
        for line in summary:
            print(f"  {line}", flush=True)
        print(f"  wall_seconds={wall:.3f} status={proc.returncode}", flush=True)
        result = Result(
            suite=suite,
            worktree=worktree_key,
            status="pass" if proc.returncode == 0 else "fail",
            command=command,
            cwd=str(cwd),
            wall_seconds=wall,
            returncode=proc.returncode,
            summary=summary,
            stdout_tail=tail(proc.stdout),
            stderr_tail=tail(proc.stderr),
        )
        self.results.append(result)
        if proc.returncode != 0 and not self.args.keep_going:
            self.write_results()
            raise SystemExit(proc.returncode)
        return result

    def skip(self, suite: str, worktree_key: str, reason: str) -> None:
        print(f"\n[{suite}] {worktree_key}: SKIP - {reason}", flush=True)
        self.results.append(
            Result(suite=suite, worktree=worktree_key, status="skip", reason=reason)
        )

    def run_projection(self) -> None:
        suite = "projection"
        test_name = PROJECTION_TESTS.get(self.args.messages)
        if test_name is None:
            supported = ", ".join(str(value) for value in sorted(PROJECTION_TESTS))
            for key in self.worktrees:
                self.skip(suite, key, f"message count must match an existing test: {supported}")
            return

        self.skip(
            suite,
            "poc7",
            "no equivalent 100k message projection harness found during inspection",
        )
        for key in ["poc8", "poc10"]:
            self.command(
                suite,
                key,
                [
                    "cargo",
                    "test",
                    "--release",
                    "--test",
                    "perf_projection_test",
                    test_name,
                    "--",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ],
                timeout=self.args.command_timeout,
            )

    def run_sync(self) -> None:
        suite = "sync"
        # poc-7 already has a daemon sync perf harness. poc-8/poc-10 do not, so
        # use the same black-box CLI flow for both newer worktrees.
        if self.args.sync_messages >= 50_000:
            test_name = "perf_sync_50k"
            ignored = ["--ignored"]
        else:
            test_name = "perf_sync_10k"
            ignored = []
        self.command(
            suite,
            "poc7",
            [
                "cargo",
                "test",
                "--release",
                "--test",
                "daemon_perf_test",
                test_name,
                "--",
                "--nocapture",
                *ignored,
                "--test-threads=1",
            ],
            timeout=self.args.command_timeout,
        )
        for key in ["poc8", "poc10"]:
            self.run_cli_sync(key, self.args.sync_messages)

    def run_encryption_display(self) -> None:
        suite = "encryption-display"
        self.skip(
            suite,
            "poc7",
            "no matching encrypted display CLI shape was added to this harness",
        )
        for key in ["poc8", "poc10"]:
            self.run_cli_encryption_display(key, self.args.display_messages)

    def run_cascade(self) -> None:
        suite = "cascade"
        if self.args.cascade_events == 10_000:
            p7_test = "topo_cascade_10k"
            ignored: list[str] = []
        elif self.args.cascade_events in {50_000, 200_000, 500_000}:
            p7_test = f"topo_cascade_{self.args.cascade_events // 1000}k"
            ignored = ["--ignored"]
        else:
            self.skip(
                suite,
                "poc7",
                "poc-7 cascade harness only exposes 10k, 50k, 200k, and 500k tests",
            )
            p7_test = ""
            ignored = []
        if p7_test:
            self.command(
                suite,
                "poc7",
                [
                    "cargo",
                    "test",
                    "--release",
                    "--test",
                    "topo_cascade_test",
                    p7_test,
                    "--",
                    "--nocapture",
                    *ignored,
                    "--test-threads=1",
                ],
                timeout=self.args.command_timeout,
            )

        if self.args.cascade_events == 10_000:
            test_name = "cascade_cli_replays_event_with_deps_out_of_order_and_unblocks_10k"
            ignored = []
        elif self.args.cascade_events == 50_000:
            test_name = "cascade_cli_replays_event_with_deps_out_of_order_and_unblocks_50k"
            ignored = ["--ignored"]
        else:
            for key in ["poc8", "poc10"]:
                self.skip(
                    suite,
                    key,
                    "CLI cascade tests expose 10k and 50k; add a new ignored test for this scale",
                )
            return
        for key in ["poc8", "poc10"]:
            self.command(
                suite,
                key,
                [
                    "cargo",
                    "test",
                    "--release",
                    "--test",
                    "cascade_cli_test",
                    test_name,
                    "--",
                    "--nocapture",
                    *ignored,
                    "--test-threads=1",
                ],
                timeout=self.args.command_timeout,
            )

    def run_cli_sync(self, worktree_key: str, message_count: int) -> None:
        suite = "sync"
        if self.args.dry_run:
            bin_name = binary_name(worktree_key)
            self.results.append(
                Result(
                    suite=suite,
                    worktree=worktree_key,
                    status="dry-run",
                    reason=(
                        f"would build {bin_name}, create two daemon DBs, generate "
                        f"{message_count} messages on alice, and wait for bob"
                    ),
                )
            )
            print(f"\n[{suite}] {worktree_key}: dry-run CLI sync {message_count}", flush=True)
            return

        worktree = self.worktrees[worktree_key]
        binary = self.build_cli(worktree_key)
        with tempfile.TemporaryDirectory(prefix=f"{worktree_key}-sync-") as tmp:
            tmp_path = Path(tmp)
            alice = tmp_path / "alice.db"
            bob = tmp_path / "bob.db"
            alice_port = free_port()
            bob_port = free_port()
            daemons: list[subprocess.Popen[str]] = []
            started = time.perf_counter()
            try:
                workspace = line_value(
                    run_cli(binary, worktree, "--db", alice, "create-workspace", "Perf Sync",
                            "--username", "alice", "--devicename", "alice-laptop"),
                    "workspace_id",
                )
                daemons.append(start_daemon(binary, worktree, alice, alice_port))
                daemons.append(start_daemon(binary, worktree, bob, bob_port))
                invite = invite_for(binary, worktree, alice, workspace, alice_port)
                accept_retry(binary, worktree, bob, invite, "bob", "bob-phone")
                wait_content(binary, worktree, bob, workspace, 0, self.args.sync_timeout)
                run_cli(binary, worktree, "--db", alice, "key-frontier", workspace)

                gen_started = time.perf_counter()
                run_cli(binary, worktree, "--db", alice, "generate", workspace,
                        str(message_count), str(self.args.event_size))
                gen_seconds = time.perf_counter() - gen_started

                sync_started = time.perf_counter()
                wait_content(binary, worktree, bob, workspace, message_count, self.args.sync_timeout)
                sync_seconds = time.perf_counter() - sync_started
                wall = time.perf_counter() - started
                rate = message_count / max(sync_seconds, 0.001)
                summary = [
                    f"cli_sync messages={message_count} event_size_bytes={self.args.event_size}",
                    f"generate_seconds={gen_seconds:.3f}",
                    f"sync_wait_seconds={sync_seconds:.3f}",
                    f"msgs_s={rate:.2f}",
                ]
                for line in summary:
                    print(f"  {line}", flush=True)
                self.results.append(
                    Result(
                        suite=suite,
                        worktree=worktree_key,
                        status="pass",
                        command=[str(binary), "... black-box sync scenario ..."],
                        cwd=str(worktree),
                        wall_seconds=wall,
                        returncode=0,
                        summary=summary,
                    )
                )
            except Exception as err:  # noqa: BLE001 - preserve failure in result.
                wall = time.perf_counter() - started
                self.results.append(
                    Result(
                        suite=suite,
                        worktree=worktree_key,
                        status="fail",
                        command=[str(binary), "... black-box sync scenario ..."],
                        cwd=str(worktree),
                        wall_seconds=wall,
                        returncode=1,
                        reason=str(err),
                    )
                )
                print(f"  failed: {err}", flush=True)
                if not self.args.keep_going:
                    raise
            finally:
                stop_daemons(daemons)

    def run_cli_encryption_display(self, worktree_key: str, message_count: int) -> None:
        suite = "encryption-display"
        if self.args.dry_run:
            self.results.append(
                Result(
                    suite=suite,
                    worktree=worktree_key,
                    status="dry-run",
                    reason=(
                        f"would send {message_count} encrypted messages and time "
                        "`messages WORKSPACE LIMIT`"
                    ),
                )
            )
            print(f"\n[{suite}] {worktree_key}: dry-run encrypted display {message_count}", flush=True)
            return

        worktree = self.worktrees[worktree_key]
        binary = self.build_cli(worktree_key)
        with tempfile.TemporaryDirectory(prefix=f"{worktree_key}-display-") as tmp:
            db = Path(tmp) / "alice.db"
            started = time.perf_counter()
            try:
                workspace = line_value(
                    run_cli(binary, worktree, "--db", db, "create-workspace", "Perf Display",
                            "--username", "alice", "--devicename", "alice-laptop"),
                    "workspace_id",
                )
                run_cli(binary, worktree, "--db", db, "key-frontier", workspace)
                send_started = time.perf_counter()
                for idx in range(message_count):
                    run_cli(binary, worktree, "--db", db, "send", workspace, f"perf-display-{idx}")
                send_seconds = time.perf_counter() - send_started

                display_started = time.perf_counter()
                out = run_cli(
                    binary,
                    worktree,
                    "--db",
                    db,
                    "messages",
                    workspace,
                    str(self.args.display_limit),
                )
                display_seconds = time.perf_counter() - display_started
                displayed = line_value(out, "messages")
                wall = time.perf_counter() - started
                summary = [
                    f"encrypted_display seeded_messages={message_count}",
                    f"send_seconds={send_seconds:.3f}",
                    f"display_limit={self.args.display_limit}",
                    f"displayed_messages={displayed}",
                    f"display_seconds={display_seconds:.3f}",
                ]
                for line in summary:
                    print(f"  {line}", flush=True)
                self.results.append(
                    Result(
                        suite=suite,
                        worktree=worktree_key,
                        status="pass",
                        command=[str(binary), "... encrypted display scenario ..."],
                        cwd=str(worktree),
                        wall_seconds=wall,
                        returncode=0,
                        summary=summary,
                    )
                )
            except Exception as err:  # noqa: BLE001
                wall = time.perf_counter() - started
                self.results.append(
                    Result(
                        suite=suite,
                        worktree=worktree_key,
                        status="fail",
                        command=[str(binary), "... encrypted display scenario ..."],
                        cwd=str(worktree),
                        wall_seconds=wall,
                        returncode=1,
                        reason=str(err),
                    )
                )
                print(f"  failed: {err}", flush=True)
                if not self.args.keep_going:
                    raise

    def build_cli(self, worktree_key: str) -> Path:
        worktree = self.worktrees[worktree_key]
        bin_name = binary_name(worktree_key)
        target = worktree / "target" / "perf-compare-cli"
        self.command(
            "build-cli",
            worktree_key,
            [
                "cargo",
                "build",
                "--release",
                "--bin",
                bin_name,
                "--target-dir",
                str(target),
            ],
            cwd=worktree,
            timeout=self.args.command_timeout,
        )
        return target / "release" / bin_name

    def write_results(self) -> None:
        json_path = self.out_dir / f"{self.run_id}.json"
        md_path = self.out_dir / f"{self.run_id}.md"
        payload = {
            "run_id": self.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "args": vars(self.args),
            "results": [result.as_dict() for result in self.results],
        }
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        md_path.write_text(render_markdown(self.results, self.run_id))
        print(f"\nwrote {json_path}")
        print(f"wrote {md_path}")


def extract_summary_lines(text: str) -> list[str]:
    lines = [line.rstrip() for line in text.splitlines()]
    summary = [line for line in lines if METRIC_LINE.search(line)]
    if summary:
        return summary[-40:]
    interesting = [line for line in lines if "test result:" in line or "error:" in line]
    return interesting[-20:]


def tail(text: str, max_chars: int = 4000) -> str:
    return text[-max_chars:]


def line_value(output: str, key: str) -> str:
    prefix = f"{key}: "
    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise RuntimeError(f"missing `{key}:` in output:\n{tail(output)}")


def binary_name(worktree_key: str) -> str:
    return "match" if worktree_key == "poc10" else "topo"


def run_cli(binary: Path, cwd: Path, *args: object, timeout: int = 120) -> str:
    command = [str(binary), *[str(arg) for arg in args]]
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {shlex.join(command)}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc.stdout


def start_daemon(binary: Path, cwd: Path, db: Path, port: int) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [
            str(binary),
            "--db",
            str(db),
            "start",
            "--listen",
            "127.0.0.1",
            str(port),
            "--sync-ms",
            "100",
            "--quiet-ms",
            "100",
        ],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line.startswith("listening: "):
            return proc
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr is not None else ""
            raise RuntimeError(f"daemon exited before listening: {line}{stderr}")
    proc.kill()
    raise RuntimeError("daemon did not print listening line")


def stop_daemons(daemons: Iterable[subprocess.Popen[str]]) -> None:
    for proc in daemons:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def invite_for(binary: Path, cwd: Path, db: Path, workspace: str, port: int) -> str:
    out = run_cli(
        binary,
        cwd,
        "--db",
        db,
        "invite",
        "--workspace",
        workspace,
        "--public-addr",
        f"127.0.0.1:{port}",
    )
    for line in out.splitlines():
        if line.startswith("topo://invite/"):
            return line
    raise RuntimeError(f"missing invite link in output:\n{out}")


def accept_retry(binary: Path, cwd: Path, db: Path, invite: str, username: str, device: str) -> str:
    last = ""
    for _ in range(200):
        proc = subprocess.run(
            [
                str(binary),
                "--db",
                str(db),
                "accept",
                invite,
                "--username",
                username,
                "--devicename",
                device,
            ],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return proc.stdout
        last = proc.stderr
        if "open tcp stream" not in last and "user invite was not received" not in last:
            break
        time.sleep(0.05)
    raise RuntimeError(f"accept failed: {last}")


def wait_content(
    binary: Path,
    cwd: Path,
    db: Path,
    workspace: str,
    expected: int,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last = ""
    while time.monotonic() < deadline:
        out = run_cli(binary, cwd, "--db", db, "content-count", workspace)
        last = out
        if line_value(out, "content_events") == str(expected):
            return
        time.sleep(0.1)
    raise RuntimeError(f"content count did not reach {expected}; last output:\n{last}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def render_markdown(results: list[Result], run_id: str) -> str:
    lines = [
        f"# Perf Compare {run_id}",
        "",
        "| Suite | Worktree | Status | Wall s | Summary |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for result in results:
        wall = "" if result.wall_seconds is None else f"{result.wall_seconds:.3f}"
        summary = "<br>".join(result.summary) if result.summary else result.reason
        summary = summary.replace("|", "\\|")
        lines.append(
            f"| {result.suite} | {result.worktree} | {result.status} | {wall} | {summary} |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare poc-7, poc-8, and poc-10 perf harnesses without fake numbers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--poc7", default=str(DEFAULT_WORKTREES["poc7"]))
    parser.add_argument("--poc8", default=str(DEFAULT_WORKTREES["poc8"]))
    parser.add_argument("--poc10", default=str(DEFAULT_WORKTREES["poc10"]))
    parser.add_argument(
        "--only",
        nargs="+",
        choices=["projection", "sync", "encryption-display", "cascade"],
        default=["projection", "sync", "encryption-display", "cascade"],
        help="Suites to run.",
    )
    parser.add_argument("--messages", type=int, default=1_000, help="Projection message count.")
    parser.add_argument("--sync-messages", type=int, default=100, help="CLI sync message count.")
    parser.add_argument("--display-messages", type=int, default=100)
    parser.add_argument("--display-limit", type=int, default=20)
    parser.add_argument("--cascade-events", type=int, default=10_000)
    parser.add_argument("--event-size", type=int, default=128)
    parser.add_argument("--sync-timeout", type=int, default=300)
    parser.add_argument("--command-timeout", type=int, default=1800)
    parser.add_argument("--keep-going", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    Runner(args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
