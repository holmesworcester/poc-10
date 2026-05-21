//! Polling CLI assertions over projected read models.
//!
//! These commands are intentionally observational. They do not settle runtime
//! work; some other process, usually a daemon, must make the assertion true.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, CliArgs, CliOutput};
use crate::core::command_context::WorkspaceId;
use crate::core::runtime::Runtime;
use crate::protocol::facts::{content, identity, sync};
use std::thread;
use std::time::{Duration, Instant};

pub const ASSERT_USAGE: &str =
    "assert eventually (content-count WORKSPACE_ID_HEX|count|sync-status) FIELD OP VALUE [--timeout-ms N] [--poll-ms N]";

pub(crate) fn run(runtime: &Runtime, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let assertion = parse_eventually_assertion(args.values())?;
    run_eventually_assertion(runtime, assertion)
}

fn parse_eventually_assertion(args: &[String]) -> Result<EventuallyAssertion, String> {
    let (args, timeout_ms, poll_ms) = parse_eventually_options(args)?;
    if args.first().map(String::as_str) != Some("eventually") {
        return Err(ASSERT_USAGE.to_string());
    }
    let args = &args[1..];
    if args.is_empty() {
        return Err(ASSERT_USAGE.to_string());
    }

    let (target, next) = parse_assertion_target(args)?;
    let field = args.get(next).ok_or_else(|| ASSERT_USAGE.to_string())?;
    let op = args
        .get(next + 1)
        .ok_or_else(|| ASSERT_USAGE.to_string())
        .and_then(|value| CompareOp::parse(value))?;
    let expected = args
        .get(next + 2)
        .ok_or_else(|| ASSERT_USAGE.to_string())?
        .parse::<u64>()
        .map_err(|_| ASSERT_USAGE.to_string())?;
    if args.len() != next + 3 {
        return Err(ASSERT_USAGE.to_string());
    }

    Ok(EventuallyAssertion {
        target: target.with_field(field)?,
        op,
        expected,
        timeout_ms,
        poll_ms,
    })
}

fn parse_eventually_options(args: &[String]) -> Result<(Vec<String>, u64, u64), String> {
    let mut remaining = Vec::new();
    let mut timeout_ms = 30_000u64;
    let mut poll_ms = 250u64;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--timeout-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| ASSERT_USAGE.to_string())?;
                timeout_ms = parse_positive_u64(value)?;
                index += 2;
            }
            "--poll-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| ASSERT_USAGE.to_string())?;
                poll_ms = parse_positive_u64(value)?;
                index += 2;
            }
            _ => {
                remaining.push(args[index].clone());
                index += 1;
            }
        }
    }
    Ok((remaining, timeout_ms, poll_ms))
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| ASSERT_USAGE.to_string())
}

fn parse_assertion_target(args: &[String]) -> Result<(PendingAssertionTarget, usize), String> {
    match args[0].as_str() {
        "content-count" => {
            let workspace = args.get(1).ok_or_else(|| ASSERT_USAGE.to_string())?;
            let workspace_id = decode_hex_32(workspace, "workspace id")?;
            Ok((PendingAssertionTarget::ContentCount { workspace_id }, 2))
        }
        "count" => Ok((PendingAssertionTarget::RuntimeCount, 1)),
        "sync-status" => Ok((PendingAssertionTarget::SyncStatus, 1)),
        _ => Err(ASSERT_USAGE.to_string()),
    }
}

fn run_eventually_assertion(
    runtime: &Runtime,
    assertion: EventuallyAssertion,
) -> Result<CliOutput, String> {
    let started = Instant::now();
    let timeout = Duration::from_millis(assertion.timeout_ms);
    let poll = Duration::from_millis(assertion.poll_ms);
    let mut polls = 0usize;

    loop {
        polls += 1;
        let observed = assertion.target.observe(runtime)?;
        if assertion.op.matches(observed, assertion.expected) {
            return Ok(CliOutput::lines(vec![
                "ok: true".to_string(),
                format!("target: {}", assertion.target.name()),
                format!("field: {}", assertion.target.field_name()),
                format!("op: {}", assertion.op.as_str()),
                format!("expected: {}", assertion.expected),
                format!("observed: {observed}"),
                format!("elapsed_ms: {}", started.elapsed().as_millis()),
                format!("polls: {polls}"),
            ]));
        }

        if started.elapsed() >= timeout {
            return Err(format!(
                "assert eventually timed out after {}ms: {} {} {} {}, last observed {}",
                assertion.timeout_ms,
                assertion.target.name(),
                assertion.target.field_name(),
                assertion.op.as_str(),
                assertion.expected,
                observed,
            ));
        }
        thread::sleep(poll);
    }
}

#[derive(Debug, Clone, Copy)]
struct EventuallyAssertion {
    target: AssertionTarget,
    op: CompareOp,
    expected: u64,
    timeout_ms: u64,
    poll_ms: u64,
}

#[derive(Debug, Clone, Copy)]
enum PendingAssertionTarget {
    ContentCount { workspace_id: WorkspaceId },
    RuntimeCount,
    SyncStatus,
}

impl PendingAssertionTarget {
    fn with_field(self, field: &str) -> Result<AssertionTarget, String> {
        match self {
            Self::ContentCount { workspace_id } => Ok(AssertionTarget::ContentCount {
                workspace_id,
                field: ContentCountField::parse(field)?,
            }),
            Self::RuntimeCount => Ok(AssertionTarget::RuntimeCount {
                field: RuntimeCountField::parse(field)?,
            }),
            Self::SyncStatus => Ok(AssertionTarget::SyncStatus {
                field: SyncStatusField::parse(field)?,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AssertionTarget {
    ContentCount {
        workspace_id: WorkspaceId,
        field: ContentCountField,
    },
    RuntimeCount {
        field: RuntimeCountField,
    },
    SyncStatus {
        field: SyncStatusField,
    },
}

impl AssertionTarget {
    fn name(self) -> &'static str {
        match self {
            Self::ContentCount { .. } => "content-count",
            Self::RuntimeCount { .. } => "count",
            Self::SyncStatus { .. } => "sync-status",
        }
    }

    fn field_name(self) -> &'static str {
        match self {
            Self::ContentCount { field, .. } => field.name(),
            Self::RuntimeCount { field } => field.name(),
            Self::SyncStatus { field } => field.name(),
        }
    }

    fn observe(self, runtime: &Runtime) -> Result<u64, String> {
        match self {
            Self::ContentCount {
                workspace_id,
                field,
            } => {
                let count =
                    content::event::queries::count_for_workspace(runtime.store(), workspace_id)?;
                Ok(field.value(count))
            }
            Self::RuntimeCount { field } => {
                let report = identity::workspace::runtime_counts::runtime_count_report(runtime)?;
                Ok(field.value(&report))
            }
            Self::SyncStatus { field } => {
                let status = sync::shared_fact::sync_status(runtime.store())?;
                Ok(field.value(&status))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ContentCountField {
    ContentEvents,
    ContentFacts,
    ContentPayloadBytes,
    MaxEventTimestamp,
}

impl ContentCountField {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "content_events" => Ok(Self::ContentEvents),
            "content_facts" => Ok(Self::ContentFacts),
            "content_payload_bytes" => Ok(Self::ContentPayloadBytes),
            "max_event_timestamp" => Ok(Self::MaxEventTimestamp),
            _ => Err(ASSERT_USAGE.to_string()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ContentEvents => "content_events",
            Self::ContentFacts => "content_facts",
            Self::ContentPayloadBytes => "content_payload_bytes",
            Self::MaxEventTimestamp => "max_event_timestamp",
        }
    }

    fn value(self, count: content::event::queries::ContentCount) -> u64 {
        match self {
            Self::ContentEvents | Self::ContentFacts => count.content_events as u64,
            Self::ContentPayloadBytes => count.content_payload_bytes,
            Self::MaxEventTimestamp => count.max_timestamp,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RuntimeCountField {
    WorkspaceRows,
    Facts,
    SyncFacts,
    AppliedFacts,
    Connections,
    ConnectionFacts,
    InviteAccepted,
}

impl RuntimeCountField {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "workspace_rows" => Ok(Self::WorkspaceRows),
            "facts" => Ok(Self::Facts),
            "sync_facts" => Ok(Self::SyncFacts),
            "applied_facts" => Ok(Self::AppliedFacts),
            "connections" => Ok(Self::Connections),
            "connection_facts" => Ok(Self::ConnectionFacts),
            "invite_accepted" => Ok(Self::InviteAccepted),
            _ => Err(ASSERT_USAGE.to_string()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::WorkspaceRows => "workspace_rows",
            Self::Facts => "facts",
            Self::SyncFacts => "sync_facts",
            Self::AppliedFacts => "applied_facts",
            Self::Connections => "connections",
            Self::ConnectionFacts => "connection_facts",
            Self::InviteAccepted => "invite_accepted",
        }
    }

    fn value(self, report: &identity::workspace::runtime_counts::RuntimeCountReport) -> u64 {
        match self {
            Self::WorkspaceRows => report.workspace_rows as u64,
            Self::Facts => report.facts as u64,
            Self::SyncFacts => report.sync_facts as u64,
            Self::AppliedFacts => report.applied_facts as u64,
            Self::Connections => report.connections as u64,
            Self::ConnectionFacts => report.connection_facts as u64,
            Self::InviteAccepted => report.invite_accepted as u64,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SyncStatusField {
    IndexedFacts,
    RootCount,
    PendingPurges,
}

impl SyncStatusField {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "indexed_facts" => Ok(Self::IndexedFacts),
            "root_count" => Ok(Self::RootCount),
            "pending_purges" => Ok(Self::PendingPurges),
            _ => Err(ASSERT_USAGE.to_string()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::IndexedFacts => "indexed_facts",
            Self::RootCount => "root_count",
            Self::PendingPurges => "pending_purges",
        }
    }

    fn value(self, status: &sync::shared_fact::rows::SyncStatus) -> u64 {
        match self {
            Self::IndexedFacts => status.indexed_facts as u64,
            Self::RootCount => status.root_count,
            Self::PendingPurges => status.pending_purges as u64,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CompareOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl CompareOp {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "=" | "==" | "eq" => Ok(Self::Eq),
            "!=" | "ne" => Ok(Self::Ne),
            ">" | "gt" => Ok(Self::Gt),
            ">=" | "gte" => Ok(Self::Gte),
            "<" | "lt" => Ok(Self::Lt),
            "<=" | "lte" => Ok(Self::Lte),
            _ => Err(ASSERT_USAGE.to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
        }
    }

    fn matches(self, observed: u64, expected: u64) -> bool {
        match self {
            Self::Eq => observed == expected,
            Self::Ne => observed != expected,
            Self::Gt => observed > expected,
            Self::Gte => observed >= expected,
            Self::Lt => observed < expected,
            Self::Lte => observed <= expected,
        }
    }
}
