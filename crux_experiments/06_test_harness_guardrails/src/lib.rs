use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use crux_core::{capability::Operation, App, Command, Request};

pub const ALLOWED_ROOT: &str = "crux_experiments/06_test_harness_guardrails";
pub const MAX_EDIT_BYTES: usize = 16 * 1024;
pub const MAX_TRANSCRIPT_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct GuardedPath(String);

impl GuardedPath {
    pub fn parse(raw: impl Into<String>) -> Result<Self, ViolationReason> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(ViolationReason::EmptyPath);
        }
        if raw.contains('\\') || raw.chars().any(char::is_control) {
            return Err(ViolationReason::UnsupportedPathSyntax { path: raw });
        }

        let path = Path::new(&raw);
        if path.is_absolute() {
            return Err(ViolationReason::AbsolutePath { path: raw });
        }

        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let part =
                        part.to_str()
                            .ok_or_else(|| ViolationReason::UnsupportedPathSyntax {
                                path: raw.clone(),
                            })?;
                    parts.push(part.to_owned());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(ViolationReason::PathTraversal { path: raw });
                }
                Component::Prefix(_) | Component::RootDir => {
                    return Err(ViolationReason::AbsolutePath { path: raw });
                }
            }
        }

        let normalized = parts.join("/");
        if normalized == ALLOWED_ROOT || normalized.starts_with(&format!("{ALLOWED_ROOT}/")) {
            Ok(Self(normalized))
        } else {
            Err(ViolationReason::PathOutsideAllowedRoot { path: raw })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct WorkId(String);

impl WorkId {
    pub fn parse(raw: impl Into<String>) -> Result<Self, ViolationReason> {
        let raw = raw.into();
        let is_valid = !raw.is_empty()
            && raw.len() <= 40
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));

        if is_valid {
            Ok(Self(raw))
        } else {
            Err(ViolationReason::InvalidWorkId { id: raw })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LlmStep {
    Edit {
        id: String,
        path: String,
        contents: String,
        depends_on: Vec<String>,
    },
    RunTests {
        id: String,
        manifest_dir: String,
        depends_on: Vec<String>,
    },
}

impl LlmStep {
    fn raw_id(&self) -> &str {
        match self {
            LlmStep::Edit { id, .. } | LlmStep::RunTests { id, .. } => id,
        }
    }

    fn into_work_item(self) -> Result<WorkItem, ViolationReason> {
        let raw_id = self.raw_id().to_owned();
        let id = WorkId::parse(raw_id)?;
        let depends_on = parse_dependencies(
            &id,
            match &self {
                LlmStep::Edit { depends_on, .. } | LlmStep::RunTests { depends_on, .. } => {
                    depends_on
                }
            },
        )?;

        let op = match self {
            LlmStep::Edit { path, contents, .. } => {
                let bytes = contents.len();
                if bytes > MAX_EDIT_BYTES {
                    return Err(ViolationReason::EditTooLarge {
                        bytes,
                        max: MAX_EDIT_BYTES,
                    });
                }

                ShellOp::WriteFile {
                    path: GuardedPath::parse(path)?,
                    contents,
                }
            }
            LlmStep::RunTests { manifest_dir, .. } => ShellOp::RunCargoTest {
                manifest_dir: GuardedPath::parse(manifest_dir)?,
            },
        };

        Ok(WorkItem { id, depends_on, op })
    }
}

fn parse_dependencies(
    id: &WorkId,
    raw_dependencies: &[String],
) -> Result<BTreeSet<WorkId>, ViolationReason> {
    let mut dependencies = BTreeSet::new();
    for raw_dependency in raw_dependencies {
        let dependency = WorkId::parse(raw_dependency.clone())?;
        if &dependency == id {
            return Err(ViolationReason::SelfDependency {
                id: id.as_str().to_owned(),
            });
        }
        dependencies.insert(dependency);
    }
    Ok(dependencies)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShellOp {
    WriteFile { path: GuardedPath, contents: String },
    RunCargoTest { manifest_dir: GuardedPath },
}

impl ShellOp {
    pub fn summary(&self) -> String {
        match self {
            ShellOp::WriteFile { path, .. } => format!("write {}", path.as_str()),
            ShellOp::RunCargoTest { manifest_dir } => {
                format!(
                    "cargo test --manifest-path {}/Cargo.toml",
                    manifest_dir.as_str()
                )
            }
        }
    }
}

impl Operation for ShellOp {
    type Output = ShellOutput;
}

#[derive(Debug)]
pub enum GuardrailEffect {
    Shell(Request<ShellOp>),
}

impl crux_core::Effect for GuardrailEffect {}

impl From<Request<ShellOp>> for GuardrailEffect {
    fn from(request: Request<ShellOp>) -> Self {
        Self::Shell(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ShellOutput {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn failure(stderr: impl Into<String>) -> Self {
        Self {
            status: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    ProposeLlmStep(LlmStep),
    ShellFinished { id: WorkId, output: ShellOutput },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkItem {
    pub id: WorkId,
    pub depends_on: BTreeSet<WorkId>,
    pub op: ShellOp,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DependencyDrain {
    pending: BTreeMap<WorkId, WorkItem>,
    running: BTreeMap<WorkId, WorkItem>,
    completed: BTreeSet<WorkId>,
    failed: BTreeSet<WorkId>,
}

impl DependencyDrain {
    fn enqueue(&mut self, item: WorkItem) -> Result<(), ViolationReason> {
        if self.pending.contains_key(&item.id)
            || self.running.contains_key(&item.id)
            || self.completed.contains(&item.id)
            || self.failed.contains(&item.id)
        {
            return Err(ViolationReason::DuplicateWork {
                id: item.id.as_str().to_owned(),
            });
        }

        self.pending.insert(item.id.clone(), item);
        Ok(())
    }

    fn start_next_ready(&mut self) -> Option<WorkItem> {
        if !self.running.is_empty() {
            return None;
        }

        let ready_id = self.pending.iter().find_map(|(id, item)| {
            item.depends_on
                .is_subset(&self.completed)
                .then(|| id.clone())
        })?;
        let item = self.pending.remove(&ready_id)?;
        self.running.insert(ready_id, item.clone());
        Some(item)
    }

    fn finish(&mut self, id: &WorkId, output: &ShellOutput) -> Result<WorkItem, ViolationReason> {
        let item = self
            .running
            .remove(id)
            .ok_or_else(|| ViolationReason::UnknownRunningWork {
                id: id.as_str().to_owned(),
            })?;

        if output.status == 0 {
            self.completed.insert(id.clone());
        } else {
            self.failed.insert(id.clone());
        }

        Ok(item)
    }

    pub fn invariant_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.running.len() > 1 {
            errors.push("more than one shell effect is running".to_owned());
        }

        for (id, item) in &self.running {
            if !item.depends_on.is_subset(&self.completed) {
                errors.push(format!(
                    "running item {} has unmet dependencies",
                    id.as_str()
                ));
            }
        }

        for id in self.pending.keys() {
            if self.completed.contains(id) || self.failed.contains(id) {
                errors.push(format!("pending item {} already finished", id.as_str()));
            }
        }

        for id in self.running.keys() {
            if self.completed.contains(id) || self.failed.contains(id) {
                errors.push(format!("running item {} already finished", id.as_str()));
            }
        }

        errors
    }

    pub fn completed_ids(&self) -> Vec<String> {
        self.completed
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    pub fn failed_ids(&self) -> Vec<String> {
        self.failed
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    pub fn pending_ids(&self) -> Vec<String> {
        self.pending
            .keys()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    pub fn running_ids(&self) -> Vec<String> {
        self.running
            .keys()
            .map(|id| id.as_str().to_owned())
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptEntry {
    pub work_id: WorkId,
    pub operation: String,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl TranscriptEntry {
    fn from_shell(work_item: &WorkItem, output: &ShellOutput) -> Self {
        Self {
            work_id: work_item.id.clone(),
            operation: work_item.op.summary(),
            status: output.status,
            stdout: clamp_transcript(&output.stdout),
            stderr: clamp_transcript(&output.stderr),
        }
    }
}

fn clamp_transcript(raw: &str) -> String {
    if raw.len() <= MAX_TRANSCRIPT_BYTES {
        return raw.to_owned();
    }

    let mut clamped = String::new();
    for ch in raw.chars() {
        if clamped.len() + ch.len_utf8() > MAX_TRANSCRIPT_BYTES {
            break;
        }
        clamped.push(ch);
    }
    clamped.push_str("...[truncated]");
    clamped
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    pub work_id: Option<String>,
    pub reason: ViolationReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViolationReason {
    EmptyPath,
    AbsolutePath { path: String },
    PathTraversal { path: String },
    PathOutsideAllowedRoot { path: String },
    UnsupportedPathSyntax { path: String },
    InvalidWorkId { id: String },
    SelfDependency { id: String },
    DuplicateWork { id: String },
    UnknownRunningWork { id: String },
    EditTooLarge { bytes: usize, max: usize },
    InvariantBroken { detail: String },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Model {
    pub drain: DependencyDrain,
    pub transcript: Vec<TranscriptEntry>,
    pub violations: Vec<Violation>,
}

impl Model {
    fn record_violation(&mut self, work_id: Option<String>, reason: ViolationReason) {
        self.violations.push(Violation { work_id, reason });
    }

    fn record_invariant_errors(&mut self) {
        for detail in self.drain.invariant_errors() {
            self.record_violation(None, ViolationReason::InvariantBroken { detail });
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewModel {
    pub pending: Vec<String>,
    pub running: Vec<String>,
    pub completed: Vec<String>,
    pub failed: Vec<String>,
    pub violations: usize,
    pub transcript_entries: usize,
}

#[derive(Default)]
pub struct GuardrailApp;

impl GuardrailApp {
    fn drain_next(&self, model: &mut Model) -> Command<GuardrailEffect, Event> {
        let Some(item) = model.drain.start_next_ready() else {
            return Command::done();
        };
        model.record_invariant_errors();

        let id = item.id.clone();
        Command::request_from_shell(item.op)
            .then_send(move |output| Event::ShellFinished { id, output })
    }
}

impl App for GuardrailApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = GuardrailEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        let command = match event {
            Event::ProposeLlmStep(step) => {
                let work_id = Some(step.raw_id().to_owned());
                match step.into_work_item() {
                    Ok(item) => match model.drain.enqueue(item) {
                        Ok(()) => self.drain_next(model),
                        Err(reason) => {
                            model.record_violation(work_id, reason);
                            Command::done()
                        }
                    },
                    Err(reason) => {
                        model.record_violation(work_id, reason);
                        Command::done()
                    }
                }
            }
            Event::ShellFinished { id, output } => match model.drain.finish(&id, &output) {
                Ok(item) => {
                    model
                        .transcript
                        .push(TranscriptEntry::from_shell(&item, &output));
                    self.drain_next(model)
                }
                Err(reason) => {
                    model.record_violation(Some(id.as_str().to_owned()), reason);
                    Command::done()
                }
            },
        };

        model.record_invariant_errors();
        command
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ViewModel {
            pending: model.drain.pending_ids(),
            running: model.drain.running_ids(),
            completed: model.drain.completed_ids(),
            failed: model.drain.failed_ids(),
            violations: model.violations.len(),
            transcript_entries: model.transcript.len(),
        }
    }
}
