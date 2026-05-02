use std::collections::{HashMap, VecDeque};

use crux_core::{capability::Operation, App, Command, Request};

#[derive(Debug, Default)]
pub struct EffectShellApp;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Model {
    pub last: Option<JobSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSummary {
    pub request_id: u64,
    pub endpoint: String,
    pub previous_cursor: Option<String>,
    pub response: String,
    pub stored_cursor: String,
    pub finished_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Start { endpoint: String, key: String },
    Finished(JobSummary),
}

impl Event {
    pub fn demo_start() -> Self {
        Self::Start {
            endpoint: "peer-a:7000".to_string(),
            key: "sync/cursor".to_string(),
        }
    }
}

#[derive(Debug)]
pub enum Effect {
    Store(Request<StoreOp>),
    Tcp(Request<TcpOp>),
    Rng(Request<RngOp>),
    Clock(Request<ClockOp>),
    Stdout(Request<StdoutOp>),
}

impl crux_core::Effect for Effect {}

impl From<Request<StoreOp>> for Effect {
    fn from(request: Request<StoreOp>) -> Self {
        Self::Store(request)
    }
}

impl From<Request<TcpOp>> for Effect {
    fn from(request: Request<TcpOp>) -> Self {
        Self::Tcp(request)
    }
}

impl From<Request<RngOp>> for Effect {
    fn from(request: Request<RngOp>) -> Self {
        Self::Rng(request)
    }
}

impl From<Request<ClockOp>> for Effect {
    fn from(request: Request<ClockOp>) -> Self {
        Self::Clock(request)
    }
}

impl From<Request<StdoutOp>> for Effect {
    fn from(request: Request<StdoutOp>) -> Self {
        Self::Stdout(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOp {
    Get { key: String },
    Put { key: String, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreReply {
    Value(Option<String>),
    Stored,
}

impl Operation for StoreOp {
    type Output = StoreReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOp {
    Send { endpoint: String, payload: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReply {
    Received { body: String },
}

impl Operation for TcpOp {
    type Output = TcpReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RngOp {
    NextU64 { purpose: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RngReply {
    U64(u64),
}

impl Operation for RngOp {
    type Output = RngReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockOp {
    NowMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockReply {
    Millis(u64),
}

impl Operation for ClockOp {
    type Output = ClockReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdoutOp {
    WriteLine { line: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdoutReply {
    Written,
}

impl Operation for StdoutOp {
    type Output = StdoutReply;
}

impl App for EffectShellApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = Option<JobSummary>;
    type Effect = Effect;

    fn update(&self, event: Self::Event, model: &mut Self::Model) -> Command<Effect, Event> {
        match event {
            Event::Start { endpoint, key } => sync_once(endpoint, key),
            Event::Finished(summary) => {
                model.last = Some(summary);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        model.last.clone()
    }
}

fn sync_once(endpoint: String, key: String) -> Command<Effect, Event> {
    Command::new(|ctx| async move {
        let previous_cursor = match ctx
            .request_from_shell(StoreOp::Get { key: key.clone() })
            .await
        {
            StoreReply::Value(value) => value,
            StoreReply::Stored => panic!("store get returned store acknowledgement"),
        };

        let request_id = match ctx
            .request_from_shell(RngOp::NextU64 {
                purpose: "sync-request-id".to_string(),
            })
            .await
        {
            RngReply::U64(value) => value,
        };

        let finished_at_ms = match ctx.request_from_shell(ClockOp::NowMillis).await {
            ClockReply::Millis(value) => value,
        };

        let cursor_for_payload = previous_cursor.as_deref().unwrap_or("<none>");
        let payload = format!(
            "sync request_id={request_id} cursor={cursor_for_payload} at_ms={finished_at_ms}"
        );

        let response = match ctx
            .request_from_shell(TcpOp::Send {
                endpoint: endpoint.clone(),
                payload,
            })
            .await
        {
            TcpReply::Received { body } => body,
        };

        let stored_cursor = response.clone();
        match ctx
            .request_from_shell(StoreOp::Put {
                key: key.clone(),
                value: stored_cursor.clone(),
            })
            .await
        {
            StoreReply::Stored => {}
            StoreReply::Value(_) => panic!("store put returned value"),
        }

        match ctx
            .request_from_shell(StdoutOp::WriteLine {
                line: format!(
                    "synced endpoint={endpoint} request_id={request_id} cursor={stored_cursor}"
                ),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(Event::Finished(JobSummary {
            request_id,
            endpoint,
            previous_cursor,
            response,
            stored_cursor,
            finished_at_ms,
        }));
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptEntry {
    StoreGet { key: String },
    StoreGetReply { key: String, value: Option<String> },
    StorePut { key: String, value: String },
    StorePutReply { key: String },
    TcpSend { endpoint: String, payload: String },
    TcpSendReply { endpoint: String, body: String },
    RngNextU64 { purpose: String },
    RngNextU64Reply { purpose: String, value: u64 },
    ClockNowMillis,
    ClockNowMillisReply { value: u64 },
    StdoutWriteLine { line: String },
    StdoutWriteLineReply,
}

#[derive(Debug, Default)]
pub struct FakeShell {
    store: HashMap<String, String>,
    tcp_replies: VecDeque<String>,
    rng_values: VecDeque<u64>,
    clock_values: VecDeque<u64>,
    pub stdout: Vec<String>,
    pub transcript: Vec<TranscriptEntry>,
}

impl FakeShell {
    pub fn demo() -> Self {
        Self::default()
            .with_store_value("sync/cursor", "cursor-7")
            .with_rng_value(41)
            .with_clock_value(1_710_000_000_123)
            .with_tcp_reply("cursor-8")
    }

    pub fn with_store_value(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.store.insert(key.into(), value.into());
        self
    }

    pub fn with_tcp_reply(mut self, body: impl Into<String>) -> Self {
        self.tcp_replies.push_back(body.into());
        self
    }

    pub fn with_rng_value(mut self, value: u64) -> Self {
        self.rng_values.push_back(value);
        self
    }

    pub fn with_clock_value(mut self, value: u64) -> Self {
        self.clock_values.push_back(value);
        self
    }

    pub fn store_value(&self, key: &str) -> Option<&str> {
        self.store.get(key).map(String::as_str)
    }

    pub fn run(&mut self, app: &EffectShellApp, event: Event, model: &mut Model) {
        let mut pending_events = VecDeque::from([event]);

        while let Some(event) = pending_events.pop_front() {
            let mut command = app.update(event, model);
            self.drain_command(&mut command, &mut pending_events);
        }
    }

    fn drain_command(
        &mut self,
        command: &mut Command<Effect, Event>,
        pending_events: &mut VecDeque<Event>,
    ) {
        loop {
            let effects: Vec<_> = command.effects().collect();
            let events: Vec<_> = command.events().collect();
            let made_progress = !effects.is_empty() || !events.is_empty();

            for effect in effects {
                self.handle_effect(effect);
            }

            pending_events.extend(events);

            if command.is_done() {
                break;
            }

            assert!(
                made_progress,
                "command stalled without an effect, event, or completion"
            );
        }
    }

    fn handle_effect(&mut self, effect: Effect) {
        match effect {
            Effect::Store(mut request) => self.handle_store(&mut request),
            Effect::Tcp(mut request) => self.handle_tcp(&mut request),
            Effect::Rng(mut request) => self.handle_rng(&mut request),
            Effect::Clock(mut request) => self.handle_clock(&mut request),
            Effect::Stdout(mut request) => self.handle_stdout(&mut request),
        }
    }

    fn handle_store(&mut self, request: &mut Request<StoreOp>) {
        match request.operation.clone() {
            StoreOp::Get { key } => {
                self.transcript
                    .push(TranscriptEntry::StoreGet { key: key.clone() });
                let value = self.store.get(&key).cloned();
                self.transcript.push(TranscriptEntry::StoreGetReply {
                    key,
                    value: value.clone(),
                });
                request
                    .resolve(StoreReply::Value(value))
                    .expect("store get should resolve once");
            }
            StoreOp::Put { key, value } => {
                self.transcript.push(TranscriptEntry::StorePut {
                    key: key.clone(),
                    value: value.clone(),
                });
                self.store.insert(key.clone(), value);
                self.transcript.push(TranscriptEntry::StorePutReply { key });
                request
                    .resolve(StoreReply::Stored)
                    .expect("store put should resolve once");
            }
        }
    }

    fn handle_tcp(&mut self, request: &mut Request<TcpOp>) {
        let TcpOp::Send { endpoint, payload } = request.operation.clone();
        self.transcript.push(TranscriptEntry::TcpSend {
            endpoint: endpoint.clone(),
            payload,
        });
        let body = self
            .tcp_replies
            .pop_front()
            .expect("fake shell needs a queued TCP reply");
        self.transcript.push(TranscriptEntry::TcpSendReply {
            endpoint,
            body: body.clone(),
        });
        request
            .resolve(TcpReply::Received { body })
            .expect("tcp send should resolve once");
    }

    fn handle_rng(&mut self, request: &mut Request<RngOp>) {
        let RngOp::NextU64 { purpose } = request.operation.clone();
        self.transcript.push(TranscriptEntry::RngNextU64 {
            purpose: purpose.clone(),
        });
        let value = self
            .rng_values
            .pop_front()
            .expect("fake shell needs a queued RNG value");
        self.transcript
            .push(TranscriptEntry::RngNextU64Reply { purpose, value });
        request
            .resolve(RngReply::U64(value))
            .expect("rng should resolve once");
    }

    fn handle_clock(&mut self, request: &mut Request<ClockOp>) {
        match request.operation {
            ClockOp::NowMillis => {
                self.transcript.push(TranscriptEntry::ClockNowMillis);
                let value = self
                    .clock_values
                    .pop_front()
                    .expect("fake shell needs a queued clock value");
                self.transcript
                    .push(TranscriptEntry::ClockNowMillisReply { value });
                request
                    .resolve(ClockReply::Millis(value))
                    .expect("clock should resolve once");
            }
        }
    }

    fn handle_stdout(&mut self, request: &mut Request<StdoutOp>) {
        let StdoutOp::WriteLine { line } = request.operation.clone();
        self.transcript
            .push(TranscriptEntry::StdoutWriteLine { line: line.clone() });
        self.stdout.push(line);
        self.transcript.push(TranscriptEntry::StdoutWriteLineReply);
        request
            .resolve(StdoutReply::Written)
            .expect("stdout should resolve once");
    }
}

pub fn run_demo() -> (Model, Vec<TranscriptEntry>, Vec<String>) {
    let app = EffectShellApp;
    let mut model = Model::default();
    let mut shell = FakeShell::demo();
    shell.run(&app, Event::demo_start(), &mut model);
    (model, shell.transcript, shell.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_proves_replies_drive_later_effects() {
        let app = EffectShellApp;
        let mut model = Model::default();
        let mut shell = FakeShell::demo();

        shell.run(&app, Event::demo_start(), &mut model);

        assert_eq!(
            shell.transcript,
            vec![
                TranscriptEntry::StoreGet {
                    key: "sync/cursor".to_string()
                },
                TranscriptEntry::StoreGetReply {
                    key: "sync/cursor".to_string(),
                    value: Some("cursor-7".to_string())
                },
                TranscriptEntry::RngNextU64 {
                    purpose: "sync-request-id".to_string()
                },
                TranscriptEntry::RngNextU64Reply {
                    purpose: "sync-request-id".to_string(),
                    value: 41
                },
                TranscriptEntry::ClockNowMillis,
                TranscriptEntry::ClockNowMillisReply {
                    value: 1_710_000_000_123
                },
                TranscriptEntry::TcpSend {
                    endpoint: "peer-a:7000".to_string(),
                    payload: "sync request_id=41 cursor=cursor-7 at_ms=1710000000123".to_string()
                },
                TranscriptEntry::TcpSendReply {
                    endpoint: "peer-a:7000".to_string(),
                    body: "cursor-8".to_string()
                },
                TranscriptEntry::StorePut {
                    key: "sync/cursor".to_string(),
                    value: "cursor-8".to_string()
                },
                TranscriptEntry::StorePutReply {
                    key: "sync/cursor".to_string()
                },
                TranscriptEntry::StdoutWriteLine {
                    line: "synced endpoint=peer-a:7000 request_id=41 cursor=cursor-8".to_string()
                },
                TranscriptEntry::StdoutWriteLineReply,
            ]
        );
        assert_eq!(
            model.last,
            Some(JobSummary {
                request_id: 41,
                endpoint: "peer-a:7000".to_string(),
                previous_cursor: Some("cursor-7".to_string()),
                response: "cursor-8".to_string(),
                stored_cursor: "cursor-8".to_string(),
                finished_at_ms: 1_710_000_000_123,
            })
        );
        assert_eq!(shell.store_value("sync/cursor"), Some("cursor-8"));
        assert_eq!(
            shell.stdout,
            vec!["synced endpoint=peer-a:7000 request_id=41 cursor=cursor-8".to_string()]
        );
    }

    #[test]
    fn cold_start_transcript_uses_empty_cursor_marker() {
        let app = EffectShellApp;
        let mut model = Model::default();
        let mut shell = FakeShell::default()
            .with_rng_value(7)
            .with_clock_value(99)
            .with_tcp_reply("cursor-1");

        shell.run(
            &app,
            Event::Start {
                endpoint: "peer-b:7000".to_string(),
                key: "sync/cursor".to_string(),
            },
            &mut model,
        );

        assert!(shell.transcript.contains(&TranscriptEntry::StoreGetReply {
            key: "sync/cursor".to_string(),
            value: None,
        }));
        assert!(shell.transcript.contains(&TranscriptEntry::TcpSend {
            endpoint: "peer-b:7000".to_string(),
            payload: "sync request_id=7 cursor=<none> at_ms=99".to_string(),
        }));
        assert_eq!(shell.store_value("sync/cursor"), Some("cursor-1"));
        assert_eq!(
            model.last,
            Some(JobSummary {
                request_id: 7,
                endpoint: "peer-b:7000".to_string(),
                previous_cursor: None,
                response: "cursor-1".to_string(),
                stored_cursor: "cursor-1".to_string(),
                finished_at_ms: 99,
            })
        );
    }
}
