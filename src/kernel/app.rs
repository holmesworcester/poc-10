use std::net::SocketAddr;

use crux_core::{capability::Operation, App, Command, Request};

use crate::control_loop;

#[derive(Debug, Default)]
pub struct KernelApp;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelModel {
    pub last_invite: Option<String>,
    pub last_generate: Option<GenerateSummary>,
    pub last_count: Option<CountSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelView {
    pub last_invite: Option<String>,
    pub last_generate: Option<GenerateSummary>,
    pub last_count: Option<CountSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelMsg {
    Invite {
        public_addr: SocketAddr,
    },
    InviteFinished(String),
    Generate {
        num_events: usize,
        event_size: usize,
    },
    GenerateFinished(GenerateSummary),
    Count,
    CountFinished(CountSummary),
}

#[derive(Debug)]
pub enum KernelEffect {
    Store(Request<StoreOp>),
    Stdout(Request<StdoutOp>),
}

impl crux_core::Effect for KernelEffect {}

impl From<Request<StoreOp>> for KernelEffect {
    fn from(request: Request<StoreOp>) -> Self {
        Self::Store(request)
    }
}

impl From<Request<StdoutOp>> for KernelEffect {
    fn from(request: Request<StdoutOp>) -> Self {
        Self::Stdout(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOp {
    CreateInvite {
        public_addr: SocketAddr,
    },
    GenerateContent {
        num_events: usize,
        event_size: usize,
    },
    DrainReadyUntilIdle {
        batch_size: usize,
    },
    CountStatus,
}

impl Operation for StoreOp {
    type Output = StoreReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreReply {
    InviteCreated { link: String },
    Generated(GeneratedContent),
    Drained(DrainReadyReport),
    Counted(CountSummary),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedContent {
    pub inserted_events: usize,
    pub applied_events: usize,
    pub event_size: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdoutOp {
    PrintLines { lines: Vec<String> },
}

impl Operation for StdoutOp {
    type Output = StdoutReply;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdoutReply {
    Written,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateSummary {
    pub generated_events: usize,
    pub applied_events: usize,
    pub event_size: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountSummary {
    pub events: usize,
    pub payload_bytes: usize,
    pub connections: usize,
    pub connection_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub applied_events: usize,
    pub rejected_events: usize,
    pub blocked_edges: usize,
}

impl CountSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("events: {}", self.events),
            format!("payload_bytes: {}", self.payload_bytes),
            format!("connections: {}", self.connections),
            format!("connection_events: {}", self.connection_events),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("applied_events: {}", self.applied_events),
            format!("rejected_events: {}", self.rejected_events),
            format!("blocked_edges: {}", self.blocked_edges),
        ]
    }
}

impl GenerateSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("generated_events: {}", self.generated_events),
            format!("applied_events: {}", self.applied_events),
            format!("event_size_bytes: {}", self.event_size),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

impl App for KernelApp {
    type Event = KernelMsg;
    type Model = KernelModel;
    type ViewModel = KernelView;
    type Effect = KernelEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            KernelMsg::Invite { public_addr } => invite(public_addr),
            KernelMsg::InviteFinished(link) => {
                model.last_invite = Some(link);
                Command::done()
            }
            KernelMsg::Generate {
                num_events,
                event_size,
            } => generate(num_events, event_size),
            KernelMsg::GenerateFinished(summary) => {
                model.last_generate = Some(summary);
                Command::done()
            }
            KernelMsg::Count => count(),
            KernelMsg::CountFinished(summary) => {
                model.last_count = Some(summary);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        KernelView {
            last_invite: model.last_invite.clone(),
            last_generate: model.last_generate.clone(),
            last_count: model.last_count.clone(),
        }
    }
}

fn invite(public_addr: SocketAddr) -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let link = match ctx
            .request_from_shell(StoreOp::CreateInvite { public_addr })
            .await
        {
            StoreReply::InviteCreated { link } => link,
            _ => panic!("invite received non-invite store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: vec![link.clone()],
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(KernelMsg::InviteFinished(link));
    })
}

fn generate(num_events: usize, event_size: usize) -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let generated = match ctx
            .request_from_shell(StoreOp::GenerateContent {
                num_events,
                event_size,
            })
            .await
        {
            StoreReply::Generated(generated) => generated,
            _ => panic!("generate received non-generate store reply"),
        };

        let drained = match ctx
            .request_from_shell(StoreOp::DrainReadyUntilIdle {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            })
            .await
        {
            StoreReply::Drained(drained) => drained,
            _ => panic!("drain received non-drain store reply"),
        };

        let summary = GenerateSummary {
            generated_events: generated.inserted_events,
            applied_events: generated.applied_events + drained.applied_events,
            event_size: generated.event_size,
            first_timestamp: generated.first_timestamp,
            last_timestamp: generated.last_timestamp,
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(KernelMsg::GenerateFinished(summary));
    })
}

fn count() -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let summary = match ctx.request_from_shell(StoreOp::CountStatus).await {
            StoreReply::Counted(summary) => summary,
            _ => panic!("count received non-count store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(KernelMsg::CountFinished(summary));
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TranscriptEntry {
        InviteRequested {
            public_addr: SocketAddr,
        },
        InviteReplied {
            link: String,
        },
        GenerateRequested {
            num_events: usize,
            event_size: usize,
        },
        GenerateReplied {
            inserted_events: usize,
        },
        DrainRequested {
            batch_size: usize,
        },
        DrainReplied {
            applied_events: usize,
        },
        CountRequested,
        CountReplied {
            events: usize,
        },
        PrintRequested {
            lines: Vec<String>,
        },
        PrintReplied,
    }

    #[derive(Debug, Default)]
    struct FakeShell {
        transcript: Vec<TranscriptEntry>,
        stdout: Vec<String>,
    }

    impl FakeShell {
        fn run(&mut self, app: &KernelApp, model: &mut KernelModel, event: KernelMsg) {
            let mut pending = VecDeque::from([event]);
            while let Some(event) = pending.pop_front() {
                let mut command = app.update(event, model);
                self.drain_command(&mut command, &mut pending);
            }
        }

        fn drain_command(
            &mut self,
            command: &mut Command<KernelEffect, KernelMsg>,
            pending: &mut VecDeque<KernelMsg>,
        ) {
            loop {
                let effects = command.effects().collect::<Vec<_>>();
                let events = command.events().collect::<Vec<_>>();
                let made_progress = !effects.is_empty() || !events.is_empty();

                for effect in effects {
                    self.handle_effect(effect);
                }
                pending.extend(events);

                if command.is_done() {
                    break;
                }
                assert!(made_progress, "kernel command stalled");
            }
        }

        fn handle_effect(&mut self, effect: KernelEffect) {
            match effect {
                KernelEffect::Store(mut request) => match request.operation.clone() {
                    StoreOp::CreateInvite { public_addr } => {
                        self.transcript
                            .push(TranscriptEntry::InviteRequested { public_addr });
                        let link = format!("topo://invite/ADDRESS.{}", public_addr);
                        self.transcript
                            .push(TranscriptEntry::InviteReplied { link: link.clone() });
                        request
                            .resolve(StoreReply::InviteCreated { link })
                            .expect("invite request should resolve");
                    }
                    StoreOp::GenerateContent {
                        num_events,
                        event_size,
                    } => {
                        self.transcript.push(TranscriptEntry::GenerateRequested {
                            num_events,
                            event_size,
                        });
                        self.transcript.push(TranscriptEntry::GenerateReplied {
                            inserted_events: num_events,
                        });
                        request
                            .resolve(StoreReply::Generated(GeneratedContent {
                                inserted_events: num_events,
                                applied_events: 0,
                                event_size,
                                first_timestamp: 8,
                                last_timestamp: 8 + num_events as u64 - 1,
                            }))
                            .expect("generate request should resolve");
                    }
                    StoreOp::DrainReadyUntilIdle { batch_size } => {
                        self.transcript
                            .push(TranscriptEntry::DrainRequested { batch_size });
                        self.transcript
                            .push(TranscriptEntry::DrainReplied { applied_events: 3 });
                        request
                            .resolve(StoreReply::Drained(DrainReadyReport {
                                applied_events: 3,
                                unblocked_events: 0,
                            }))
                            .expect("drain request should resolve");
                    }
                    StoreOp::CountStatus => {
                        self.transcript.push(TranscriptEntry::CountRequested);
                        self.transcript
                            .push(TranscriptEntry::CountReplied { events: 12 });
                        request
                            .resolve(StoreReply::Counted(CountSummary {
                                events: 12,
                                payload_bytes: 768,
                                connections: 2,
                                connection_events: 4,
                                ready_events: 0,
                                blocked_events: 1,
                                applied_events: 11,
                                rejected_events: 0,
                                blocked_edges: 3,
                            }))
                            .expect("count request should resolve");
                    }
                },
                KernelEffect::Stdout(mut request) => match request.operation.clone() {
                    StdoutOp::PrintLines { lines } => {
                        self.transcript.push(TranscriptEntry::PrintRequested {
                            lines: lines.clone(),
                        });
                        self.stdout.extend(lines);
                        self.transcript.push(TranscriptEntry::PrintReplied);
                        request
                            .resolve(StdoutReply::Written)
                            .expect("stdout request should resolve");
                    }
                },
            }
        }
    }

    #[test]
    fn generate_requests_store_then_drain_then_prints_summary() {
        let app = KernelApp;
        let mut model = KernelModel::default();
        let mut shell = FakeShell::default();

        shell.run(
            &app,
            &mut model,
            KernelMsg::Generate {
                num_events: 4,
                event_size: 64,
            },
        );

        let expected_lines = vec![
            "generated_events: 4".to_string(),
            "applied_events: 3".to_string(),
            "event_size_bytes: 64".to_string(),
            "first_timestamp: 8".to_string(),
            "last_timestamp: 11".to_string(),
        ];
        assert_eq!(
            shell.transcript,
            vec![
                TranscriptEntry::GenerateRequested {
                    num_events: 4,
                    event_size: 64,
                },
                TranscriptEntry::GenerateReplied { inserted_events: 4 },
                TranscriptEntry::DrainRequested {
                    batch_size: control_loop::DEFAULT_READY_BATCH,
                },
                TranscriptEntry::DrainReplied { applied_events: 3 },
                TranscriptEntry::PrintRequested {
                    lines: expected_lines.clone(),
                },
                TranscriptEntry::PrintReplied,
            ]
        );
        assert_eq!(shell.stdout, expected_lines);
        assert_eq!(
            app.view(&model).last_generate,
            Some(GenerateSummary {
                generated_events: 4,
                applied_events: 3,
                event_size: 64,
                first_timestamp: 8,
                last_timestamp: 11,
            })
        );
    }

    #[test]
    fn invite_requests_store_then_prints_link() {
        let app = KernelApp;
        let mut model = KernelModel::default();
        let mut shell = FakeShell::default();
        let public_addr = "127.0.0.1:7000".parse().unwrap();

        shell.run(&app, &mut model, KernelMsg::Invite { public_addr });

        let link = "topo://invite/ADDRESS.127.0.0.1:7000".to_string();
        assert_eq!(
            shell.transcript,
            vec![
                TranscriptEntry::InviteRequested { public_addr },
                TranscriptEntry::InviteReplied { link: link.clone() },
                TranscriptEntry::PrintRequested {
                    lines: vec![link.clone()],
                },
                TranscriptEntry::PrintReplied,
            ]
        );
        assert_eq!(shell.stdout, vec![link.clone()]);
        assert_eq!(app.view(&model).last_invite, Some(link));
    }

    #[test]
    fn count_requests_store_then_prints_status_lines() {
        let app = KernelApp;
        let mut model = KernelModel::default();
        let mut shell = FakeShell::default();

        shell.run(&app, &mut model, KernelMsg::Count);

        let expected = CountSummary {
            events: 12,
            payload_bytes: 768,
            connections: 2,
            connection_events: 4,
            ready_events: 0,
            blocked_events: 1,
            applied_events: 11,
            rejected_events: 0,
            blocked_edges: 3,
        };
        assert_eq!(
            shell.transcript,
            vec![
                TranscriptEntry::CountRequested,
                TranscriptEntry::CountReplied { events: 12 },
                TranscriptEntry::PrintRequested {
                    lines: expected.lines(),
                },
                TranscriptEntry::PrintReplied,
            ]
        );
        assert_eq!(shell.stdout, expected.lines());
        assert_eq!(app.view(&model).last_count, Some(expected));
    }
}
