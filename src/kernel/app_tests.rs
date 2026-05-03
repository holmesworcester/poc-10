use std::{collections::VecDeque, net::SocketAddr};

use crux_core::{App, Command};

use super::app::*;
use crate::control_loop;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TranscriptEntry {
    InviteRequested {
        public_addr: SocketAddr,
    },
    InviteReplied {
        link: String,
    },
    ConnectionRequestCreated {
        invite: String,
    },
    SyncRoutesStarted {
        route_count: usize,
        sent_events: usize,
    },
    BindListener {
        addr: SocketAddr,
    },
    ListenerBound {
        listener_id: u64,
        local_addr: SocketAddr,
    },
    AcceptStream {
        listener_id: u64,
    },
    StreamAccepted {
        stream_id: u64,
        peer_addr: SocketAddr,
    },
    OpenStream {
        addr: SocketAddr,
    },
    StreamOpened {
        stream_id: u64,
    },
    WriteFrames {
        stream_id: u64,
        frame_count: usize,
    },
    FramesWritten,
    ReadFrame {
        stream_id: u64,
    },
    FrameRead {
        bytes: Vec<u8>,
    },
    FrameIngested {
        established_routes: usize,
        sent_events: usize,
        received_events: usize,
    },
    OutboxMarked {
        row_count: usize,
    },
    ShutdownWrite {
        stream_id: u64,
    },
    WriteShutdown,
    StreamClosed {
        stream_id: u64,
    },
    GenerateRequested {
        num_events: usize,
        event_size: usize,
    },
    GenerateReplied {
        inserted_events: usize,
    },
    StageDependentRequested {
        num_events: usize,
        deps_per_event: usize,
    },
    StageDependentReplied {
        staged_events: usize,
    },
    ReplayDependentRequested,
    ReplayDependentReplied {
        replayed_events: usize,
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
    frames_to_read: VecDeque<Vec<u8>>,
    read_closed: bool,
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
                StoreOp::CreateConnectionRequest { invite } => {
                    self.transcript
                        .push(TranscriptEntry::ConnectionRequestCreated { invite });
                    request
                        .resolve(StoreReply::ConnectionRequestCreated(ConnectionRequest {
                            addr: "127.0.0.1:7000".parse().unwrap(),
                            bytes: b"request".to_vec(),
                        }))
                        .expect("connection request should resolve");
                }
                StoreOp::IngestFrame { bytes, .. } => {
                    let (outgoing, sent_outbox, established_routes, sent_events, received_events) =
                        match bytes.as_slice() {
                            b"ack" => (Vec::new(), Vec::new(), 1, 0, 0),
                            b"sync-ack" => (Vec::new(), Vec::new(), 0, 5, 3),
                            b"client-frame" => (
                                vec![b"server-frame".to_vec()],
                                vec![b"server-outbox".to_vec()],
                                1,
                                2,
                                7,
                            ),
                            _ => panic!("unexpected frame bytes: {bytes:?}"),
                        };
                    self.transcript.push(TranscriptEntry::FrameIngested {
                        established_routes,
                        sent_events,
                        received_events,
                    });
                    request
                        .resolve(StoreReply::FrameIngested(FrameIngest {
                            outgoing,
                            sent_outbox,
                            established_routes,
                            sent_events,
                            received_events,
                        }))
                        .expect("ingest frame should resolve");
                }
                StoreOp::MarkOutboxSent { sent_outbox } => {
                    self.transcript.push(TranscriptEntry::OutboxMarked {
                        row_count: sent_outbox.len(),
                    });
                    request
                        .resolve(StoreReply::OutboxMarked)
                        .expect("mark outbox should resolve");
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
                StoreOp::StageDependentEvents {
                    num_events,
                    deps_per_event,
                } => {
                    self.transcript
                        .push(TranscriptEntry::StageDependentRequested {
                            num_events,
                            deps_per_event,
                        });
                    self.transcript
                        .push(TranscriptEntry::StageDependentReplied {
                            staged_events: num_events,
                        });
                    request
                        .resolve(StoreReply::DependentEventsStaged(DependentStageSummary {
                            staged_events: num_events,
                            deps_per_event,
                            dep_edges: 17,
                            first_timestamp: 8,
                            last_timestamp: 8 + num_events as u64 - 1,
                        }))
                        .expect("stage dependent events should resolve");
                }
                StoreOp::ReplayDependentEventsReverse => {
                    self.transcript
                        .push(TranscriptEntry::ReplayDependentRequested);
                    self.transcript
                        .push(TranscriptEntry::ReplayDependentReplied {
                            replayed_events: 12,
                        });
                    request
                        .resolve(StoreReply::DependentEventsReplayed(
                            DependentReplaySummary {
                                replayed_events: 12,
                                blocked_after_reverse: 9,
                                applied_events: 12,
                                ready_events: 0,
                                blocked_events: 0,
                                blocked_edges: 0,
                            },
                        ))
                        .expect("replay dependent events should resolve");
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
                StoreOp::StartSyncRoutes => {
                    let target = "127.0.0.1:7001".parse().unwrap();
                    let outbound = vec![OutboundSyncWork {
                        target,
                        outgoing: vec![b"sync-start".to_vec()],
                        sent_outbox: vec![b"sync-outbox".to_vec()],
                        sent_events: 0,
                    }];
                    self.transcript.push(TranscriptEntry::SyncRoutesStarted {
                        route_count: outbound.len(),
                        sent_events: 2,
                    });
                    request
                        .resolve(StoreReply::SyncStarted(SyncRoutesStart {
                            outbound,
                            sent_events: 2,
                        }))
                        .expect("sync start request should resolve");
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
            KernelEffect::Network(mut request) => match request.operation.clone() {
                NetworkOp::BindListener { addr } => {
                    self.transcript.push(TranscriptEntry::BindListener { addr });
                    self.transcript.push(TranscriptEntry::ListenerBound {
                        listener_id: 7,
                        local_addr: addr,
                    });
                    request
                        .resolve(NetworkReply::ListenerBound {
                            listener_id: 7,
                            local_addr: addr,
                        })
                        .expect("bind listener should resolve");
                }
                NetworkOp::AcceptStream { listener_id } => {
                    self.transcript
                        .push(TranscriptEntry::AcceptStream { listener_id });
                    let peer_addr = "127.0.0.1:8080".parse().unwrap();
                    self.transcript.push(TranscriptEntry::StreamAccepted {
                        stream_id: 42,
                        peer_addr,
                    });
                    request
                        .resolve(NetworkReply::StreamAccepted {
                            stream_id: 42,
                            peer_addr,
                        })
                        .expect("accept stream should resolve");
                }
                NetworkOp::OpenStream { addr } => {
                    self.transcript.push(TranscriptEntry::OpenStream { addr });
                    self.transcript
                        .push(TranscriptEntry::StreamOpened { stream_id: 42 });
                    request
                        .resolve(NetworkReply::StreamOpened { stream_id: 42 })
                        .expect("open stream should resolve");
                }
                NetworkOp::WriteFrames { stream_id, frames } => {
                    self.transcript.push(TranscriptEntry::WriteFrames {
                        stream_id,
                        frame_count: frames.len(),
                    });
                    self.transcript.push(TranscriptEntry::FramesWritten);
                    request
                        .resolve(NetworkReply::FramesWritten)
                        .expect("write frames should resolve");
                }
                NetworkOp::ReadFrame { stream_id } => {
                    self.transcript
                        .push(TranscriptEntry::ReadFrame { stream_id });
                    if let Some(bytes) = self.frames_to_read.pop_front() {
                        self.transcript.push(TranscriptEntry::FrameRead {
                            bytes: bytes.clone(),
                        });
                        request
                            .resolve(NetworkReply::FrameRead(bytes))
                            .expect("read frame should resolve");
                    } else {
                        assert!(!self.read_closed, "fake stream read after close");
                        self.read_closed = true;
                        self.transcript
                            .push(TranscriptEntry::StreamClosed { stream_id });
                        request
                            .resolve(NetworkReply::StreamClosed)
                            .expect("stream close should resolve");
                    }
                }
                NetworkOp::ShutdownWrite { stream_id } => {
                    self.transcript
                        .push(TranscriptEntry::ShutdownWrite { stream_id });
                    self.transcript.push(TranscriptEntry::WriteShutdown);
                    request
                        .resolve(NetworkReply::WriteShutdown)
                        .expect("shutdown write should resolve");
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
fn generate_deps_requests_store_then_prints_summary() {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = FakeShell::default();

    shell.run(
        &app,
        &mut model,
        KernelMsg::GenerateDependentEvents {
            num_events: 12,
            deps_per_event: 3,
        },
    );

    let expected = DependentStageSummary {
        staged_events: 12,
        deps_per_event: 3,
        dep_edges: 17,
        first_timestamp: 8,
        last_timestamp: 19,
    };
    assert_eq!(
        shell.transcript,
        vec![
            TranscriptEntry::StageDependentRequested {
                num_events: 12,
                deps_per_event: 3,
            },
            TranscriptEntry::StageDependentReplied { staged_events: 12 },
            TranscriptEntry::PrintRequested {
                lines: expected.lines(),
            },
            TranscriptEntry::PrintReplied,
        ]
    );
    assert_eq!(shell.stdout, expected.lines());
    assert_eq!(app.view(&model).last_dependent_stage, Some(expected));
}

#[test]
fn replay_deps_reverse_requests_store_then_prints_summary() {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = FakeShell::default();

    shell.run(&app, &mut model, KernelMsg::ReplayDependentEventsReverse);

    let expected = DependentReplaySummary {
        replayed_events: 12,
        blocked_after_reverse: 9,
        applied_events: 12,
        ready_events: 0,
        blocked_events: 0,
        blocked_edges: 0,
    };
    assert_eq!(
        shell.transcript,
        vec![
            TranscriptEntry::ReplayDependentRequested,
            TranscriptEntry::ReplayDependentReplied {
                replayed_events: 12,
            },
            TranscriptEntry::PrintRequested {
                lines: expected.lines(),
            },
            TranscriptEntry::PrintReplied,
        ]
    );
    assert_eq!(shell.stdout, expected.lines());
    assert_eq!(app.view(&model).last_dependent_replay, Some(expected));
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
fn connect_opens_stream_exchanges_frames_and_prints_result() {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = FakeShell {
        frames_to_read: VecDeque::from([b"ack".to_vec()]),
        ..FakeShell::default()
    };

    shell.run(
        &app,
        &mut model,
        KernelMsg::Connect {
            invite: "topo://invite/demo".to_string(),
        },
    );

    let addr = "127.0.0.1:7000".parse().unwrap();
    assert_eq!(
        shell.transcript,
        vec![
            TranscriptEntry::ConnectionRequestCreated {
                invite: "topo://invite/demo".to_string(),
            },
            TranscriptEntry::OpenStream { addr },
            TranscriptEntry::StreamOpened { stream_id: 42 },
            TranscriptEntry::WriteFrames {
                stream_id: 42,
                frame_count: 1,
            },
            TranscriptEntry::FramesWritten,
            TranscriptEntry::ReadFrame { stream_id: 42 },
            TranscriptEntry::FrameRead {
                bytes: b"ack".to_vec(),
            },
            TranscriptEntry::FrameIngested {
                established_routes: 1,
                sent_events: 0,
                received_events: 0,
            },
            TranscriptEntry::DrainRequested {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            },
            TranscriptEntry::DrainReplied { applied_events: 3 },
            TranscriptEntry::ShutdownWrite { stream_id: 42 },
            TranscriptEntry::WriteShutdown,
            TranscriptEntry::ReadFrame { stream_id: 42 },
            TranscriptEntry::StreamClosed { stream_id: 42 },
            TranscriptEntry::PrintRequested {
                lines: vec!["connected: 127.0.0.1:7000".to_string()],
            },
            TranscriptEntry::PrintReplied,
        ]
    );
    assert_eq!(shell.stdout, vec!["connected: 127.0.0.1:7000".to_string()]);
    assert_eq!(
        app.view(&model).last_connect,
        Some(ConnectSummary {
            addr,
            established_routes: 1,
        })
    );
}

#[test]
fn sync_routes_asks_store_for_module_routes_then_pumps_each_stream() {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = FakeShell {
        frames_to_read: VecDeque::from([b"sync-ack".to_vec()]),
        ..FakeShell::default()
    };

    shell.run(&app, &mut model, KernelMsg::SyncRoutes);

    let target = "127.0.0.1:7001".parse().unwrap();
    let expected_lines = vec![
        "routes_synced: 1".to_string(),
        "sent_events: 7".to_string(),
        "received_events: 3".to_string(),
    ];
    assert_eq!(
        shell.transcript,
        vec![
            TranscriptEntry::SyncRoutesStarted {
                route_count: 1,
                sent_events: 2,
            },
            TranscriptEntry::OpenStream { addr: target },
            TranscriptEntry::StreamOpened { stream_id: 42 },
            TranscriptEntry::WriteFrames {
                stream_id: 42,
                frame_count: 1,
            },
            TranscriptEntry::FramesWritten,
            TranscriptEntry::OutboxMarked { row_count: 1 },
            TranscriptEntry::ReadFrame { stream_id: 42 },
            TranscriptEntry::FrameRead {
                bytes: b"sync-ack".to_vec(),
            },
            TranscriptEntry::FrameIngested {
                established_routes: 0,
                sent_events: 5,
                received_events: 3,
            },
            TranscriptEntry::DrainRequested {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            },
            TranscriptEntry::DrainReplied { applied_events: 3 },
            TranscriptEntry::ShutdownWrite { stream_id: 42 },
            TranscriptEntry::WriteShutdown,
            TranscriptEntry::ReadFrame { stream_id: 42 },
            TranscriptEntry::StreamClosed { stream_id: 42 },
            TranscriptEntry::PrintRequested {
                lines: expected_lines.clone(),
            },
            TranscriptEntry::PrintReplied,
        ]
    );
    assert_eq!(shell.stdout, expected_lines);
    assert_eq!(
        app.view(&model).last_sync,
        Some(SyncSummary {
            routes_synced: 1,
            sent_events: 7,
            received_events: 3,
        })
    );
}

#[test]
fn serve_binds_accepts_and_lets_event_modules_drive_responses() {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = FakeShell {
        frames_to_read: VecDeque::from([b"client-frame".to_vec()]),
        ..FakeShell::default()
    };
    let listen = "127.0.0.1:7002".parse().unwrap();
    let peer_addr = "127.0.0.1:8080".parse().unwrap();

    shell.run(
        &app,
        &mut model,
        KernelMsg::Serve {
            listen,
            accept_count: 1,
        },
    );

    let expected_lines = vec![
        "listening: 127.0.0.1:7002".to_string(),
        "accepted_connections: 1".to_string(),
        "received_events: 7".to_string(),
    ];
    assert_eq!(
        shell.transcript,
        vec![
            TranscriptEntry::BindListener { addr: listen },
            TranscriptEntry::ListenerBound {
                listener_id: 7,
                local_addr: listen,
            },
            TranscriptEntry::PrintRequested {
                lines: vec!["listening: 127.0.0.1:7002".to_string()],
            },
            TranscriptEntry::PrintReplied,
            TranscriptEntry::AcceptStream { listener_id: 7 },
            TranscriptEntry::StreamAccepted {
                stream_id: 42,
                peer_addr,
            },
            TranscriptEntry::ReadFrame { stream_id: 42 },
            TranscriptEntry::FrameRead {
                bytes: b"client-frame".to_vec(),
            },
            TranscriptEntry::FrameIngested {
                established_routes: 1,
                sent_events: 2,
                received_events: 7,
            },
            TranscriptEntry::DrainRequested {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            },
            TranscriptEntry::DrainReplied { applied_events: 3 },
            TranscriptEntry::WriteFrames {
                stream_id: 42,
                frame_count: 1,
            },
            TranscriptEntry::FramesWritten,
            TranscriptEntry::OutboxMarked { row_count: 1 },
            TranscriptEntry::ReadFrame { stream_id: 42 },
            TranscriptEntry::StreamClosed { stream_id: 42 },
            TranscriptEntry::PrintRequested {
                lines: vec![
                    "accepted_connections: 1".to_string(),
                    "received_events: 7".to_string(),
                ],
            },
            TranscriptEntry::PrintReplied,
        ]
    );
    assert_eq!(shell.stdout, expected_lines);
    assert_eq!(
        app.view(&model).last_serve,
        Some(ServeSummary {
            accepted_connections: 1,
            received_events: 7,
        })
    );
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
