use std::net::SocketAddr;

use crux_core::{capability::Operation, command::CommandContext, App, Command, Request};

use crate::control_loop;

#[derive(Debug, Default)]
pub struct KernelApp;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelModel {
    pub last_error: Option<String>,
    pub last_invite: Option<String>,
    pub last_connect: Option<ConnectSummary>,
    pub last_sync: Option<SyncSummary>,
    pub last_serve: Option<ServeSummary>,
    pub last_generate: Option<GenerateSummary>,
    pub last_count: Option<CountSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelView {
    pub last_error: Option<String>,
    pub last_invite: Option<String>,
    pub last_connect: Option<ConnectSummary>,
    pub last_sync: Option<SyncSummary>,
    pub last_serve: Option<ServeSummary>,
    pub last_generate: Option<GenerateSummary>,
    pub last_count: Option<CountSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelMsg {
    Failed(String),
    Invite {
        public_addr: SocketAddr,
    },
    InviteFinished(String),
    Connect {
        invite: String,
    },
    ConnectFinished(ConnectSummary),
    SyncRoutes,
    SyncFinished(SyncSummary),
    Serve {
        listen: SocketAddr,
        accept_count: usize,
    },
    ServeFinished(ServeSummary),
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
    Network(Request<NetworkOp>),
    Stdout(Request<StdoutOp>),
}

impl crux_core::Effect for KernelEffect {}

impl From<Request<StoreOp>> for KernelEffect {
    fn from(request: Request<StoreOp>) -> Self {
        Self::Store(request)
    }
}

impl From<Request<NetworkOp>> for KernelEffect {
    fn from(request: Request<NetworkOp>) -> Self {
        Self::Network(request)
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
    CreateConnectionRequest {
        invite: String,
    },
    IngestFrame {
        origin: SocketAddr,
        remember_origin: bool,
        bytes: Vec<u8>,
    },
    MarkOutboxSent {
        sent_outbox: Vec<Vec<u8>>,
    },
    GenerateContent {
        num_events: usize,
        event_size: usize,
    },
    DrainReadyUntilIdle {
        batch_size: usize,
    },
    StartSyncRoutes,
    CountStatus,
}

impl Operation for StoreOp {
    type Output = StoreReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreReply {
    InviteCreated { link: String },
    ConnectionRequestCreated(ConnectionRequest),
    FrameIngested(FrameIngest),
    OutboxMarked,
    Generated(GeneratedContent),
    Drained(DrainReadyReport),
    SyncStarted(SyncRoutesStart),
    Counted(CountSummary),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkOp {
    BindListener {
        addr: SocketAddr,
    },
    AcceptStream {
        listener_id: u64,
    },
    OpenStream {
        addr: SocketAddr,
    },
    WriteFrames {
        stream_id: u64,
        frames: Vec<Vec<u8>>,
    },
    ReadFrame {
        stream_id: u64,
    },
    ShutdownWrite {
        stream_id: u64,
    },
}

impl Operation for NetworkOp {
    type Output = NetworkReply;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkReply {
    ListenerBound {
        listener_id: u64,
        local_addr: SocketAddr,
    },
    StreamAccepted {
        stream_id: u64,
        peer_addr: SocketAddr,
    },
    StreamOpened {
        stream_id: u64,
    },
    FramesWritten,
    FrameRead(Vec<u8>),
    StreamClosed,
    WriteShutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub addr: SocketAddr,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameIngest {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSyncWork {
    pub target: SocketAddr,
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub sent_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncRoutesStart {
    pub outbound: Vec<OutboundSyncWork>,
    pub sent_events: usize,
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
pub struct ConnectSummary {
    pub addr: SocketAddr,
    pub established_routes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamSummary {
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub routes_synced: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

impl SyncSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("routes_synced: {}", self.routes_synced),
            format!("sent_events: {}", self.sent_events),
            format!("received_events: {}", self.received_events),
        ]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeSummary {
    pub accepted_connections: usize,
    pub received_events: usize,
}

impl ServeSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("accepted_connections: {}", self.accepted_connections),
            format!("received_events: {}", self.received_events),
        ]
    }
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
            KernelMsg::Failed(message) => {
                model.last_error = Some(message);
                Command::done()
            }
            KernelMsg::Invite { public_addr } => invite(public_addr),
            KernelMsg::InviteFinished(link) => {
                model.last_invite = Some(link);
                Command::done()
            }
            KernelMsg::Connect { invite } => connect(invite),
            KernelMsg::ConnectFinished(summary) => {
                model.last_connect = Some(summary);
                Command::done()
            }
            KernelMsg::SyncRoutes => sync_routes(),
            KernelMsg::SyncFinished(summary) => {
                model.last_sync = Some(summary);
                Command::done()
            }
            KernelMsg::Serve {
                listen,
                accept_count,
            } => serve(listen, accept_count),
            KernelMsg::ServeFinished(summary) => {
                model.last_serve = Some(summary);
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
            last_error: model.last_error.clone(),
            last_invite: model.last_invite.clone(),
            last_connect: model.last_connect.clone(),
            last_sync: model.last_sync.clone(),
            last_serve: model.last_serve.clone(),
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

fn connect(invite: String) -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let request = match ctx
            .request_from_shell(StoreOp::CreateConnectionRequest { invite })
            .await
        {
            StoreReply::ConnectionRequestCreated(request) => request,
            _ => panic!("connect received non-connection-request store reply"),
        };

        let stream_id = match ctx
            .request_from_shell(NetworkOp::OpenStream { addr: request.addr })
            .await
        {
            NetworkReply::StreamOpened { stream_id } => stream_id,
            _ => panic!("open stream returned non-open reply"),
        };

        match ctx
            .request_from_shell(NetworkOp::WriteFrames {
                stream_id,
                frames: vec![request.bytes],
            })
            .await
        {
            NetworkReply::FramesWritten => {}
            _ => panic!("write frames returned non-write reply"),
        }

        let stream = pump_stream(&ctx, stream_id, request.addr, true).await;

        if stream.established_routes == 0 {
            ctx.send_event(KernelMsg::Failed(
                "connection was not established".to_string(),
            ));
            return;
        }

        let summary = ConnectSummary {
            addr: request.addr,
            established_routes: stream.established_routes,
        };
        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: vec![format!("connected: {}", summary.addr)],
            })
            .await
        {
            StdoutReply::Written => {}
        }
        ctx.send_event(KernelMsg::ConnectFinished(summary));
    })
}

fn sync_routes() -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let start = match ctx.request_from_shell(StoreOp::StartSyncRoutes).await {
            StoreReply::SyncStarted(start) => start,
            _ => panic!("sync received non-sync-start store reply"),
        };

        let mut summary = SyncSummary {
            sent_events: start.sent_events,
            ..SyncSummary::default()
        };

        for outbound in start.outbound {
            let stream_id = match ctx
                .request_from_shell(NetworkOp::OpenStream {
                    addr: outbound.target,
                })
                .await
            {
                NetworkReply::StreamOpened { stream_id } => stream_id,
                _ => panic!("open stream returned non-open reply"),
            };

            match ctx
                .request_from_shell(NetworkOp::WriteFrames {
                    stream_id,
                    frames: outbound.outgoing,
                })
                .await
            {
                NetworkReply::FramesWritten => {}
                _ => panic!("write sync frames returned non-write reply"),
            }

            match ctx
                .request_from_shell(StoreOp::MarkOutboxSent {
                    sent_outbox: outbound.sent_outbox,
                })
                .await
            {
                StoreReply::OutboxMarked => {}
                _ => panic!("mark sync outbox returned non-mark reply"),
            }

            let stream = pump_stream(&ctx, stream_id, outbound.target, false).await;
            summary.routes_synced += 1;
            summary.sent_events += outbound.sent_events + stream.sent_events;
            summary.received_events += stream.received_events;
        }

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }
        ctx.send_event(KernelMsg::SyncFinished(summary));
    })
}

fn serve(listen: SocketAddr, accept_count: usize) -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let (listener_id, local_addr) = match ctx
            .request_from_shell(NetworkOp::BindListener { addr: listen })
            .await
        {
            NetworkReply::ListenerBound {
                listener_id,
                local_addr,
            } => (listener_id, local_addr),
            _ => panic!("bind listener returned non-listener reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: vec![format!("listening: {local_addr}")],
            })
            .await
        {
            StdoutReply::Written => {}
        }

        let mut summary = ServeSummary::default();
        for _ in 0..accept_count {
            let (stream_id, peer_addr) = match ctx
                .request_from_shell(NetworkOp::AcceptStream { listener_id })
                .await
            {
                NetworkReply::StreamAccepted {
                    stream_id,
                    peer_addr,
                } => (stream_id, peer_addr),
                _ => panic!("accept stream returned non-accept reply"),
            };
            let stream = pump_stream(&ctx, stream_id, peer_addr, false).await;
            summary.accepted_connections += 1;
            summary.received_events += stream.received_events;
        }

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }
        ctx.send_event(KernelMsg::ServeFinished(summary));
    })
}

async fn pump_stream(
    ctx: &CommandContext<KernelEffect, KernelMsg>,
    stream_id: u64,
    origin: SocketAddr,
    remember_origin: bool,
) -> StreamSummary {
    let mut summary = StreamSummary::default();
    let mut write_open = true;
    loop {
        let bytes = match ctx
            .request_from_shell(NetworkOp::ReadFrame { stream_id })
            .await
        {
            NetworkReply::FrameRead(bytes) => bytes,
            NetworkReply::StreamClosed => break,
            _ => panic!("read frame returned non-read reply"),
        };

        let ingest = match ctx
            .request_from_shell(StoreOp::IngestFrame {
                origin,
                remember_origin,
                bytes,
            })
            .await
        {
            StoreReply::FrameIngested(ingest) => ingest,
            _ => panic!("ingest frame returned non-ingest reply"),
        };
        summary.established_routes += ingest.established_routes;
        summary.sent_events += ingest.sent_events;
        summary.received_events += ingest.received_events;

        match ctx
            .request_from_shell(StoreOp::DrainReadyUntilIdle {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            })
            .await
        {
            StoreReply::Drained(_) => {}
            _ => panic!("stream drain returned non-drain reply"),
        }

        if ingest.outgoing.is_empty() {
            if write_open {
                match ctx
                    .request_from_shell(NetworkOp::ShutdownWrite { stream_id })
                    .await
                {
                    NetworkReply::WriteShutdown => {}
                    _ => panic!("shutdown write returned non-shutdown reply"),
                }
                write_open = false;
            }
        } else {
            match ctx
                .request_from_shell(NetworkOp::WriteFrames {
                    stream_id,
                    frames: ingest.outgoing,
                })
                .await
            {
                NetworkReply::FramesWritten => {}
                _ => panic!("write response frames returned non-write reply"),
            }
            match ctx
                .request_from_shell(StoreOp::MarkOutboxSent {
                    sent_outbox: ingest.sent_outbox,
                })
                .await
            {
                StoreReply::OutboxMarked => {}
                _ => panic!("mark outbox returned non-mark reply"),
            }
        }
    }
    summary
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
                        let (
                            outgoing,
                            sent_outbox,
                            established_routes,
                            sent_events,
                            received_events,
                        ) = match bytes.as_slice() {
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
}
