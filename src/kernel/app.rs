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
    pub last_dependent_stage: Option<DependentStageSummary>,
    pub last_dependent_replay: Option<DependentReplaySummary>,
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
    pub last_dependent_stage: Option<DependentStageSummary>,
    pub last_dependent_replay: Option<DependentReplaySummary>,
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
    GenerateDependentEvents {
        num_events: usize,
        deps_per_event: usize,
    },
    GenerateDependentEventsFinished(DependentStageSummary),
    ReplayDependentEventsReverse,
    ReplayDependentEventsReverseFinished(DependentReplaySummary),
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
    StageDependentEvents {
        num_events: usize,
        deps_per_event: usize,
    },
    ReplayDependentEventsReverse,
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
    DependentEventsStaged(DependentStageSummary),
    DependentEventsReplayed(DependentReplaySummary),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentStageSummary {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl DependentStageSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("staged_events: {}", self.staged_events),
            format!("deps_per_event: {}", self.deps_per_event),
            format!("dep_edges: {}", self.dep_edges),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentReplaySummary {
    pub replayed_events: usize,
    pub blocked_after_reverse: usize,
    pub applied_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
}

impl DependentReplaySummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("replayed_events: {}", self.replayed_events),
            format!("blocked_after_reverse: {}", self.blocked_after_reverse),
            format!("applied_events: {}", self.applied_events),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("blocked_edges: {}", self.blocked_edges),
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
            KernelMsg::GenerateDependentEvents {
                num_events,
                deps_per_event,
            } => generate_dependent_events(num_events, deps_per_event),
            KernelMsg::GenerateDependentEventsFinished(summary) => {
                model.last_dependent_stage = Some(summary);
                Command::done()
            }
            KernelMsg::ReplayDependentEventsReverse => replay_dependent_events_reverse(),
            KernelMsg::ReplayDependentEventsReverseFinished(summary) => {
                model.last_dependent_replay = Some(summary);
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
            last_dependent_stage: model.last_dependent_stage.clone(),
            last_dependent_replay: model.last_dependent_replay.clone(),
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

fn generate_dependent_events(
    num_events: usize,
    deps_per_event: usize,
) -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let summary = match ctx
            .request_from_shell(StoreOp::StageDependentEvents {
                num_events,
                deps_per_event,
            })
            .await
        {
            StoreReply::DependentEventsStaged(summary) => summary,
            _ => panic!("generate deps received non-stage store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(KernelMsg::GenerateDependentEventsFinished(summary));
    })
}

fn replay_dependent_events_reverse() -> Command<KernelEffect, KernelMsg> {
    Command::new(|ctx| async move {
        let summary = match ctx
            .request_from_shell(StoreOp::ReplayDependentEventsReverse)
            .await
        {
            StoreReply::DependentEventsReplayed(summary) => summary,
            _ => panic!("replay deps received non-replay store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(KernelMsg::ReplayDependentEventsReverseFinished(summary));
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
