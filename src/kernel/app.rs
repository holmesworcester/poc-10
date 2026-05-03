use std::net::SocketAddr;

use crux_core::{capability::Operation, App, Command, Request};

use super::commands::{
    connect, count, generate, generate_dependent_events, invite, replay_dependent_events_reverse,
    serve, sync_routes,
};

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
