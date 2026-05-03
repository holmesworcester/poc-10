use std::net::SocketAddr;

use crux_core::{capability::Operation, Request};

use super::summaries::{CountSummary, DependentReplaySummary, DependentStageSummary};

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
