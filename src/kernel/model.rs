use std::net::SocketAddr;

use super::summaries::{
    ConnectSummary, CountSummary, DependentReplaySummary, DependentStageSummary, GenerateSummary,
    ServeSummary, SyncSummary,
};

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
