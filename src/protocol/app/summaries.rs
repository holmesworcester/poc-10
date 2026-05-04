use std::net::SocketAddr;

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
