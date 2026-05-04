#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsStageSummary {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl EventWithDepsStageSummary {
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
pub struct EventWithDepsReplaySummary {
    pub replayed_events: usize,
    pub blocked_after_reverse: usize,
    pub applied_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
}

impl EventWithDepsReplaySummary {
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
