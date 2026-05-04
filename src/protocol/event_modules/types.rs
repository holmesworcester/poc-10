pub type EventId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub timestamp: u64,
    pub body_len: usize,
    pub canonical_bytes: Vec<u8>,
    pub dependencies: Vec<EventId>,
    pub scope: EventScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventScope {
    Shared,
    Local,
    Transient,
}

impl EventScope {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Shared => 0,
            Self::Local => 1,
            Self::Transient => 2,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Shared),
            1 => Ok(Self::Local),
            2 => Ok(Self::Transient),
            _ => Err(format!("unknown event scope {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatus {
    Ready,
    Blocked,
    Applied,
    Rejected,
}

impl EventStatus {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Blocked => 1,
            Self::Applied => 2,
            Self::Rejected => 3,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Blocked),
            2 => Ok(Self::Applied),
            3 => Ok(Self::Rejected),
            _ => Err(format!("unknown event status {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIndexEntry {
    pub event_id: EventId,
    pub partition: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventStatusCounts {
    pub ready: usize,
    pub blocked: usize,
    pub applied: usize,
    pub rejected: usize,
    pub blocked_edges: usize,
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}
