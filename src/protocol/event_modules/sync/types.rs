//! Shared sync-domain types.
//!
//! Sync control events are connection-scoped and transient. The same semantic
//! item has two local roles: an outbound event should be queued to the
//! connection outbox, while an inbound event should be queued as sync work.
//! Encoding the role in the canonical bytes gives each role its own stable id
//! while leaving stream framing to core TCP.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    Outbound,
    Inbound,
}

impl SyncDirection {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Outbound => 0,
            Self::Inbound => 1,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Outbound),
            1 => Ok(Self::Inbound),
            _ => Err(format!("unknown sync direction {value}")),
        }
    }
}
