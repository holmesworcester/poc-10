use super::super::connection_record::types::ConnectionId;
use crate::core::store::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxKey {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
}

impl OutboxKey {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.connection_id);
        bytes.extend_from_slice(&self.event_id);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub key: OutboxKey,
    pub event_bytes: Vec<u8>,
}
