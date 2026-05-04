use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaveIdEvent {
    pub connection_id: EventId,
    pub bucket: u8,
    pub id: EventId,
}
