use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedIdEvent {
    pub connection_id: EventId,
    pub id: EventId,
}
