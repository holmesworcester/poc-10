use crate::core::store::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedIdEvent {
    pub connection_id: EventId,
    pub id: EventId,
}
